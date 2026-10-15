// Package shareclient talks to a peer's share server.
//
// There is no authentication here because there is nothing to authenticate
// with: the request travels through the tunnel, and the peer identifies us by
// the overlay address it arrives from. If the tunnel is not up, the connection
// simply fails, which is the correct outcome.
package shareclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/mahantsunandan/locnet/internal/resource"
)

// SharePort must match the node's share server.
const SharePort = 8421

// Client talks to one peer.
type Client struct {
	base string
	hc   *http.Client
}

// New returns a client for the peer at addr.
func New(addr netip.Addr) *Client {
	return &Client{
		base: "http://" + netip.AddrPortFrom(addr, SharePort).String(),
		// No overall timeout: a large download is a legitimate slow
		// request. The dial and response-header timeouts below are what
		// catch a peer that is simply not there.
		hc: &http.Client{Transport: &http.Transport{
			ResponseHeaderTimeout: 20 * time.Second,
		}},
	}
}

// List returns the shares this peer offers us.
func (c *Client) List(ctx context.Context) ([]resource.Advert, error) {
	var out []resource.Advert
	if err := c.getJSON(ctx, "/shares", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Dir lists a directory inside a files share. relPath may be empty for the
// share root.
func (c *Client) Dir(ctx context.Context, share, relPath string) ([]resource.FileEntry, error) {
	var out []resource.FileEntry
	if err := c.getJSON(ctx, filesPath(share, relPath), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Get downloads one file to dest. If dest is a directory, the remote filename
// is used inside it.
func (c *Client) Get(ctx context.Context, share, relPath, dest string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+filesPath(share, relPath), nil)
	if err != nil {
		return "", err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("cannot reach the peer: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", httpError(resp)
	}

	if info, err := os.Stat(dest); err == nil && info.IsDir() {
		dest = filepath.Join(dest, path.Base(relPath))
	}

	// Download to a temporary name and rename, so an interrupted transfer
	// does not leave something that looks like a complete file.
	tmp := dest + ".locnet-part"
	f, err := os.Create(tmp)
	if err != nil {
		return "", err
	}
	_, copyErr := io.Copy(f, resp.Body)
	closeErr := f.Close()
	if copyErr != nil || closeErr != nil {
		os.Remove(tmp)
		if copyErr != nil {
			return "", copyErr
		}
		return "", closeErr
	}
	if err := os.Rename(tmp, dest); err != nil {
		os.Remove(tmp)
		return "", err
	}
	return dest, nil
}

// Put uploads src into a share.
func (c *Client) Put(ctx context.Context, share, relPath, src string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory; upload files one at a time", src)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.base+filesPath(share, relPath), f)
	if err != nil {
		return err
	}
	req.ContentLength = info.Size()

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach the peer: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return httpError(resp)
	}
	return nil
}

// Exec submits a job and waits for it to finish.
//
// No overall client timeout applies: the far machine enforces its own limit
// and a long-running job is the normal case. The caller bounds it with ctx.
func (c *Client) Exec(ctx context.Context, job resource.Job) (*resource.JobResult, error) {
	raw, err := json.Marshal(job)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/exec", strings.NewReader(string(raw)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach the peer: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, httpError(resp)
	}
	var out resource.JobResult
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Desktop reports what this peer's screen offers us right now.
func (c *Client) Desktop(ctx context.Context) (*resource.DesktopStatus, error) {
	var out resource.DesktopStatus
	if err := c.getJSON(ctx, "/desktop/info", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DesktopStream opens the frame stream. The caller owns the returned body and
// must close it; that is what stops the far machine capturing.
//
// The client used here has no response-header timeout, unlike everything else
// in this package: a screen that has not changed sends nothing, and treating
// silence as failure would disconnect exactly the sessions that are costing
// nothing.
func (c *Client) DesktopStream(ctx context.Context, fps, quality int) (io.ReadCloser, error) {
	u := fmt.Sprintf("%s/desktop/stream?fps=%d&q=%d", c.base, fps, quality)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	hc := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach the peer: %w", err)
	}
	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		return nil, httpError(resp)
	}
	return resp.Body, nil
}

// DesktopInput sends a batch of input events.
func (c *Client) DesktopInput(ctx context.Context, events []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/desktop/input",
		bytes.NewReader(events))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach the peer: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return httpError(resp)
	}
	return nil
}

// Wake asks this peer to broadcast magic packets for the given hardware
// addresses onto its own network.
func (c *Client) Wake(ctx context.Context, macs []string) (int, error) {
	body, err := json.Marshal(map[string][]string{"macs": macs})
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/wake", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, fmt.Errorf("cannot reach the peer: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return 0, httpError(resp)
	}
	var out struct {
		Sent int `json:"sent"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, err
	}
	return out.Sent, nil
}

// Probe asks this peer to connect back to us on the given ports and report
// which ones answered.
//
// The peer probes the source address of this request, so there is nothing to
// pass but the port list: what gets tested is necessarily this machine, as seen
// from that one. That is the only vantage point from which "can anyone reach my
// SSH server" has a truthful answer — asked locally, a machine will happily
// confirm a port that its own firewall blocks to every peer on the network.
func (c *Client) Probe(ctx context.Context, peerName string, ports []uint16) (*resource.ProbeResult, error) {
	if len(ports) == 0 {
		return nil, errors.New("no ports to probe")
	}
	body, err := json.Marshal(resource.ProbeRequest{Ports: ports})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/probe", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach the peer: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, httpError(resp)
	}
	var out resource.ProbeResult
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	// The responder does not name itself; we know who we asked.
	out.From = peerName
	return &out, nil
}

func (c *Client) getJSON(ctx context.Context, p string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+p, nil)
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach the peer: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return httpError(resp)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// filesPath builds /files/<share>/<path>, escaping each segment so that a
// filename containing a space, a hash or a question mark survives the trip.
func filesPath(share, relPath string) string {
	out := "/files/" + url.PathEscape(share)
	for _, seg := range strings.Split(relPath, "/") {
		if seg == "" {
			continue
		}
		out += "/" + url.PathEscape(seg)
	}
	return out
}

func httpError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	msg := strings.TrimSpace(string(body))
	if msg == "" {
		msg = resp.Status
	}
	return fmt.Errorf("%s", msg)
}
