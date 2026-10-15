// Package ipc is the local channel between the locnet CLI and the locnetd
// service.
//
// On Unix it is a mode-0660 socket in a root-owned directory, so the operating
// system decides who may talk to the daemon. Windows has no equivalent that
// works without a named-pipe dependency, so there the daemon listens on
// 127.0.0.1 with a random port and a random token, both written to a file that
// only administrators can read. The security property is the same in both
// cases — you must already have privileged access to the machine — but it is
// worth knowing which one you are relying on.
package ipc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/mahantsunandan/locnet/internal/paths"
)

// TokenHeader carries the control token on Windows.
const TokenHeader = "X-LocNet-Control"

// Group is the Unix group allowed to drive the daemon without root.
//
// Requiring sudo for `locnet status` is not security, it is friction: the
// information is already visible to anyone who can read the interface list.
// Giving the socket to a group means an administrator decides once who may
// use the network, and the operating system enforces it from then on.
const Group = "locnet"

// controlFile records where the daemon is listening when there is no Unix
// socket to point at.
type controlFile struct {
	Addr  string `json:"addr"`
	Token string `json:"token"`
}

func controlFilePath() string {
	return filepath.Join(paths.StateDir(), "control.json")
}

// Listener is a local control listener plus whatever the client needs to
// reach it.
type Listener struct {
	net.Listener
	token string
}

// Token returns the shared secret clients must present, empty on Unix.
func (l *Listener) Token() string { return l.token }

// Listen opens the control channel and publishes how to reach it.
func Listen() (*Listener, error) {
	if runtime.GOOS == "windows" {
		return listenTCP()
	}
	return listenUnix()
}

func listenUnix() (*Listener, error) {
	path := paths.ControlSocket()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("ipc: create %s: %w", filepath.Dir(path), err)
	}
	// A socket left behind by a killed daemon would block the bind. Removing
	// it is safe: if another daemon were live, its bind would still hold the
	// name and the listen below would fail for the right reason.
	_ = os.Remove(path)

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("ipc: listen on %s: %w", path, err)
	}
	// 0660 rather than 0666: membership of the socket's group is the
	// permission to control the network.
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return nil, fmt.Errorf("ipc: chmod %s: %w", path, err)
	}

	// Hand the socket to the locnet group if it exists. Without the group
	// the socket stays root-only, which still works — it just means sudo.
	if gid, ok := lookupGroup(Group); ok {
		dir := filepath.Dir(path)
		// The directory must be traversable by the group or the socket
		// inside it cannot be reached, whatever its own permissions say.
		_ = os.Chown(dir, 0, gid)
		_ = os.Chmod(dir, 0o750)
		if err := os.Chown(path, 0, gid); err != nil {
			return nil, fmt.Errorf("ipc: chown %s to group %s: %w", path, Group, err)
		}
	}
	return &Listener{Listener: ln}, nil
}

// lookupGroup resolves a group name to a gid.
func lookupGroup(name string) (int, bool) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, false
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, false
	}
	return gid, true
}

func listenTCP() (*Listener, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("ipc: listen on loopback: %w", err)
	}
	token, err := randomHex()
	if err != nil {
		ln.Close()
		return nil, err
	}
	if err := paths.EnsureDir(paths.StateDir()); err != nil {
		ln.Close()
		return nil, err
	}
	raw, _ := json.Marshal(controlFile{Addr: ln.Addr().String(), Token: token})
	if err := os.WriteFile(controlFilePath(), raw, 0o600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("ipc: write %s: %w", controlFilePath(), err)
	}
	return &Listener{Listener: ln, token: token}, nil
}

// Cleanup removes whatever Listen published.
func Cleanup() {
	if runtime.GOOS == "windows" {
		_ = os.Remove(controlFilePath())
		return
	}
	_ = os.Remove(paths.ControlSocket())
}

// Client talks to a running locnetd.
type Client struct {
	hc    *http.Client
	token string
}

// Dial connects to the local daemon.
func Dial() (*Client, error) {
	if runtime.GOOS == "windows" {
		raw, err := os.ReadFile(controlFilePath())
		if err != nil {
			return nil, notRunning(err)
		}
		var cf controlFile
		if err := json.Unmarshal(raw, &cf); err != nil {
			return nil, fmt.Errorf("ipc: %s is corrupt: %w", controlFilePath(), err)
		}
		return &Client{
			hc: &http.Client{
				Timeout: 60 * time.Second,
				Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "tcp", cf.Addr)
				}},
			},
			token: cf.Token,
		}, nil
	}

	path := paths.ControlSocket()
	if _, err := os.Stat(path); err != nil {
		return nil, notRunning(err)
	}
	return &Client{hc: &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		}},
	}}, nil
}

// addToGroupCmd is the command that grants access, which differs by platform.
// Printing the Linux one on a Mac — where there is no usermod — sends someone
// looking for a tool that does not exist.
func addToGroupCmd() string {
	switch runtime.GOOS {
	case "darwin":
		return "sudo dseditgroup -o edit -a $USER -t user " + Group
	default:
		return "sudo usermod -aG " + Group + " $USER"
	}
}

func notRunning(err error) error {
	if os.IsNotExist(err) {
		return fmt.Errorf("locnetd does not appear to be running (no control socket at %s)", paths.ControlSocket())
	}
	if os.IsPermission(err) {
		return fmt.Errorf("not allowed to talk to locnetd.\n"+
			"Either use sudo, or add yourself to the %q group and log out and back in:\n"+
			"    %s", Group, addToGroupCmd())
	}
	return fmt.Errorf("ipc: %w", err)
}

// Get performs a GET against the daemon and decodes the JSON reply.
func (c *Client) Get(path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, "http://locnetd"+path, nil)
	if err != nil {
		return err
	}
	return c.do(req, out)
}

// Post performs a POST with a JSON body.
func (c *Client) Post(path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, "http://locnetd"+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, out)
}

func (c *Client) do(req *http.Request, out any) error {
	if c.token != "" {
		req.Header.Set(TokenHeader, c.token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("locnetd: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		var er struct {
			Error string `json:"error"`
		}
		if json.NewDecoder(resp.Body).Decode(&er) == nil && er.Error != "" {
			return fmt.Errorf("%s", er.Error)
		}
		// A bare 404 from the daemon means it does not have the endpoint at
		// all: the CLI was upgraded and the service was not, or the other way
		// round. Saying so beats "404 Not Found", which reads like a typo.
		if resp.StatusCode == http.StatusNotFound {
			return fmt.Errorf("the running locnetd does not support %s — it is a different "+
				"version from this locnet command. Install the same version of both", req.URL.Path)
		}
		return fmt.Errorf("locnetd returned %s", resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func randomHex() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
