package node

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/mahantsunandan/locnet/internal/deskserve"
	"github.com/mahantsunandan/locnet/internal/resource"
)

// The daemon does not capture anything. It holds the access list, and it holds
// the address of the session helper that does the capturing, and its whole job
// here is to let one talk to the other only when the list says so.
//
// Keeping the decision on this side matters. The helper runs as an ordinary
// user in a graphical session — the least trustworthy process in the system to
// put in charge of who may watch the screen. It answers loopback only, with a
// token it generated and handed to the daemon, so the daemon is the only thing
// that can reach it at all.

// desktopExpiry is how long a registration survives without a heartbeat. Long
// enough to ride out a slow moment, short enough that a machine whose user has
// logged out stops claiming to have a screen within a minute.
const desktopExpiry = 70 * time.Second

// desktopReg is a live session helper.
type desktopReg struct {
	mu     sync.Mutex
	url    string
	token  string
	status resource.DesktopStatus
	seen   time.Time
	hc     *http.Client
}

func newDesktopReg() *desktopReg {
	return &desktopReg{
		// No overall timeout: a stream is meant to run for hours. The dial
		// is to loopback, so a helper that has gone away fails at once
		// anyway.
		hc: &http.Client{Transport: &http.Transport{
			ResponseHeaderTimeout: 15 * time.Second,
			DisableCompression:    true,
		}},
	}
}

// register records a helper. It reports whether this is a new attachment
// rather than one of its heartbeats.
func (d *desktopReg) register(reg deskserve.Registration) (first bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	first = d.url == "" || time.Since(d.seen) > desktopExpiry
	d.url, d.token, d.status, d.seen = reg.URL, reg.Token, reg.Status, time.Now()
	return first
}

func (d *desktopReg) unregister() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.url, d.token, d.seen = "", "", time.Time{}
	d.status = resource.DesktopStatus{}
}

// live returns the helper's address if one is currently registered.
func (d *desktopReg) live() (base, token string, ok bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.url == "" || time.Since(d.seen) > desktopExpiry {
		return "", "", false
	}
	return d.url, d.token, true
}

// Status reports what peers should be told about this machine's screen.
func (d *desktopReg) Status() resource.DesktopStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.url == "" || time.Since(d.seen) > desktopExpiry {
		return resource.DesktopStatus{}
	}
	return d.status
}

// ----------------------------------------------------------------- HTTP

// handleDesktop serves a peer's request against the session helper.
func (s *shareServer) handleDesktop(w http.ResponseWriter, r *http.Request, peer string) {
	s.mu.Lock()
	cfg := s.desktop
	reg := s.deskReg
	s.mu.Unlock()

	if !cfg.AllowsPeer(peer) {
		// The same answer whether sharing is off or this peer is simply not
		// on the list, for the same reason as compute: a machine that will
		// not show you its screen owes you no account of why.
		s.logf("desktop: refused %s", peer)
		http.Error(w, "this machine does not share its screen with you", http.StatusNotFound)
		return
	}
	if reg == nil {
		http.Error(w, "no desktop session is running on that machine", http.StatusServiceUnavailable)
		return
	}
	base, token, ok := reg.live()
	if !ok {
		http.Error(w, "nobody is logged in on that machine, so there is no screen to show.\n"+
			"A desktop session must be open, with `locnet desktop serve` running in it.",
			http.StatusServiceUnavailable)
		return
	}

	switch r.URL.Path {
	case "/desktop/info":
		reg.proxy(w, r, base+"/info", token, nil, s.logf)
	case "/desktop/stream":
		// The viewer asks; the machine being watched decides. Anything
		// outside what the operator configured is clamped rather than
		// refused, so a stale client does not simply stop working.
		q := url.Values{}
		q.Set("fps", strconv.Itoa(minInt(intQuery(r, "fps", cfg.FPS()), cfg.FPS())))
		q.Set("q", strconv.Itoa(minInt(intQuery(r, "q", cfg.JPEGQuality()), cfg.JPEGQuality())))
		reg.proxy(w, r, base+"/stream?"+q.Encode(), token, nil, s.logf)
	case "/desktop/input":
		if !cfg.Control {
			http.Error(w, "this machine is shared for viewing only", http.StatusForbidden)
			return
		}
		reg.proxy(w, r, base+"/input", token, r.Body, s.logf)
	default:
		http.NotFound(w, r)
	}
}

// proxy forwards one request to the helper and streams the answer back.
func (d *desktopReg) proxy(w http.ResponseWriter, r *http.Request, target, token string,
	body io.Reader, logf func(string, ...any)) {

	req, err := http.NewRequestWithContext(r.Context(), r.Method, target, body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req.Header.Set(deskserve.TokenHeader, token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := d.hc.Do(req)
	if err != nil {
		// Nothing is forgotten here on purpose. A helper that has really
		// gone stops heartbeating and its registration lapses within a
		// minute; dropping it on one failed request would also drop one that
		// was merely busy for a moment.
		logf("desktop: session helper did not answer: %v", err)
		http.Error(w, "the desktop session on that machine stopped answering", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for _, h := range []string{"Content-Type", "Cache-Control", "X-Accel-Buffering"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	copyFlushing(w, resp.Body)
}

// copyFlushing forwards a stream, pushing each chunk out as it arrives.
//
// A plain io.Copy would work for a file and is wrong for a live one: the
// response would sit in a buffer until enough of it accumulated, which for a
// screen that has not changed is indefinitely.
func copyFlushing(w http.ResponseWriter, r io.Reader) {
	rc := http.NewResponseController(w)
	buf := make([]byte, 32<<10)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if ferr := rc.Flush(); ferr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// setDesktop installs a new desktop configuration.
func (s *shareServer) setDesktop(cfg resource.DesktopConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.desktop = cfg
}

func intQuery(r *http.Request, name string, def int) int {
	v, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil || v <= 0 {
		return def
	}
	return v
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ----------------------------------------------------------- engine surface

// Desktop returns this machine's desktop-sharing configuration.
func (e *Engine) Desktop() resource.DesktopConfig {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.st.Desktop
}

// SetDesktop replaces the desktop configuration and pushes it everywhere it
// is enforced or advertised.
func (e *Engine) SetDesktop(cfg resource.DesktopConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	e.mu.Lock()
	e.st.Desktop = cfg
	st := *e.st
	shareSrv := e.shareSrv
	e.mu.Unlock()

	if err := SaveState(e.dir, &st); err != nil {
		return err
	}
	if shareSrv != nil {
		shareSrv.setDesktop(cfg)
	}
	if cfg.Enabled {
		mode := "view only"
		if cfg.Control {
			mode = "view and control"
		}
		e.logf("desktop: shared with %s (%s)", cfg.AllowText(), mode)
	} else {
		e.logf("desktop: sharing disabled")
	}
	// Peers learn from the netmap, and the netmap comes from the hub, so a
	// change is only real once the hub has heard about it.
	go e.reportSoon()
	return nil
}

// RegisterDesktop records a session helper that has just started.
func (e *Engine) RegisterDesktop(reg deskserve.Registration) error {
	if reg.URL == "" || reg.Token == "" {
		return fmt.Errorf("a desktop registration needs a url and a token")
	}
	e.mu.Lock()
	shareSrv := e.shareSrv
	e.mu.Unlock()
	if shareSrv == nil {
		return fmt.Errorf("the tunnel is not up, so there is nothing to attach a desktop to")
	}
	shareSrv.mu.Lock()
	if shareSrv.deskReg == nil {
		shareSrv.deskReg = newDesktopReg()
	}
	target := shareSrv.deskReg
	shareSrv.mu.Unlock()

	// Only log the first registration of a session. The helper re-registers
	// every twenty seconds as its heartbeat, and a line per heartbeat would
	// bury everything else in the log.
	if first := target.register(reg); first {
		e.logf("desktop: session helper attached (pid %d)", reg.PID)
	}
	return nil
}

// UnregisterDesktop forgets the session helper.
func (e *Engine) UnregisterDesktop() {
	e.mu.Lock()
	shareSrv := e.shareSrv
	e.mu.Unlock()
	if shareSrv == nil {
		return
	}
	shareSrv.mu.Lock()
	reg := shareSrv.deskReg
	shareSrv.mu.Unlock()
	if reg != nil {
		reg.unregister()
		e.logf("desktop: session helper detached")
	}
}

// DesktopStatus reports what the session helper last said about the screen.
func (e *Engine) DesktopStatus() resource.DesktopStatus {
	e.mu.Lock()
	shareSrv := e.shareSrv
	e.mu.Unlock()
	if shareSrv == nil {
		return resource.DesktopStatus{}
	}
	shareSrv.mu.Lock()
	reg := shareSrv.deskReg
	shareSrv.mu.Unlock()
	if reg == nil {
		return resource.DesktopStatus{}
	}
	return reg.Status()
}

// DesktopJSON is the daemon's answer to a status query about the screen.
type DesktopJSON struct {
	Config resource.DesktopConfig `json:"config"`
	Status resource.DesktopStatus `json:"status"`
}

// WriteDesktopJSON is a small helper so the control API and the CLI agree on
// the shape of this answer.
func WriteDesktopJSON(w io.Writer, cfg resource.DesktopConfig, st resource.DesktopStatus) error {
	return json.NewEncoder(w).Encode(DesktopJSON{Config: cfg, Status: st})
}
