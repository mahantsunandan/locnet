// Package deskserve is the desktop session helper: the small process that
// captures the screen and injects input, running as the logged-in user.
//
// It exists as a separate process because locnetd cannot do this job. A
// Windows service lives in session 0, whose desktop is a blank virtual one
// nobody is looking at; a Linux daemon started by systemd has no DISPLAY and
// no X authority, and giving it one would mean handing root a copy of a user's
// display credentials. Both problems disappear if the capture runs where the
// screen is.
//
// The helper is not reachable from the network. It listens on loopback with a
// random per-run token and tells locnetd where it is; locnetd is the only
// thing that ever calls it, and locnetd is where the access list is enforced.
// So the split is not only about which process can see the screen — it also
// keeps the decision about who may watch in the one place that already decides
// who may read a file share.
package deskserve

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mahantsunandan/locnet/internal/ipc"
	"github.com/mahantsunandan/locnet/internal/resource"
	"github.com/mahantsunandan/locnet/internal/screen"
)

// TokenHeader carries the per-run secret from locnetd to the helper.
const TokenHeader = "X-LocNet-Desktop"

// Registration is what the helper tells locnetd about itself.
type Registration struct {
	URL    string                 `json:"url"`
	Token  string                 `json:"token"`
	Status resource.DesktopStatus `json:"status"`
	PID    int                    `json:"pid,omitempty"`
}

// heartbeat is how often the helper re-registers. Registration expires on the
// daemon side a little after this, so a helper that is killed stops being
// advertised without needing to have said goodbye.
const heartbeat = 20 * time.Second

// Options are the helper's local settings. They are deliberately not part of
// the network-visible desktop configuration: which VNC server to bridge, and
// its password, are facts about this machine's own session, and neither the
// hub nor a peer has any business holding them.
type Options struct {
	// VNCAddr is a VNC server to bridge when the platform cannot be
	// captured directly. Empty means "look on loopback and use one if it is
	// there"; "off" means never.
	VNCAddr string
	// VNCPassword is that server's password, if it wants one.
	VNCPassword string
}

// Server is a running helper.
type Server struct {
	token string
	logf  func(string, ...any)
	g     *grabber
}

// Run starts the helper and blocks until ctx is cancelled.
func Run(ctx context.Context, logf func(string, ...any), opts Options) error {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	daemon, err := ipc.Dial()
	if err != nil {
		return err
	}

	var tok [24]byte
	if _, err := rand.Read(tok[:]); err != nil {
		return err
	}
	s := &Server{token: hex.EncodeToString(tok[:]), logf: logf,
		g: &grabber{opts: opts, logf: logf}}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("desktop helper: %w", err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /info", s.auth(s.handleInfo))
	mux.HandleFunc("GET /stream", s.auth(s.handleStream))
	mux.HandleFunc("POST /input", s.auth(s.handleInput))
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			logf("desktop helper: %v", err)
		}
	}()

	// Probing the display now rather than on the first viewer means the
	// console can say "this machine runs Wayland" before anyone clicks, and
	// say it in the machine list rather than as a failed connection.
	st := s.g.probe()
	switch {
	case st.Error != "":
		logf("desktop helper: %s", st.Error)
	case st.Via != "":
		logf("desktop helper: %dx%d via %s, input %s", st.Width, st.Height, st.Via,
			map[bool]string{true: "available", false: "not available"}[st.Control])
	default:
		logf("desktop helper: %dx%d, input %s", st.Width, st.Height,
			map[bool]string{true: "available", false: "not available"}[st.Control])
	}

	reg := Registration{
		URL:   "http://" + ln.Addr().String(),
		Token: s.token,
		PID:   os.Getpid(),
	}
	send := func() {
		reg.Status = s.g.status()
		if err := daemon.Post("/desktop/register", reg, nil); err != nil {
			logf("desktop helper: cannot register with locnetd: %v", err)
		}
	}
	send()
	logf("desktop helper: registered with locnetd, listening on %s", ln.Addr())

	t := time.NewTicker(heartbeat)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			// A parting word so the machine stops advertising a screen that
			// is about to stop answering. Best effort: if the daemon is the
			// thing going away, the registration expires anyway.
			_ = daemon.Post("/desktop/unregister", struct{}{}, nil)
			s.g.close()
			return nil
		case <-t.C:
			send()
		}
	}
}

// auth checks the token locnetd was given at registration.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get(TokenHeader)
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.g.probe())
}

func (s *Server) handleInput(w http.ResponseWriter, r *http.Request) {
	var evs []screen.Event
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&evs); err != nil {
		http.Error(w, "malformed input", http.StatusBadRequest)
		return
	}
	if err := s.g.input(evs); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleStream sends frames until the viewer goes away.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	fps := clampInt(intParam(r, "fps", resource.DefaultDesktopFPS), 1, resource.MaxDesktopFPS)
	quality := clampInt(intParam(r, "q", resource.DefaultDesktopQuality), 10, 95)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	// Some proxies buffer an unknown-length response until it ends, which
	// for a live stream is forever. This is the conventional way to ask them
	// not to.
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	rc := http.NewResponseController(w)
	enc := &screen.Encoder{Quality: quality}
	interval := time.Second / time.Duration(fps)

	// A desktop is still most of the time. Backing off when nothing moves
	// takes the idle cost of a shared screen from "one screenshot every 80
	// milliseconds" to almost nothing, and the first changed pixel puts it
	// straight back to full rate.
	idle := 0
	ctx := r.Context()
	for {
		wait := interval
		if idle > 20 {
			wait = 250 * time.Millisecond
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}

		err := s.g.withFrame(interval/2, func(img *image.RGBA, ptr image.Point, hasPtr bool) error {
			n, err := enc.Frame(w, img)
			if err != nil {
				return err
			}
			if n == 0 {
				idle++
			} else {
				idle = 0
			}
			if hasPtr {
				if err := enc.Cursor(w, ptr); err != nil {
					return err
				}
			}
			return enc.End(w)
		})
		if err != nil {
			// Say why on the stream itself. A viewer that simply stops
			// updating leaves the user wondering whether the network or the
			// far machine is the problem.
			_ = enc.Message(w, err.Error())
			_ = rc.Flush()
			return
		}
		if err := rc.Flush(); err != nil {
			return
		}
	}
}

// -------------------------------------------------------------------- grabber

// openSession is screen.Open, indirected so that tests can supply a display
// that does not need a computer with a monitor attached to it.
var openSession = screen.Open

// grabber owns the one connection to the display.
//
// Everything is serialised through it, including the encode, because a capture
// reuses its pixel buffer: a second viewer triggering a fresh capture while
// the first is still compressing the previous one would show the first viewer
// half of each. Two people watching one screen is rare enough that taking
// turns is the right trade for not copying 33 MB per frame.
type grabber struct {
	opts Options
	logf func(string, ...any)

	mu     sync.Mutex
	sess   screen.Session
	cached *image.RGBA
	last   time.Time
	w, h   int
	err    string
	via    string
	ctrl   bool
}

// open attaches to the display, or returns why it cannot.
//
// When the platform cannot be captured — a Wayland session, most often — the
// fallback is a VNC server running on this same machine. That keeps the
// promise the viewer makes: the person watching still installs nothing, and
// the dependency is one the operator of *this* machine chose, can see running,
// and can stop.
func (g *grabber) openLocked() error {
	if g.sess != nil {
		return nil
	}
	sess, err := openSession()
	if err == nil {
		g.sess, g.err, g.via = sess, "", ""
		g.ctrl = sess.Controllable()
		return nil
	}

	bridged, addr, berr := g.bridgeLocked()
	if berr == nil {
		g.logf("desktop helper: %v", err)
		g.logf("desktop helper: bridging the VNC server at %s instead", addr)
		g.sess, g.err = bridged, ""
		g.via = "VNC at " + addr
		g.ctrl = bridged.Controllable()
		return nil
	}

	// Report the platform's own reason, not the bridge's: "this is a Wayland
	// session" is the useful sentence, and the failed fallback is a detail
	// underneath it.
	g.err = err.Error()
	if !errors.Is(berr, errNoBridge) {
		g.err += "\nThe VNC fallback did not work either: " + berr.Error()
	}
	g.w, g.h, g.ctrl, g.via = 0, 0, false, ""
	return err
}

// errNoBridge means no bridge was configured or found, as opposed to one that
// was tried and failed.
var errNoBridge = errors.New("no VNC server to bridge")

// vncCandidates are the ports a VNC server on this machine is likely to be on:
// display :0 and display :1.
var vncCandidates = []string{"127.0.0.1:5900", "127.0.0.1:5901"}

// bridgeLocked finds and connects to a local VNC server.
func (g *grabber) bridgeLocked() (screen.Session, string, error) {
	if strings.EqualFold(g.opts.VNCAddr, "off") {
		return nil, "", errNoBridge
	}
	if addr := g.opts.VNCAddr; addr != "" {
		sess, err := screen.DialVNC(addr, g.opts.VNCPassword)
		return sess, addr, err
	}
	// Nobody said where. Look on loopback only — a server somewhere else on
	// the network is not this machine's screen, and picking one up by
	// accident would show a viewer the wrong computer.
	for _, addr := range vncCandidates {
		if !screen.ProbeVNC(addr, 700*time.Millisecond) {
			continue
		}
		sess, err := screen.DialVNC(addr, g.opts.VNCPassword)
		if err != nil {
			return nil, addr, err
		}
		return sess, addr, nil
	}
	return nil, "", errNoBridge
}

// probe reports what a viewer would get, opening the display if needed.
func (g *grabber) probe() resource.DesktopStatus {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.openLocked(); err != nil {
		return g.statusLocked()
	}
	if g.w == 0 {
		img, err := g.sess.Capture()
		if err != nil {
			g.err = err.Error()
			g.dropLocked()
			return g.statusLocked()
		}
		g.cached = img
		g.w, g.h = img.Bounds().Dx(), img.Bounds().Dy()
		g.last = time.Now()
	}
	return g.statusLocked()
}

func (g *grabber) status() resource.DesktopStatus {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.statusLocked()
}

func (g *grabber) statusLocked() resource.DesktopStatus {
	return resource.DesktopStatus{
		Ready:   g.err == "",
		Width:   g.w,
		Height:  g.h,
		Control: g.ctrl,
		Error:   g.err,
		Via:     g.via,
	}
}

// dropLocked forgets a broken session so the next attempt starts a new one.
// The display going away — a lock screen, an X server restart, a laptop lid —
// is normal and should heal by itself.
func (g *grabber) dropLocked() {
	if g.sess != nil {
		_ = g.sess.Close()
		g.sess = nil
	}
	g.cached = nil
	g.w, g.h = 0, 0
	g.via = ""
}

// withFrame captures — or reuses a frame younger than maxAge — and calls fn
// while the display is locked.
func (g *grabber) withFrame(maxAge time.Duration, fn func(*image.RGBA, image.Point, bool) error) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.openLocked(); err != nil {
		return err
	}
	img := g.cached
	if img == nil || time.Since(g.last) >= maxAge {
		var err error
		img, err = g.sess.Capture()
		if err != nil {
			g.err = err.Error()
			g.dropLocked()
			return err
		}
		g.cached = img
		g.last = time.Now()
		g.w, g.h = img.Bounds().Dx(), img.Bounds().Dy()
	}

	ptr, hasPtr := g.sess.Pointer()
	return fn(img, ptr, hasPtr)
}

func (g *grabber) input(evs []screen.Event) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.openLocked(); err != nil {
		return err
	}
	for _, ev := range evs {
		if err := g.sess.Input(ev); err != nil {
			return err
		}
	}
	return nil
}

func (g *grabber) close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.dropLocked()
}

func intParam(r *http.Request, name string, def int) int {
	v, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil {
		return def
	}
	return v
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
