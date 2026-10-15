// Package console is the local web interface: one page listing every machine
// on the network, what it is running, what it is sharing, and a button to
// connect to each.
//
// It runs inside the locnet CLI rather than the daemon, and it is bound to
// 127.0.0.1 with a per-run token. That is the same shape as the rest of the
// local control surface and for the same reason: the console can start
// programs and reach into peers' shares, so it must not be something another
// page in your browser — or anything on your LAN — can drive.
package console

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/mahantsunandan/locnet/docs"
	"github.com/mahantsunandan/locnet/internal/ipc"
	"github.com/mahantsunandan/locnet/internal/launch"
	"github.com/mahantsunandan/locnet/internal/node"
	"github.com/mahantsunandan/locnet/internal/peercfg"
	"github.com/mahantsunandan/locnet/internal/remote"
	"github.com/mahantsunandan/locnet/internal/resource"
	"github.com/mahantsunandan/locnet/internal/shareclient"
)

//go:embed console.html
var page []byte

// Server is the console.
type Server struct {
	token    string
	daemon   *ipc.Client
	download string

	jobMu sync.Mutex
	jobs  map[string]*job
}

// New creates a console backed by the local daemon.
func New(downloadDir string) (*Server, error) {
	c, err := ipc.Dial()
	if err != nil {
		return nil, err
	}
	var tok [24]byte
	if _, err := rand.Read(tok[:]); err != nil {
		return nil, err
	}
	if downloadDir == "" {
		home, _ := os.UserHomeDir()
		downloadDir = filepath.Join(home, "Downloads")
	}
	return &Server{token: hex.EncodeToString(tok[:]), daemon: c, download: downloadDir}, nil
}

// ListenAndServe binds to loopback and returns the URL to open. It blocks
// until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context, port int, onReady func(url string)) error {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return fmt.Errorf("console: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.handlePage)
	mux.HandleFunc("GET /api/status", s.api(s.handleStatus))
	mux.HandleFunc("POST /api/launch", s.api(s.handleLaunch))
	mux.HandleFunc("GET /api/accounts", s.api(s.handleAccounts))
	mux.HandleFunc("POST /api/account", s.api(s.handleSetAccount))
	mux.HandleFunc("GET /api/files", s.api(s.handleFiles))
	mux.HandleFunc("POST /api/download", s.api(s.handleDownload))
	mux.HandleFunc("POST /api/run", s.api(s.handleRun))
	mux.HandleFunc("POST /api/exec", s.api(s.handleExec))
	mux.HandleFunc("POST /api/copy", s.api(s.handleCopy))
	mux.HandleFunc("POST /api/fetch", s.api(s.handleFetch))
	mux.HandleFunc("GET /api/job", s.api(s.handleJob))
	mux.HandleFunc("POST /api/cancel", s.api(s.handleCancel))
	mux.HandleFunc("GET /api/browse", s.api(s.handleBrowse))
	mux.HandleFunc("GET /api/queue", s.api(s.handleQueue))
	mux.HandleFunc("POST /api/queue/submit", s.api(s.handleQueueSubmit))
	mux.HandleFunc("POST /api/queue/cancel", s.api(s.handleQueueCancel))
	mux.HandleFunc("GET /api/queue/job", s.api(s.handleQueueJob))
	mux.HandleFunc("GET /api/info", s.api(s.handleInfo))
	mux.HandleFunc("POST /api/tunnel", s.api(s.handleTunnel))
	mux.HandleFunc("POST /api/hosts", s.api(s.handleHosts))
	mux.HandleFunc("POST /api/share/add", s.api(s.handleShareAdd))
	mux.HandleFunc("POST /api/share/remove", s.api(s.handleShareRemove))
	mux.HandleFunc("POST /api/compute", s.api(s.handleCompute))
	mux.HandleFunc("POST /api/wake", s.api(s.handleWake))
	mux.HandleFunc("GET /api/diagnose", s.api(s.handleDiagnose))
	mux.HandleFunc("POST /api/manage/{op}", s.api(s.handleManage))
	mux.HandleFunc("POST /api/desktop/stop", s.api(s.handleDesktopStop))
	mux.HandleFunc("GET /api/docs", s.api(s.handleDocs))
	mux.HandleFunc("GET /api/docs/{name}", s.api(s.handleDoc))

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()

	if onReady != nil {
		onReady(fmt.Sprintf("http://%s/?t=%s", ln.Addr(), s.token))
	}
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Token is the per-run secret.
func (s *Server) Token() string { return s.token }

func (s *Server) handlePage(w http.ResponseWriter, r *http.Request) {
	// The token is checked on /api/ rather than here. The page itself is
	// inert markup; everything that can do anything is behind the API.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(page)
}

// api enforces the token on every call that can act.
//
// The token travels in a header, not a cookie or a query parameter. A
// cross-origin page cannot set a custom header without a CORS preflight, and
// this server answers no preflights — so another tab in the same browser
// cannot drive the console even if it guesses the port.
func (s *Server) api(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			http.Error(w, "no", http.StatusForbidden)
			return
		}
		got := r.Header.Get("X-Token")
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		next(w, r)
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	var st node.Status
	if err := s.daemon.Get("/status", &st); err != nil {
		writeErr(w, http.StatusBadGateway, "%v", err)
		return
	}
	writeJSON(w, st)
}

// handleAccounts reports the remembered login for each peer, so the console
// can show what it will actually connect as rather than leaving the user to
// find out from a failed password prompt.
func (s *Server) handleAccounts(w http.ResponseWriter, r *http.Request) {
	f, err := peercfg.Load()
	if err != nil {
		// A missing or unreadable preferences file is not an error worth
		// failing the page over — it just means nothing is remembered.
		writeJSON(w, map[string]string{})
		return
	}
	out := make(map[string]string, len(f.Peers))
	for name, p := range f.Peers {
		if p.User != "" {
			out[name] = p.User
		}
	}
	writeJSON(w, out)
}

// handleSetAccount remembers the account to use for a peer. An empty user
// forgets it.
func (s *Server) handleSetAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Peer string `json:"peer"`
		User string `json:"user"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Peer == "" {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	var err error
	if req.User == "" {
		err = peercfg.Forget(req.Peer)
	} else {
		err = peercfg.Set(req.Peer, peercfg.Peer{User: req.User})
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	writeJSON(w, map[string]string{"peer": req.Peer, "user": req.User})
}

func (s *Server) handleLaunch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Peer string `json:"peer"`
		Host string `json:"host"`
		Kind string `json:"kind"`
		Port uint16 `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}

	kind := launch.Kind(req.Kind)
	login := peercfg.UserFor(req.Peer)
	target := launch.TargetFor(kind, req.Host, req.Port)

	if kind == launch.KindSSH {
		// Open a real terminal running ssh. Returning a command for the
		// user to paste, which this used to do, is a button that does
		// nothing.
		dest := req.Host
		if login != "" {
			dest = login + "@" + dest
		}
		if err := launch.Terminal([]string{"ssh", dest}); err != nil {
			writeErr(w, http.StatusInternalServerError, "%v", err)
			return
		}
		writeJSON(w, map[string]string{"launched": "ssh " + dest})
		return
	}

	// Check the port answers before starting a client. A viewer launched at a
	// port with nothing behind it either hangs on a timeout or flashes an
	// error and disappears — and the console has already said "launched", so
	// the button looks like it did nothing. This turns that into a sentence.
	if port := req.Port; port != 0 && kind != launch.KindBrowser {
		if !remote.Reachable(r.Context(), req.Host, port, 4*time.Second) {
			writeErr(w, http.StatusBadGateway, "%s", noServiceHint(kind, req.Peer, port))
			return
		}
		// Open is not the same as usable. A remote-desktop server that will
		// hang up on the client makes the client flash and vanish, or sit on
		// a black window, and the person blames the client.
		addr := net.JoinHostPort(req.Host, strconv.Itoa(int(port)))
		if problem := resource.CheckProtocol(r.Context(), string(kind), addr); problem != "" {
			writeErr(w, http.StatusBadGateway, "%s: %s", req.Peer, problem)
			return
		}
		if kind == launch.KindVNC {
			resource.WakeVNC(r.Context(), addr)
		}
	}

	if err := launch.RunDetached(kind, target, login); err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	shown := target
	if login != "" {
		shown = login + "@" + target
	}
	writeJSON(w, map[string]string{"launched": shown})
}

// noServiceHint says what is missing and how to start it. "Connection
// refused" is accurate and useless; the person wants to know which service to
// turn on over there.
func noServiceHint(kind launch.Kind, peer string, port uint16) string {
	base := fmt.Sprintf("nothing is listening on port %d on %s", port, peer)
	switch kind {
	case launch.KindVNC:
		return base + ".\nOn that machine:  sudo locnet setup -install\n" +
			"which installs a VNC server, starts it, and publishes it to this network.\n" +
			"If one is already running there, it is probably bound to 127.0.0.1, which\n" +
			"peers cannot reach. Publish it:  locnet share add screen :5901 -allow \"*\"\n" +
			"Then wait a few minutes — LocNet rescans for services every five.\n" +
			"On a Linux or Windows desktop, Screen (RDP) shows the real screen instead."
	case launch.KindRDP:
		return base + ".\nOn a GNOME desktop, turn on its own RDP server and give it a login —\n" +
			"on that machine, as the person who logs in there:  " + resource.FixRDP + "\n" +
			"On another Linux desktop, xrdp is the usual RDP server. Windows has one built in\n" +
			"(Settings → System → Remote Desktop)."
	case launch.KindSSH:
		return base + ".\nStart the SSH server there:  sudo systemctl enable --now sshd"
	}
	return base + "."
}

func (s *Server) handleFiles(w http.ResponseWriter, r *http.Request) {
	addr, err := netip.ParseAddr(r.URL.Query().Get("peer"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad peer address")
		return
	}
	share := r.URL.Query().Get("share")
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	c := shareclient.New(addr)
	if share == "" {
		list, err := c.List(ctx)
		if err != nil {
			writeErr(w, http.StatusBadGateway, "%v", err)
			return
		}
		writeJSON(w, list)
		return
	}
	entries, err := c.Dir(ctx, share, r.URL.Query().Get("path"))
	if err != nil {
		writeErr(w, http.StatusBadGateway, "%v", err)
		return
	}
	writeJSON(w, entries)
}

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Peer  string `json:"peer"`
		Share string `json:"share"`
		Path  string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	addr, err := netip.ParseAddr(req.Peer)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad peer address")
		return
	}
	if err := os.MkdirAll(s.download, 0o755); err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()
	dest, err := shareclient.New(addr).Get(ctx, req.Share, req.Path, s.download)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "%v", err)
		return
	}
	writeJSON(w, map[string]string{"saved": dest})
}

// handleRun submits a job to a peer that offers compute.
//
// The console is a thin client here: it does no filtering of its own. Whether
// the job is permitted is decided on the machine that would run it, against an
// access list only that machine's operator controls.
func (s *Server) handleRun(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Peer    string   `json:"peer"`
		Command []string `json:"command"`
		Dir     string   `json:"dir,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	addr, err := netip.ParseAddr(req.Peer)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad peer address")
		return
	}
	job := resource.Job{Command: req.Command, Dir: req.Dir}
	if err := job.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(),
		time.Duration(resource.DefaultMaxSeconds+30)*time.Second)
	defer cancel()

	res, err := shareclient.New(addr).Exec(ctx, job)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "%v", err)
		return
	}
	writeJSON(w, res)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, format string, args ...any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf(format, args...)})
}

// Open launches the system browser at url. Failure is not fatal — the URL is
// printed either way.
func Open(url string) error { return launch.Run(launch.KindBrowser, url) }

// handleDocs lists the documentation compiled into this program.
func (s *Server) handleDocs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, docs.List())
}

// handleDoc returns one document's markdown; the page renders it.
func (s *Server) handleDoc(w http.ResponseWriter, r *http.Request) {
	text, ok := docs.Read(r.PathValue("name"))
	if !ok {
		writeErr(w, http.StatusNotFound, "no such document")
		return
	}
	writeJSON(w, map[string]string{"name": r.PathValue("name"), "text": text})
}
