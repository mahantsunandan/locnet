// Command locnetd is the node agent. It runs as a system service, holds this
// machine's keys, keeps the network map current, and drives the WireGuard
// tunnel. The locnet CLI is a thin client for it.
package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mahantsunandan/locnet/internal/deskserve"
	"github.com/mahantsunandan/locnet/internal/hubapi"
	"github.com/mahantsunandan/locnet/internal/ipc"
	"github.com/mahantsunandan/locnet/internal/node"
	"github.com/mahantsunandan/locnet/internal/paths"
	"github.com/mahantsunandan/locnet/internal/resource"
)

// Version is stamped at build time with -ldflags "-X main.Version=...".
var Version = "0.1.0"

func main() {
	stateDir := flag.String("state-dir", paths.StateDir(), "where to keep this machine's keys and cached network map")
	noAutoUp := flag.Bool("no-auto-up", false, "start without bringing the tunnel up, even if this machine has joined")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("locnetd", Version)
		return
	}

	node.AgentVersion = Version
	run := func(ctx context.Context) error { return daemon(ctx, *stateDir, *noAutoUp) }

	// On Windows the service control manager starts us with no console and
	// expects status reports on a control channel. Everywhere else this
	// returns false immediately and we run in the foreground under systemd,
	// launchd or a terminal.
	if handled, err := runAsService(run); handled {
		if err != nil {
			log.Fatalf("locnetd: service: %v", err)
		}
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		log.Fatalf("locnetd: %v", err)
	}
}

// daemon is the agent proper: it owns the engine and the control socket, and
// returns when ctx is cancelled.
func daemon(ctx context.Context, stateDir string, noAutoUp bool) error {
	logger := log.New(os.Stderr, "", log.LstdFlags)
	logf := func(format string, a ...any) { logger.Printf(format, a...) }

	engine, err := node.NewEngine(stateDir, logf)
	if err != nil {
		return err
	}
	defer engine.Close()

	ln, err := ipc.Listen()
	if err != nil {
		return err
	}
	defer ipc.Cleanup()

	srv := &http.Server{
		Handler:           newControlHandler(engine, ln.Token(), logf),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			logger.Printf("locnetd: control socket: %v", err)
		}
	}()
	logf("locnetd %s listening on %s", Version, ln.Addr())

	// A machine that has already joined should come back up by itself after
	// a reboot. Anything else would mean every power cut needs a human.
	if st := engine.State(); st.Registered() && !noAutoUp {
		go autoUp(ctx, engine, logf)
	} else if !st.Registered() {
		logf("locnetd: this machine has not joined a network yet. Run: locnet join <code>")
	}

	<-ctx.Done()
	logf("locnetd: shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	return nil
}

var (
	// upMu serialises Engine.Up. Up checks whether it is already running
	// before it starts and records that it is only once it has finished, so
	// two at once — the boot-time retry below and someone typing `locnet up`
	// — would each create a tunnel.
	upMu sync.Mutex
	// manualControl is set once anyone brings the tunnel up or down by hand,
	// which ends the automatic retries: a `locnet down` must stay down.
	manualControl atomic.Bool
)

// autoUp brings the tunnel up at start, and keeps trying until it works.
//
// One attempt was not enough. On Windows the service starts before the device
// stack is ready, and creating the adapter fails with "problem code 0x1F … the
// system cannot find the file specified" — found by rebooting the first
// Windows machine on the network, which then sat offline, running, waiting
// for somebody to type `locnet up`. WireGuard for Windows retries for the same
// reason. A network that is not up yet at boot is the same story elsewhere.
func autoUp(ctx context.Context, e *node.Engine, logf func(string, ...any)) {
	delay := 2 * time.Second
	for attempt := 1; ; attempt++ {
		if manualControl.Load() {
			return
		}
		upMu.Lock()
		err := e.Up()
		upMu.Unlock()
		if err == nil {
			if attempt > 1 {
				logf("locnetd: the tunnel came up on attempt %d", attempt)
			}
			return
		}
		logf("locnetd: could not bring the tunnel up (attempt %d, next in %s): %v", attempt, delay, err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(delay*2, time.Minute)
	}
}

// newControlHandler builds the local API the CLI drives.
func newControlHandler(e *node.Engine, token string, logf func(string, ...any)) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, e.Status())
	})

	mux.HandleFunc("POST /join", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Code string `json:"code"`
			Up   bool   `json:"up"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "malformed request: %v", err)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		if err := e.Join(ctx, req.Code); err != nil {
			writeErr(w, http.StatusBadRequest, "%v", err)
			return
		}
		if req.Up {
			if err := bringUp(e, logf); err != nil {
				writeErr(w, http.StatusInternalServerError, "joined, but %v", err)
				return
			}
		}
		writeJSON(w, http.StatusOK, e.Status())
	})

	mux.HandleFunc("POST /up", func(w http.ResponseWriter, r *http.Request) {
		manualControl.Store(true)
		if err := bringUp(e, logf); err != nil {
			writeErr(w, http.StatusInternalServerError, "%v", err)
			return
		}
		writeJSON(w, http.StatusOK, e.Status())
	})

	mux.HandleFunc("POST /down", func(w http.ResponseWriter, r *http.Request) {
		manualControl.Store(true)
		if err := e.Down(); err != nil {
			writeErr(w, http.StatusInternalServerError, "%v", err)
			return
		}
		writeJSON(w, http.StatusOK, e.Status())
	})

	mux.HandleFunc("POST /leave", func(w http.ResponseWriter, r *http.Request) {
		if err := e.Leave(); err != nil {
			writeErr(w, http.StatusInternalServerError, "%v", err)
			return
		}
		writeJSON(w, http.StatusOK, e.Status())
	})

	mux.HandleFunc("POST /share/add", func(w http.ResponseWriter, r *http.Request) {
		var sh resource.Share
		if err := json.NewDecoder(r.Body).Decode(&sh); err != nil {
			writeErr(w, http.StatusBadRequest, "malformed request: %v", err)
			return
		}
		if err := e.AddShare(sh); err != nil {
			writeErr(w, http.StatusBadRequest, "%v", err)
			return
		}
		writeJSON(w, http.StatusOK, e.ListShares())
	})

	mux.HandleFunc("POST /share/remove", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "malformed request: %v", err)
			return
		}
		if err := e.RemoveShare(req.Name); err != nil {
			writeErr(w, http.StatusNotFound, "%v", err)
			return
		}
		writeJSON(w, http.StatusOK, e.ListShares())
	})

	mux.HandleFunc("POST /compute", func(w http.ResponseWriter, r *http.Request) {
		var cfg resource.ComputeConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeErr(w, http.StatusBadRequest, "malformed request: %v", err)
			return
		}
		if err := e.SetCompute(cfg); err != nil {
			writeErr(w, http.StatusBadRequest, "%v", err)
			return
		}
		writeJSON(w, http.StatusOK, e.Compute())
	})

	// The daemon runs as root and cannot know which human it works for, so the
	// operator's public key arrives from the CLI rather than being hunted for
	// in whichever home directory root happens to be able to read.
	mux.HandleFunc("POST /sshkeys", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			UserKey    string   `json:"user_key"`
			AcceptFrom []string `json:"accept_from"`
			SetAccept  bool     `json:"set_accept"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "malformed request: %v", err)
			return
		}
		if req.UserKey != "" {
			if err := e.SetSSHUserKey(req.UserKey); err != nil {
				writeErr(w, http.StatusInternalServerError, "%v", err)
				return
			}
		}
		if req.SetAccept {
			if err := e.SetSSHAcceptFrom(req.AcceptFrom); err != nil {
				writeErr(w, http.StatusInternalServerError, "%v", err)
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"accept_from": e.SSHAcceptFrom()})
	})

	mux.HandleFunc("GET /desktop", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, node.DesktopJSON{
			Config: e.Desktop(), Status: e.DesktopStatus(),
		})
	})

	mux.HandleFunc("POST /desktop", func(w http.ResponseWriter, r *http.Request) {
		var cfg resource.DesktopConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeErr(w, http.StatusBadRequest, "malformed request: %v", err)
			return
		}
		if err := e.SetDesktop(cfg); err != nil {
			writeErr(w, http.StatusBadRequest, "%v", err)
			return
		}
		writeJSON(w, http.StatusOK, node.DesktopJSON{
			Config: e.Desktop(), Status: e.DesktopStatus(),
		})
	})

	// The session helper announces itself here. It is a local caller like
	// any other, so it has already passed whatever guards the control
	// channel — a Unix socket owned by the locnet group, or a token file
	// only administrators can read.
	mux.HandleFunc("POST /desktop/register", func(w http.ResponseWriter, r *http.Request) {
		var reg deskserve.Registration
		if err := json.NewDecoder(r.Body).Decode(&reg); err != nil {
			writeErr(w, http.StatusBadRequest, "malformed request: %v", err)
			return
		}
		if err := e.RegisterDesktop(reg); err != nil {
			writeErr(w, http.StatusBadRequest, "%v", err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"registered": true})
	})

	mux.HandleFunc("POST /desktop/unregister", func(w http.ResponseWriter, r *http.Request) {
		e.UnregisterDesktop()
		writeJSON(w, http.StatusOK, map[string]bool{"registered": false})
	})

	// The queue lives on the hub; the CLI reaches it through the daemon
	// because the daemon is the thing holding this machine's identity key,
	// and every queue call is signed with it.
	mux.HandleFunc("POST /queue/submit", func(w http.ResponseWriter, r *http.Request) {
		var j hubapi.Job
		if err := json.NewDecoder(r.Body).Decode(&j); err != nil {
			writeErr(w, http.StatusBadRequest, "malformed request: %v", err)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		out, err := e.SubmitJob(ctx, j)
		if err != nil {
			writeErr(w, http.StatusBadGateway, "%v", err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	})

	mux.HandleFunc("POST /queue/list", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID    string `json:"id"`
			Brief bool   `json:"brief"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		jobs, err := e.ListJobs(ctx, req.ID, req.Brief)
		if err != nil {
			writeErr(w, http.StatusBadGateway, "%v", err)
			return
		}
		writeJSON(w, http.StatusOK, jobs)
	})

	mux.HandleFunc("POST /queue/cancel", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "malformed request: %v", err)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		if err := e.CancelJob(ctx, req.ID); err != nil {
			writeErr(w, http.StatusBadGateway, "%v", err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"cancelled": req.ID})
	})

	// Network administration, for a machine the hub has made an
	// administrator. The daemon signs and forwards; the hub decides.
	mux.HandleFunc("POST /manage/{op}", func(w http.ResponseWriter, r *http.Request) {
		op := r.PathValue("op")
		switch op {
		case "nodes", "invite", "invites", "revoke", "remove", "approve", "audit", "access", "webshare":
		default:
			writeErr(w, http.StatusNotFound, "unknown management request %q", op)
			return
		}
		var in json.RawMessage
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&in); err != nil && err != io.EOF {
			writeErr(w, http.StatusBadRequest, "malformed request: %v", err)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		out, err := e.Manage(ctx, op, in)
		if err != nil {
			writeErr(w, http.StatusBadGateway, "%v", strings.TrimPrefix(err.Error(), "hub: "))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(out)
	})

	// Something on this machine has changed what it serves; look again now.
	mux.HandleFunc("POST /rescan", func(w http.ResponseWriter, r *http.Request) {
		e.Rescan()
		writeJSON(w, http.StatusOK, map[string]bool{"rescanning": true})
	})

	mux.HandleFunc("POST /hosts", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "malformed request: %v", err)
			return
		}
		if err := e.SetManageHosts(req.Enabled); err != nil {
			writeErr(w, http.StatusInternalServerError, "%v", err)
			return
		}
		writeJSON(w, http.StatusOK, e.Status())
	})

	if token == "" {
		return mux
	}
	// Only reached on Windows, where the control channel is a loopback
	// socket rather than a filesystem object with an owner.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get(ipc.TokenHeader)
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			logf("locnetd: rejected a control request with a bad token from %s", r.RemoteAddr)
			writeErr(w, http.StatusUnauthorized, "bad control token")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// upTimeout bounds how long the caller waits for the tunnel to start. Every
// step of Up talks to the kernel, and any of them can wedge on an unusual
// host. Without a bound the CLI just times out with nothing useful to say.
const upTimeout = 40 * time.Second

// bringUp runs Up with a deadline, so a stuck step becomes an error naming the
// stage rather than a silent hang.
//
// Up is left running when the deadline passes rather than being cancelled: it
// is partway through creating an interface and there is no safe point to
// abandon it. The operator gets an answer; the daemon finishes or logs why.
func bringUp(e *node.Engine, logf func(string, ...any)) error {
	done := make(chan error, 1)
	go func() {
		upMu.Lock()
		defer upMu.Unlock()
		done <- e.Up()
	}()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("the tunnel would not start: %w", err)
		}
		return nil
	case <-time.After(upTimeout):
		logf("locnetd: bringing the tunnel up has taken over %s; it is still running", upTimeout)
		return fmt.Errorf("the tunnel did not start within %s. "+
			"Run `journalctl -u locnetd -n 40` — the last `up:` line names the step it is stuck on", upTimeout)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, format string, args ...any) {
	writeJSON(w, status, map[string]string{"error": fmt.Sprintf(format, args...)})
}
