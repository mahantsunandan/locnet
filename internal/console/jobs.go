package console

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/mahantsunandan/locnet/internal/node"
	"github.com/mahantsunandan/locnet/internal/peercfg"
	"github.com/mahantsunandan/locnet/internal/remote"
)

// A job is one fan-out — a command or a transfer aimed at several machines —
// whose output the page collects as it happens.
//
// Copying a folder to six machines takes minutes. A single request that
// answers at the end would look like a hung page and would time out. So the
// request starts the work and returns an id, and the page reads lines as they
// arrive. That also makes cancelling possible, which matters most for exactly
// the long transfers that made this necessary.
type job struct {
	mu      sync.Mutex
	lines   []jobLine
	done    bool
	summary string
	started time.Time
	cancel  context.CancelFunc
	// percent is the most recent completion figure seen in the output, or
	// -1 when the transport could not report one (scp cannot).
	percent int
}

type jobLine struct {
	Target string `json:"target,omitempty"`
	Text   string `json:"text"`
	// Kind is "", "ok" or "err", so the page can colour the line without
	// having to parse it.
	Kind string `json:"kind,omitempty"`
}

func (j *job) add(target, text, kind string) {
	j.mu.Lock()
	defer j.mu.Unlock()

	if p := remote.Percent(text); p >= 0 {
		j.percent = p
		// A progress line replaces the last one rather than piling up: rsync
		// emits hundreds of them, and a log of "3%… 4%… 5%" is not a log.
		if n := len(j.lines); n > 0 && j.lines[n-1].Kind == "progress" {
			j.lines[n-1] = jobLine{Target: target, Text: text, Kind: "progress"}
			return
		}
		j.lines = append(j.lines, jobLine{Target: target, Text: text, Kind: "progress"})
		return
	}
	j.lines = append(j.lines, jobLine{Target: target, Text: text, Kind: kind})
}

func (j *job) finish(summary string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.summary, j.done, j.percent = summary, true, 100
}

// newJob registers a job and returns its id.
func (s *Server) newJob(cancel context.CancelFunc) (string, *job) {
	var raw [8]byte
	rand.Read(raw[:])
	id := hex.EncodeToString(raw[:])

	j := &job{started: time.Now(), cancel: cancel, percent: -1}
	s.jobMu.Lock()
	if s.jobs == nil {
		s.jobs = map[string]*job{}
	}
	s.jobs[id] = j
	s.reapLocked()
	s.jobMu.Unlock()
	return id, j
}

// reapLocked drops finished jobs after a while so a long-lived console does
// not accumulate the output of every transfer it ever ran.
func (s *Server) reapLocked() {
	for id, j := range s.jobs {
		j.mu.Lock()
		stale := j.done && time.Since(j.started) > 30*time.Minute
		j.mu.Unlock()
		if stale {
			delete(s.jobs, id)
		}
	}
}

func (s *Server) job(id string) *job {
	s.jobMu.Lock()
	defer s.jobMu.Unlock()
	return s.jobs[id]
}

// resolveTargets turns peer names from the page into addresses and logins.
//
// The page sends names, never addresses. It could send an address — it is a
// local page holding the token — but then the set of machines LocNet will SSH
// to would be whatever the page said, rather than whatever is actually on the
// mesh. Resolving here means a target has to be a peer.
func (s *Server) resolveTargets(names []string) ([]remote.Target, error) {
	var st node.Status
	if err := s.daemon.Get("/status", &st); err != nil {
		return nil, err
	}
	byName := map[string]node.PeerStatus{}
	for _, p := range st.Peers {
		byName[p.Name] = p
	}

	var out []remote.Target
	var unknown, offline []string
	for _, n := range names {
		p, ok := byName[n]
		if !ok {
			unknown = append(unknown, n)
			continue
		}
		if !p.Online {
			offline = append(offline, n)
			continue
		}
		out = append(out, remote.Target{
			Name:  p.Name,
			Host:  p.IP.String(),
			Login: peercfg.UserFor(p.Name),
			OS:    p.OS,
		})
	}
	if len(out) == 0 {
		switch {
		case len(unknown) > 0:
			return nil, fmt.Errorf("not on this network: %v", unknown)
		case len(offline) > 0:
			return nil, fmt.Errorf("offline: %v", offline)
		}
		return nil, fmt.Errorf("no machines selected")
	}
	sort.Slice(out, func(i, k int) bool { return out[i].Name < out[k].Name })
	return out, nil
}

// handleExec runs one command on several machines over SSH.
//
// This is deliberately separate from /api/run. That one uses LocNet's own
// compute channel, which the far machine has to opt into and which runs no
// shell. This one uses the account you already have there. Both are useful:
// compute is for lending cycles to colleagues, SSH is for administering
// machines you own.
func (s *Server) handleExec(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Peers   []string `json:"peers"`
		Command string   `json:"command"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	targets, err := s.resolveTargets(req.Peers)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	id, j := s.newJob(cancel)
	j.add("", fmt.Sprintf("$ %s   → %s", req.Command, names(targets)), "head")

	go func() {
		defer cancel()
		res := remote.Exec(ctx, targets, req.Command, func(target, line string) {
			j.add(target, line, "")
		})
		reportResults(j, res)
	}()

	writeJSON(w, map[string]string{"job": id})
}

// handleCopy sends files and folders to several machines over SFTP.
func (s *Server) handleCopy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Peers   []string `json:"peers"`
		Sources []string `json:"sources"`
		Dest    string   `json:"dest"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	if len(req.Sources) == 0 {
		writeErr(w, http.StatusBadRequest, "nothing selected to send")
		return
	}
	targets, err := s.resolveTargets(req.Peers)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}

	dest := req.Dest
	if dest == "" {
		dest = "~/"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
	id, j := s.newJob(cancel)
	j.add("", fmt.Sprintf("sending %d item(s) to %s:%s", len(req.Sources), names(targets), dest), "head")

	go func() {
		defer cancel()
		res := remote.Copy(ctx, targets, req.Sources, req.Dest, func(target, line string) {
			j.add(target, line, "")
		})
		reportResults(j, res)
	}()

	writeJSON(w, map[string]string{"job": id})
}

// handleFetch pulls a path from several machines into the download folder.
func (s *Server) handleFetch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Peers []string `json:"peers"`
		Path  string   `json:"path"`
		// Into is the local folder to collect into. Empty means the console's
		// download directory — the file manager sends whichever folder its
		// left pane is showing, because that is where the user is looking.
		Into string `json:"into"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	into := s.download
	if req.Into != "" {
		if !filepath.IsAbs(req.Into) {
			writeErr(w, http.StatusBadRequest, "the destination must be an absolute path")
			return
		}
		into = req.Into
	}
	targets, err := s.resolveTargets(req.Peers)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}

	// One subfolder per machine, created up front: scp will not make a
	// destination directory itself, and six machines' copies of syslog in one
	// folder would leave one file.
	for _, t := range targets {
		if err := os.MkdirAll(filepath.Join(into, t.Name), 0o755); err != nil {
			writeErr(w, http.StatusInternalServerError, "%v", err)
			return
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
	id, j := s.newJob(cancel)
	j.add("", fmt.Sprintf("fetching %s from %s into %s", req.Path, names(targets), into), "head")

	go func() {
		defer cancel()
		res := remote.Fetch(ctx, targets, req.Path, into, func(target, line string) {
			j.add(target, line, "")
		})
		reportResults(j, res)
	}()

	writeJSON(w, map[string]string{"job": id})
}

func reportResults(j *job, res []remote.Result) {
	for _, r := range res {
		if r.OK {
			j.add(r.Target, fmt.Sprintf("done in %.1fs", r.Secs), "ok")
		} else {
			j.add(r.Target, r.Error, "err")
		}
	}
	j.finish(remote.Summarise(res))
}

// handleJob returns whatever has been logged since the page last asked.
func (s *Server) handleJob(w http.ResponseWriter, r *http.Request) {
	j := s.job(r.URL.Query().Get("id"))
	if j == nil {
		writeErr(w, http.StatusNotFound, "no such job (it may have expired)")
		return
	}
	since, _ := strconv.Atoi(r.URL.Query().Get("since"))

	j.mu.Lock()
	defer j.mu.Unlock()
	if since < 0 || since > len(j.lines) {
		since = 0
	}
	writeJSON(w, map[string]any{
		"lines":   j.lines[since:],
		"next":    len(j.lines),
		"done":    j.done,
		"summary": j.summary,
		"percent": j.percent,
	})
}

// handleCancel stops a running job.
func (s *Server) handleCancel(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Job string `json:"job"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	j := s.job(req.Job)
	if j == nil {
		writeErr(w, http.StatusNotFound, "no such job")
		return
	}
	if j.cancel != nil {
		j.cancel()
	}
	j.add("", "cancelled", "err")
	writeJSON(w, map[string]bool{"cancelled": true})
}

func names(t []remote.Target) string {
	out := make([]string, 0, len(t))
	for _, x := range t {
		out = append(out, x.Name)
	}
	return joinComma(out)
}

func joinComma(in []string) string {
	switch len(in) {
	case 0:
		return "nothing"
	case 1:
		return in[0]
	}
	s := ""
	for i, x := range in {
		if i > 0 {
			s += ", "
		}
		s += x
	}
	return s
}

// ---------------------------------------------------------------- browsing

// handleBrowse lists a folder, on this machine or on a peer.
//
// One endpoint for both sides so the two panes of the file view are the same
// code: the only difference is which machine answers, and that is a parameter
// rather than a second implementation.
func (s *Server) handleBrowse(w http.ResponseWriter, r *http.Request) {
	peer := r.URL.Query().Get("peer")
	dir := r.URL.Query().Get("path")

	if peer == "" || peer == "." {
		out, err := remote.ListLocal(dir)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "%v", err)
			return
		}
		writeJSON(w, out)
		return
	}

	targets, err := s.resolveTargets([]string{peer})
	if err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	out, err := remote.ListRemote(r.Context(), targets[0], dir)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "%v", err)
		return
	}
	writeJSON(w, out)
}
