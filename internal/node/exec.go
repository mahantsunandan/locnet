package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/mahantsunandan/locnet/internal/resource"
)

// runJob executes a peer's job under this machine's compute configuration.
//
// The word "sandbox" appears nowhere in this file, deliberately. A job runs as
// a real user with that user's real permissions; the protections are that
// compute is off by default, that only named peers may submit, that there is
// no shell to inject into, that the process runs under an unprivileged account
// unless told otherwise, and that it is killed at a deadline. That is a
// reasonable set of controls for machines you own. It is not a sandbox and
// nothing here should be pointed at code you do not trust.
func runJob(ctx context.Context, cfg resource.ComputeConfig, job resource.Job, peer string,
	logf func(string, ...any)) resource.JobResult {

	res := resource.JobResult{}
	if err := job.Validate(); err != nil {
		res.Error = err.Error()
		res.ExitCode = -1
		return res
	}

	limit := cfg.Timeout()
	if job.TimeoutSeconds > 0 && job.TimeoutSeconds < limit {
		limit = job.TimeoutSeconds
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(limit)*time.Second)
	defer cancel()

	// No shell. The command and its arguments are exec'd as given, so a
	// semicolon is a semicolon and a glob is a literal asterisk.
	cmd := exec.CommandContext(ctx, job.Command[0], job.Command[1:]...)

	dir := job.Dir
	if dir == "" {
		dir = cfg.WorkDir
	}
	if dir == "" {
		dir = os.TempDir()
	}
	cmd.Dir = dir

	// A job inherits nothing from the daemon's environment. locnetd runs as a
	// system service with whatever the init system handed it, and passing
	// that through would leak configuration a peer has no business seeing.
	cmd.Env = []string{
		"PATH=" + defaultPath(),
		"HOME=" + dir,
		"LOCNET_JOB_FROM=" + peer,
	}
	if job.Count > 0 {
		cmd.Env = append(cmd.Env,
			fmt.Sprintf("LOCNET_JOB_INDEX=%d", job.Index),
			fmt.Sprintf("LOCNET_JOB_COUNT=%d", job.Count))
	}

	release, err := applyCredentials(cmd, cfg)
	if err != nil {
		res.Error = err.Error()
		res.ExitCode = -1
		logf("compute: refused %s's job: %v", peer, err)
		return res
	}
	defer release()
	attach, detach := killWholeGroup(cmd)
	defer detach()
	// If something outlives the kill anyway and keeps the output pipe open,
	// stop waiting for it rather than holding the result back indefinitely.
	cmd.WaitDelay = 5 * time.Second

	var stdout, stderr limitedBuffer
	stdout.limit = resource.MaxOutputBytes
	stderr.limit = resource.MaxOutputBytes / 4
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	started := time.Now()
	err = runCommand(ctx, cmd, attach)
	res.Seconds = time.Since(started).Seconds()
	res.Stdout = stdout.String()
	res.Stderr = stderr.String()
	res.Truncated = stdout.truncated || stderr.truncated

	switch {
	case ctx.Err() == context.DeadlineExceeded:
		res.TimedOut = true
		res.ExitCode = -1
		res.Error = fmt.Sprintf("killed after %d seconds", limit)
	case err == nil:
		res.ExitCode = 0
	default:
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.ExitCode = ee.ExitCode()
		} else {
			res.ExitCode = -1
			res.Error = err.Error()
		}
	}

	logf("compute: %s ran %q → exit %d in %.1fs", peer, strings.Join(job.Command, " "),
		res.ExitCode, res.Seconds)
	return res
}

// limitedBuffer collects output up to a cap and then stops, so a command that
// prints without end cannot exhaust memory on the machine running it.
type limitedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	room := b.limit - b.buf.Len()
	if room <= 0 {
		b.truncated = true
		return len(p), nil // claim success; the process should keep running
	}
	if len(p) > room {
		b.buf.Write(p[:room])
		b.truncated = true
		return len(p), nil
	}
	return b.buf.Write(p)
}

func (b *limitedBuffer) String() string {
	s := b.buf.String()
	if b.truncated {
		s += "\n[output truncated by LocNet]"
	}
	return s
}

// ------------------------------------------------------------ HTTP surface

// handleExec is the share server's compute endpoint.
func (s *shareServer) handleExec(w http.ResponseWriter, r *http.Request, peer string) {
	s.mu.Lock()
	cfg := s.compute
	s.mu.Unlock()

	if !cfg.AllowsPeer(peer) {
		// Same 404 whether compute is off or the peer is simply not on the
		// list. A machine that does not accept your work owes you no
		// explanation of why.
		s.logf("compute: refused a job from %s", peer)
		http.Error(w, "this machine does not accept jobs from you", http.StatusNotFound)
		return
	}

	var job resource.Job
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&job); err != nil {
		http.Error(w, "malformed job", http.StatusBadRequest)
		return
	}

	res := runJob(r.Context(), cfg, job, peer, s.logf)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

// setCompute installs a new compute configuration.
func (s *shareServer) setCompute(cfg resource.ComputeConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.compute = cfg
}
