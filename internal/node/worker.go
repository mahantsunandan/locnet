package node

import (
	"context"
	"strings"
	"time"

	"github.com/mahantsunandan/locnet/internal/hub"
	"github.com/mahantsunandan/locnet/internal/hubapi"
	"github.com/mahantsunandan/locnet/internal/resource"
)

// The worker side of the queue: ask the hub for a job, run it, say what
// happened, ask again.
//
// Pulling rather than being pushed is what makes this survive a fleet of
// laptops. A machine that is asleep asks for nothing; a machine that is busy
// asks for nothing more until it is free; a machine that is switched off in
// the middle of a job simply stops asking, and the hub gives the job to
// somebody else once its lease runs out. None of those needs any code here.
//
// The loop runs only while this machine's own compute configuration is on.
// Turning compute off stops it within one poll, and nothing on the hub can
// start it.

// workerIdleWait is how long to wait after an error before asking again. The
// hub holds an idle claim open by itself, so this is only for failures.
const workerIdleWait = 15 * time.Second

// workerLoop runs queued jobs until ctx is cancelled.
func (e *Engine) workerLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		cfg := e.Compute()
		if !cfg.Enabled {
			// Not offering compute means not taking queued work either.
			// Checking rather than subscribing keeps this to one branch.
			if !sleep(ctx, 30*time.Second) {
				return
			}
			continue
		}

		job, ok, err := e.claimJob(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			e.logf("queue: could not ask the hub for work: %v", err)
			if !sleep(ctx, workerIdleWait) {
				return
			}
			continue
		}
		if !ok {
			continue // the claim timed out with nothing to do
		}

		e.runQueued(ctx, cfg, job)
	}
}

// claimJob asks the hub for one job. ok is false when there was nothing.
func (e *Engine) claimJob(ctx context.Context) (hub.Job, bool, error) {
	// No client-side timeout below the hub's own long poll, or every idle
	// wait would look like a failure.
	claimCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	var job hub.Job
	err := e.tryHubs(claimCtx, func(addr string) error {
		return e.postJSON(claimCtx, addr, "/queue/claim", map[string]string{}, &job, true)
	})
	if err != nil {
		return hub.Job{}, false, err
	}
	if job.ID == "" {
		return hub.Job{}, false, nil
	}
	return job, true, nil
}

// cancelCheckInterval is how often a running queued job asks the hub whether
// it has been cancelled. A cancel takes effect within this long.
const cancelCheckInterval = 10 * time.Second

// runQueued executes one claimed job and reports the outcome.
func (e *Engine) runQueued(ctx context.Context, cfg resource.ComputeConfig, job hub.Job) {
	e.logf("queue: running %s for %s: %s", job.ID, job.Submitter, strings.Join(job.Command, " "))

	// Cancelling a running job used to mark it cancelled on the hub and do
	// nothing else: the process ran to the end, holding the machine, and its
	// result was then thrown away. Watching for the cancel is what makes the
	// button mean what it says.
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	cancelled := make(chan struct{})
	go e.watchForCancel(runCtx, job.ID, func() {
		close(cancelled)
		stop()
	})

	res := runJob(runCtx, cfg, resource.Job{
		Command:        job.Command,
		Dir:            job.Dir,
		TimeoutSeconds: job.MaxSeconds,
		Index:          job.Index,
		Count:          job.Count,
	}, job.Submitter, e.logf)

	select {
	case <-cancelled:
		e.logf("queue: %s was cancelled on the hub and has been stopped", job.ID)
		return
	default:
	}

	out := hub.JobResult{
		ID:       job.ID,
		ExitCode: res.ExitCode,
		Stdout:   hubapi.TrimOutput(res.Stdout, hubapi.KeepStdout),
		Stderr:   hubapi.TrimOutput(res.Stderr, hubapi.KeepStderr),
		Seconds:  res.Seconds,
		Error:    res.Error,
	}
	if res.TimedOut {
		out.Error = "the job hit its time limit and was stopped"
	}

	// Report even if the daemon is shutting down: a result that never
	// arrives costs the job another attempt on another machine, which is the
	// expensive kind of mistake.
	reportCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	err := e.tryHubs(reportCtx, func(addr string) error {
		return e.postJSON(reportCtx, addr, "/queue/result", out, nil, true)
	})
	if err != nil {
		e.logf("queue: %s finished but the hub would not take the result: %v", job.ID, err)
		return
	}
	e.logf("queue: %s finished with exit code %d in %.1fs", job.ID, res.ExitCode, res.Seconds)
}

// watchForCancel polls the hub until ctx ends, calling onCancel once if the
// job is cancelled there. A hub that cannot be reached is not a cancel: the
// job carries on, and the lease decides its fate as it always did.
func (e *Engine) watchForCancel(ctx context.Context, id string, onCancel func()) {
	t := time.NewTicker(cancelCheckInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		checkCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		jobs, err := e.listJobs(checkCtx, id, true)
		cancel()
		if err != nil || len(jobs) == 0 {
			continue
		}
		if jobs[0].State == hub.JobCancelled {
			onCancel()
			return
		}
	}
}

// SubmitJob puts work on the network's queue.
func (e *Engine) SubmitJob(ctx context.Context, j hub.Job) (*hub.Job, error) {
	var out hub.Job
	err := e.tryHubs(ctx, func(addr string) error {
		return e.postJSON(ctx, addr, "/queue/submit", j, &out, true)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ListJobs returns the queue. An id narrows it to one job; brief leaves out
// the jobs' output.
func (e *Engine) ListJobs(ctx context.Context, id string, brief bool) ([]hub.Job, error) {
	return e.listJobs(ctx, id, brief)
}

func (e *Engine) listJobs(ctx context.Context, id string, brief bool) ([]hub.Job, error) {
	var out []hub.Job
	req := map[string]any{"id": id, "brief": brief}
	err := e.tryHubs(ctx, func(addr string) error {
		return e.postJSON(ctx, addr, "/queue/list", req, &out, true)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CancelJob stops a queued or running job.
func (e *Engine) CancelJob(ctx context.Context, id string) error {
	return e.tryHubs(ctx, func(addr string) error {
		return e.postJSON(ctx, addr, "/queue/cancel", map[string]string{"id": id}, nil, true)
	})
}

// sleep waits, returning false if the context was cancelled first.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
