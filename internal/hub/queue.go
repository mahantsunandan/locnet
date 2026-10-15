package hub

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mahantsunandan/locnet/internal/hubapi"
	"github.com/mahantsunandan/locnet/internal/placement"
	"github.com/mahantsunandan/locnet/internal/resource"
)

// The queue turns "run this on whichever machine is free" into something a
// fleet can do unattended.
//
// It lives on the hub because the hub is the one machine that is always on and
// already has a durable record of who exists and how loaded they are. Nothing
// is pushed: workers ask for work, which means a machine that is asleep,
// rebooting or simply busy is not a machine anything has to route around. It
// also means the queue survives every worker being off — the jobs sit there
// until someone comes back.
//
// Consent is the existing one, deliberately. A machine runs a queued job only
// if its own compute configuration already allows the person who submitted it.
// There is no separate "worker mode" to turn on and no way for the hub to
// conscript a machine that has not opted in, because the hub is the one part
// of this system that is not trusted with execution.

// Job and JobResult are the wire contract, and live in hubapi so that the node
// agent can speak it without importing the hub. The state names are re-exported
// so that reading this file does not mean reading two.
type (
	Job       = hubapi.Job
	JobResult = hubapi.JobResult
)

const (
	JobQueued    = hubapi.JobQueued
	JobRunning   = hubapi.JobRunning
	JobDone      = hubapi.JobDone
	JobFailed    = hubapi.JobFailed
	JobCancelled = hubapi.JobCancelled
)

const (
	// defaultMaxAttempts covers a worker rebooting mid-job. Beyond that a
	// job that keeps disappearing is a job that will keep disappearing, and
	// retrying it forever only hides the problem.
	defaultMaxAttempts = 3
	// leaseSlack is how long after a job's own time limit the hub waits
	// before assuming the worker is gone.
	leaseSlack = 2 * time.Minute
	// keepFinished bounds the history kept in the state file.
	keepFinished = 200
)

// Submit adds a job to the queue.
func (s *Store) Submit(j *Job) (*Job, error) {
	if len(j.Command) == 0 || strings.TrimSpace(j.Command[0]) == "" {
		return nil, fmt.Errorf("a job needs a command")
	}
	if j.Submitter == "" {
		return nil, fmt.Errorf("a job needs a submitter")
	}
	id, err := jobID()
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if j.On != "" && !s.nodeExistsLocked(j.On) {
		return nil, fmt.Errorf("there is no machine called %q on this network", j.On)
	}
	j.ID = id
	j.State = JobQueued
	j.QueuedAt = time.Now()
	if j.MaxAttempts <= 0 {
		j.MaxAttempts = defaultMaxAttempts
	}
	s.st.Queue = append(s.st.Queue, j)
	s.pruneQueueLocked()
	// Audited before saving, so the entry is on disk with the job it
	// describes rather than waiting for some later change to carry it.
	s.auditLocked(j.Submitter, "job.submit", fmt.Sprintf("%s %s", j.ID, strings.Join(j.Command, " ")))
	if err := s.save(); err != nil {
		return nil, err
	}
	s.bumpQueue()
	cp := *j
	return &cp, nil
}

// Claim hands one job to a worker, or reports that there is nothing for it.
//
// The matching is done here rather than by the worker for two reasons: the hub
// already knows every machine's load from the reports it collects, and a
// worker deciding for itself what it is capable of would be a worker that can
// lie about it to get work it should not have.
func (s *Store) Claim(nodeID string) (*Job, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sweepLocked()
	worker, ok := s.st.Nodes[nodeID]
	if !ok || !s.visibleLocked(worker) {
		return nil, false
	}

	cand := placement.Candidate{
		Name: worker.Name, Online: true, Stats: worker.Stats,
	}

	queued := s.queuedLocked()
	for _, j := range queued {
		if j.On != "" && j.On != worker.Name {
			continue
		}
		// The worker's own access list decides, exactly as it does for a
		// direct `locnet run`. The queue is a scheduler, not an authority.
		if !worker.Compute.AllowsPeer(j.Submitter) {
			continue
		}
		if ok, _ := j.Need.Fits(cand); !ok {
			continue
		}

		j.State = JobRunning
		j.Node = worker.Name
		j.Attempts++
		j.StartedAt = time.Now()
		limit := time.Duration(j.MaxSeconds) * time.Second
		if limit <= 0 {
			limit = time.Duration(resource.DefaultMaxSeconds) * time.Second
		}
		j.LeaseUntil = time.Now().Add(limit + leaseSlack)
		_ = s.save()
		s.bumpQueue()
		// A copy, because the caller encodes it after the lock is released
		// and the original goes on changing under other requests.
		cp := *j
		return &cp, true
	}
	return nil, false
}

// Complete records a finished job.
func (s *Store) Complete(nodeID string, res JobResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	worker, ok := s.st.Nodes[nodeID]
	if !ok {
		return fmt.Errorf("unknown node")
	}
	j := s.jobLocked(res.ID)
	if j == nil {
		return fmt.Errorf("no job called %q", res.ID)
	}
	// A worker whose lease expired may still turn up with an answer, and by
	// then the job may be running somewhere else. Its result is stale and
	// accepting it would overwrite a live attempt.
	if j.Node != worker.Name {
		return fmt.Errorf("job %s is no longer yours", j.ID)
	}
	if j.Terminal() {
		return nil
	}

	j.FinishedAt = time.Now()
	j.ExitCode = res.ExitCode
	j.Stdout = hubapi.TrimOutput(res.Stdout, hubapi.KeepStdout)
	j.Stderr = hubapi.TrimOutput(res.Stderr, hubapi.KeepStderr)
	j.Seconds = res.Seconds
	j.Error = res.Error
	j.LeaseUntil = time.Time{}
	if res.ExitCode == 0 && res.Error == "" {
		j.State = JobDone
	} else {
		j.State = JobFailed
	}
	s.pruneQueueLocked()
	s.bumpQueue()
	return s.save()
}

// Cancel stops a job. A queued job is dropped; a running one is marked
// cancelled and its worker is told when it next checks in.
//
// Only the machine that submitted a job, or an administrator, may cancel it.
// Any member used to be able to, which on a shared fleet let one person's
// machine quietly throw away everybody else's overnight sweep.
func (s *Store) Cancel(who string, admin bool, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j := s.jobLocked(id)
	if j == nil {
		return fmt.Errorf("no job called %q", id)
	}
	if !admin && j.Submitter != who {
		return fmt.Errorf("job %s was submitted by %s; only %s or an administrator can cancel it", j.ID, j.Submitter, j.Submitter)
	}
	if j.Terminal() {
		return fmt.Errorf("job %s already finished", j.ID)
	}
	j.State = JobCancelled
	j.FinishedAt = time.Now()
	j.LeaseUntil = time.Time{}
	s.auditLocked(who, "job.cancel", j.ID)
	s.bumpQueue()
	return s.save()
}

// Jobs returns the queue, newest first. brief leaves out each job's output,
// which is most of the bytes and is not what a listing is for.
func (s *Store) Jobs(brief bool) []Job {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	out := make([]Job, 0, len(s.st.Queue))
	for _, j := range s.st.Queue {
		cp := *j
		if brief {
			cp.OutputBytes = len(cp.Stdout) + len(cp.Stderr)
			cp.Stdout, cp.Stderr = "", ""
		}
		out = append(out, cp)
	}
	sort.SliceStable(out, func(i, k int) bool {
		return out[i].QueuedAt.After(out[k].QueuedAt)
	})
	return out
}

// JobByID finds one job by its full ID or a unique prefix of it.
func (s *Store) JobByID(id string) (Job, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if j := s.jobLocked(id); j != nil {
		return *j, true
	}
	return Job{}, false
}

// Cancelled reports whether a running job has been cancelled under a worker,
// so the worker can stop wasting the machine on it.
func (s *Store) Cancelled(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	j := s.jobLocked(id)
	return j != nil && j.State == JobCancelled
}

// ------------------------------------------------------------ internals

func (s *Store) jobLocked(id string) *Job {
	if id == "" {
		return nil
	}
	var match *Job
	for _, j := range s.st.Queue {
		if j.ID == id {
			return j
		}
		if strings.HasPrefix(j.ID, id) {
			if match != nil {
				return nil // ambiguous prefix: better to find nothing
			}
			match = j
		}
	}
	return match
}

func (s *Store) nodeExistsLocked(name string) bool {
	for _, n := range s.st.Nodes {
		if n.Name == name {
			return true
		}
	}
	return false
}

// queuedLocked returns runnable jobs in the order they should be considered.
func (s *Store) queuedLocked() []*Job {
	var out []*Job
	for _, j := range s.st.Queue {
		if j.State == JobQueued {
			out = append(out, j)
		}
	}
	sort.SliceStable(out, func(i, k int) bool {
		if out[i].Priority != out[k].Priority {
			return out[i].Priority > out[k].Priority
		}
		return out[i].QueuedAt.Before(out[k].QueuedAt)
	})
	return out
}

// sweepLocked requeues jobs whose worker never came back.
func (s *Store) sweepLocked() {
	now := time.Now()
	changed := false
	for _, j := range s.st.Queue {
		if j.State != JobRunning || j.LeaseUntil.IsZero() || now.Before(j.LeaseUntil) {
			continue
		}
		changed = true
		if j.Attempts >= j.MaxAttempts {
			j.State = JobFailed
			j.FinishedAt = now
			j.Error = fmt.Sprintf("%s stopped answering, and this was attempt %d of %d",
				j.Node, j.Attempts, j.MaxAttempts)
			continue
		}
		j.State = JobQueued
		j.Node = ""
		j.LeaseUntil = time.Time{}
		j.StartedAt = time.Time{}
	}
	if changed {
		_ = s.save()
	}
}

// pruneQueueLocked keeps the history from growing without limit.
func (s *Store) pruneQueueLocked() {
	var finished []*Job
	for _, j := range s.st.Queue {
		if j.Terminal() {
			finished = append(finished, j)
		}
	}
	if len(finished) <= keepFinished {
		return
	}
	sort.Slice(finished, func(i, k int) bool {
		return finished[i].FinishedAt.Before(finished[k].FinishedAt)
	})
	drop := map[string]bool{}
	for _, j := range finished[:len(finished)-keepFinished] {
		drop[j.ID] = true
	}
	kept := s.st.Queue[:0]
	for _, j := range s.st.Queue {
		if !drop[j.ID] {
			kept = append(kept, j)
		}
	}
	s.st.Queue = kept
}

// bumpQueue wakes workers that are long-polling for something to do.
//
// It is deliberately not s.bump(): the netmap version is what every node
// watches, and moving it because a job changed state would make a busy queue
// re-sign and re-send the whole network map to every machine, several times a
// minute, for news none of them needs.
func (s *Store) bumpQueue() {
	close(s.queueChanged)
	s.queueChanged = make(chan struct{})
}

// WaitForQueueChange blocks until the queue changes or timeout passes.
func (s *Store) WaitForQueueChange(timeout time.Duration, done <-chan struct{}) {
	s.mu.Lock()
	ch := s.queueChanged
	s.mu.Unlock()

	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-ch:
	case <-t.C:
	case <-done:
	}
}

func jobID() (string, error) {
	var b [5]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "j" + hex.EncodeToString(b[:]), nil
}
