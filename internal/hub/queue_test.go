package hub

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/mahantsunandan/locnet/internal/key"
	"github.com/mahantsunandan/locnet/internal/placement"
	"github.com/mahantsunandan/locnet/internal/resource"
)

// queueFixture is a hub with a submitter and however many workers a test
// needs, all registered and reporting.
type queueFixture struct {
	store *Store
	ids   map[string]string // name -> node id
}

func newQueueFixture(t *testing.T, names ...string) *queueFixture {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "hub.json"), "testnet", DefaultPrefix)
	if err != nil {
		t.Fatal(err)
	}
	f := &queueFixture{store: store, ids: map[string]string{}}
	for _, name := range names {
		_, pub, err := key.NewMachine()
		if err != nil {
			t.Fatal(err)
		}
		tok, err := store.CreateToken("test", 1, 0)
		if err != nil {
			t.Fatal(err)
		}
		n, err := store.Register(tok.Token, &Node{Name: name, MachineKey: pub})
		if err != nil {
			t.Fatal(err)
		}
		f.ids[name] = n.ID
	}
	return f
}

// worker makes a node willing to run work from the named submitters, with the
// hardware described.
func (f *queueFixture) worker(t *testing.T, name string, stats resource.Stats, allow ...string) {
	t.Helper()
	err := f.store.Report(f.ids[name], Report{
		Stats:   stats,
		Compute: resource.ComputeConfig{Enabled: true, Allow: allow, RunAs: "someone"},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (f *queueFixture) submit(t *testing.T, from string, j *Job) *Job {
	t.Helper()
	j.Submitter = from
	out, err := f.store.Submit(j)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func plainStats() resource.Stats {
	return resource.Stats{CPUs: 8, MemFreeMB: 16000, DiskFreeGB: 200}
}

func TestQueueRunsAJobOnAWillingWorker(t *testing.T) {
	f := newQueueFixture(t, "alice", "worker")
	f.worker(t, "worker", plainStats(), "alice")

	job := f.submit(t, "alice", &Job{Command: []string{"echo", "hello"}})
	if job.State != JobQueued {
		t.Fatalf("a new job is %q, wanted queued", job.State)
	}

	got, ok := f.store.Claim(f.ids["worker"])
	if !ok {
		t.Fatal("the worker was offered nothing although the job matches it")
	}
	if got.ID != job.ID || got.State != JobRunning || got.Node != "worker" {
		t.Fatalf("claimed %+v", got)
	}

	// A second worker asking now must not get the same job twice.
	if _, ok := f.store.Claim(f.ids["worker"]); ok {
		t.Error("the same job was handed out twice")
	}

	if err := f.store.Complete(f.ids["worker"], JobResult{ID: job.ID, ExitCode: 0, Stdout: "hello\n"}); err != nil {
		t.Fatal(err)
	}
	done, _ := f.store.JobByID(job.ID)
	if done.State != JobDone || done.Stdout != "hello\n" {
		t.Errorf("finished job is %+v", done)
	}
}

func TestQueueRespectsTheWorkersAccessList(t *testing.T) {
	f := newQueueFixture(t, "alice", "bob", "worker")
	// The worker takes work from bob, and from nobody else.
	f.worker(t, "worker", plainStats(), "bob")

	f.submit(t, "alice", &Job{Command: []string{"rm", "-rf", "/"}})
	if j, ok := f.store.Claim(f.ids["worker"]); ok {
		t.Fatalf("the worker was given %s, submitted by someone its access list does not name", j.ID)
	}

	f.submit(t, "bob", &Job{Command: []string{"echo", "ok"}})
	if _, ok := f.store.Claim(f.ids["worker"]); !ok {
		t.Error("the worker refused work from a machine it does allow")
	}
}

func TestQueueExcludesMachinesThatCannotRunIt(t *testing.T) {
	f := newQueueFixture(t, "alice", "cpu-only", "gpu-box")
	f.worker(t, "cpu-only", plainStats(), "alice")
	f.worker(t, "gpu-box", resource.Stats{
		CPUs: 16, MemFreeMB: 64000, DiskFreeGB: 500,
		GPUs: []resource.GPU{{Name: "RTX 4090", MemTotalMB: 24000, MemFreeMB: 22000}},
	}, "alice")

	job := f.submit(t, "alice", &Job{
		Command: []string{"python", "train.py"},
		Need:    placement.Need{GPU: true, VRAMMB: 20000},
	})

	if _, ok := f.store.Claim(f.ids["cpu-only"]); ok {
		t.Error("a machine with no GPU was given a job that needs one")
	}
	got, ok := f.store.Claim(f.ids["gpu-box"])
	if !ok {
		t.Fatal("the machine with the right card was given nothing")
	}
	if got.ID != job.ID {
		t.Errorf("claimed %s, wanted %s", got.ID, job.ID)
	}
}

func TestQueueHonoursPinningAndPriority(t *testing.T) {
	f := newQueueFixture(t, "alice", "a", "b")
	f.worker(t, "a", plainStats(), "alice")
	f.worker(t, "b", plainStats(), "alice")

	f.submit(t, "alice", &Job{Command: []string{"first"}})
	urgent := f.submit(t, "alice", &Job{Command: []string{"urgent"}, Priority: 10})
	pinned := f.submit(t, "alice", &Job{Command: []string{"pinned"}, On: "b", Priority: 20})

	// b is pinned the highest-priority job; a cannot have it even though it
	// asked first.
	got, ok := f.store.Claim(f.ids["a"])
	if !ok {
		t.Fatal("a got nothing")
	}
	if got.ID == pinned.ID {
		t.Error("a job pinned to b was given to a")
	}
	if got.ID != urgent.ID {
		t.Errorf("a was given %q, wanted the higher-priority job", got.Command)
	}

	got, ok = f.store.Claim(f.ids["b"])
	if !ok || got.ID != pinned.ID {
		t.Errorf("b was given %+v, wanted its pinned job", got)
	}
}

func TestQueueRetriesWhenAWorkerVanishes(t *testing.T) {
	f := newQueueFixture(t, "alice", "worker")
	f.worker(t, "worker", plainStats(), "alice")
	job := f.submit(t, "alice", &Job{Command: []string{"sleep", "1"}, MaxAttempts: 2})

	claimed, ok := f.store.Claim(f.ids["worker"])
	if !ok {
		t.Fatal("nothing was claimed")
	}
	// The worker is switched off mid-job: no result ever arrives and the
	// lease runs out.
	expireLease(t, f.store, claimed.ID)

	again, ok := f.store.Claim(f.ids["worker"])
	if !ok {
		t.Fatal("an abandoned job was never offered again")
	}
	if again.Attempts != 2 {
		t.Errorf("attempt count is %d, wanted 2", again.Attempts)
	}

	// Second attempt is also abandoned, and the ceiling is 2, so it fails
	// rather than looping forever.
	expireLease(t, f.store, claimed.ID)
	if _, ok := f.store.Claim(f.ids["worker"]); ok {
		t.Error("a job past its attempt limit was offered again")
	}
	final, _ := f.store.JobByID(job.ID)
	if final.State != JobFailed {
		t.Errorf("state after exhausting attempts is %q, wanted failed", final.State)
	}
	if final.Error == "" {
		t.Error("the failure says nothing about why")
	}
}

func TestQueueRefusesAStaleResult(t *testing.T) {
	f := newQueueFixture(t, "alice", "a", "b")
	f.worker(t, "a", plainStats(), "alice")
	f.worker(t, "b", plainStats(), "alice")
	job := f.submit(t, "alice", &Job{Command: []string{"work"}})

	claimed, _ := f.store.Claim(f.ids["a"])
	expireLease(t, f.store, claimed.ID)
	if _, ok := f.store.Claim(f.ids["b"]); !ok {
		t.Fatal("b was not given the abandoned job")
	}

	// a finally comes back with its answer. By now b owns the job, and
	// accepting a's result would clobber a live attempt.
	err := f.store.Complete(f.ids["a"], JobResult{ID: job.ID, ExitCode: 0, Stdout: "stale"})
	if err == nil {
		t.Error("a result from a worker that lost the job was accepted")
	}
	now, _ := f.store.JobByID(job.ID)
	if now.State != JobRunning || now.Node != "b" {
		t.Errorf("job is %s on %s, wanted running on b", now.State, now.Node)
	}
}

func TestQueueCancel(t *testing.T) {
	f := newQueueFixture(t, "alice", "worker")
	f.worker(t, "worker", plainStats(), "alice")
	job := f.submit(t, "alice", &Job{Command: []string{"long"}})

	if err := f.store.Cancel("worker", false, job.ID); err == nil {
		t.Error("a machine that did not submit the job was allowed to cancel it")
	}
	if err := f.store.Cancel("alice", false, job.ID[:4]); err != nil {
		t.Fatalf("cancel by prefix: %v", err)
	}
	if _, ok := f.store.Claim(f.ids["worker"]); ok {
		t.Error("a cancelled job was still handed out")
	}
	if err := f.store.Cancel("alice", false, job.ID); err == nil {
		t.Error("cancelling a finished job was accepted")
	}
}

func TestQueueSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hub.json")
	store, err := Open(path, "testnet", DefaultPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Submit(&Job{Submitter: "alice", Command: []string{"echo", "hi"}}); err != nil {
		t.Fatal(err)
	}

	// The hub is restarted — a reboot, an upgrade, a power cut.
	reopened, err := Open(path, "testnet", DefaultPrefix)
	if err != nil {
		t.Fatal(err)
	}
	jobs := reopened.Jobs(false)
	if len(jobs) != 1 || jobs[0].State != JobQueued {
		t.Fatalf("after a restart the queue is %+v", jobs)
	}
}

// expireLease backdates a running job's lease so the sweeper treats its worker
// as gone.
func expireLease(t *testing.T, s *Store, id string) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	j := s.jobLocked(id)
	if j == nil {
		t.Fatalf("no job %s", id)
	}
	j.LeaseUntil = time.Now().Add(-time.Second)
}

func TestQueueAdministratorMayCancelAnyJob(t *testing.T) {
	f := newQueueFixture(t, "alice", "boss")
	job := f.submit(t, "alice", &Job{Command: []string{"long"}})
	if err := f.store.Cancel("boss", true, job.ID); err != nil {
		t.Fatalf("an administrator could not cancel: %v", err)
	}
}

// A machine waiting for approval must not be handed work: with "*" in its own
// compute list it would otherwise receive anyone's job and could report
// whatever result it liked.
func TestQueueIgnoresMachinesWaitingForApproval(t *testing.T) {
	f := newQueueFixture(t, "alice")
	if err := f.store.SetRequireApproval(true); err != nil {
		t.Fatal(err)
	}
	_, pub, err := key.NewMachine()
	if err != nil {
		t.Fatal(err)
	}
	tok, err := f.store.CreateToken("test", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	n, err := f.store.Register(tok.Token, &Node{Name: "stranger", MachineKey: pub})
	if err != nil {
		t.Fatal(err)
	}
	f.ids["stranger"] = n.ID
	f.worker(t, "stranger", plainStats(), "*")
	f.submit(t, "alice", &Job{Command: []string{"secret-work"}})

	if _, ok := f.store.Claim(n.ID); ok {
		t.Fatal("a machine waiting for approval was handed a job")
	}
	if _, _, ok := f.store.QueueMember(n.ID); ok {
		t.Error("a machine waiting for approval counts as a queue member")
	}
	if err := f.store.ApproveNode("stranger"); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.store.Claim(n.ID); !ok {
		t.Error("once admitted, the machine was still not handed work")
	}
}

func TestQueueListingHidesOtherMachinesSecrets(t *testing.T) {
	f := newQueueFixture(t, "alice", "bob")
	f.submit(t, "alice", &Job{Command: []string{"train"}, Env: []string{"API_KEY=hunter2"}})

	j := f.store.Jobs(false)[0]
	j.Stdout = "the model's output"
	redactJob(&j, "bob", false)
	if j.Env[0] != "API_KEY=…" || j.Stdout != "" || j.OutputBytes == 0 {
		t.Errorf("bob sees env %q and output %q", j.Env, j.Stdout)
	}

	stored := f.store.Jobs(false)[0]
	if stored.Env[0] != "API_KEY=hunter2" {
		t.Errorf("redacting a listing changed the stored job: %q", stored.Env)
	}

	own := f.store.Jobs(false)[0]
	redactJob(&own, "alice", false)
	if own.Env[0] != "API_KEY=hunter2" {
		t.Errorf("the submitter cannot see its own environment: %q", own.Env)
	}
}
