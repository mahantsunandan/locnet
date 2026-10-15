package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mahantsunandan/locnet/internal/hubapi"
	"github.com/mahantsunandan/locnet/internal/placement"
	"github.com/mahantsunandan/locnet/internal/resource"
)

// post sends a signed request to the hub as this node, the way locnetd does.
func (n *testNode) post(t *testing.T, path string, in, out any) int {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	raw = hubapi.WithNonce(raw) // as every agent does
	url := "http://" + n.hub.addr + hubapi.APIVersion + path
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	hubapi.SignRequest(req, n.id, n.machine, raw)

	resp, err := (&http.Client{Timeout: 40 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("%s: POST %s: %v", n.name, path, err)
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
	}
	return resp.StatusCode
}

// TestQueueOverTheWire runs a job from submission to result over the real HTTP
// API, with the real request signing.
//
// The store's own tests cover the scheduling decisions. This one covers the
// things only the wire can get wrong: that the submitter is taken from the
// signature rather than the body, that a worker's claim and result are
// authenticated as that worker, and that the whole round trip round-trips.
func TestQueueOverTheWire(t *testing.T) {
	h := startHub(t)
	alice := registerNode(t, h, "workstation")
	worker := registerNode(t, h, "lab-1")
	outsider := registerNode(t, h, "laptop")

	worker.report(t, hubapi.ReportRequest{
		Stats: resource.Stats{CPUs: 16, MemFreeMB: 32000, DiskFreeGB: 400},
		Compute: resource.ComputeConfig{
			Enabled: true, Allow: []string{"workstation"}, RunAs: "builder",
		},
	})

	// A job that claims to come from somebody else. The hub must ignore the
	// claim: the submitter is whoever signed the request.
	var job hubapi.Job
	if code := alice.post(t, "/queue/submit", hubapi.Job{
		Submitter: "someone-else",
		Command:   []string{"make", "-j16"},
		Need:      placement.Need{CPUs: 8},
	}, &job); code != http.StatusOK {
		t.Fatalf("submit returned %d", code)
	}
	if job.Submitter != "workstation" {
		t.Errorf("submitter is %q; it must come from the signature, not the body", job.Submitter)
	}
	if job.ID == "" || job.State != hubapi.JobQueued {
		t.Fatalf("submitted job is %+v", job)
	}

	// A machine the worker's access list does not name gets nothing, even
	// though it is a member of the network and asking politely.
	var nothing hubapi.Job
	if code := outsider.post(t, "/queue/claim", map[string]int{"wait_seconds": 1}, &nothing); code != http.StatusNoContent {
		t.Errorf("a machine with no compute offer got %d from claim, wanted 204", code)
	}

	var claimed hubapi.Job
	if code := worker.post(t, "/queue/claim", map[string]string{}, &claimed); code != http.StatusOK {
		t.Fatalf("claim returned %d", code)
	}
	if claimed.ID != job.ID || claimed.Node != "lab-1" {
		t.Fatalf("claimed %+v", claimed)
	}
	if len(claimed.Command) != 2 || claimed.Command[0] != "make" {
		t.Errorf("the command did not survive the trip: %v", claimed.Command)
	}

	// A result signed by a machine that does not hold the job is refused.
	if code := outsider.post(t, "/queue/result", hubapi.JobResult{
		ID: job.ID, ExitCode: 0, Stdout: "not mine",
	}, nil); code == http.StatusOK {
		t.Error("a result from a machine that never claimed the job was accepted")
	}

	if code := worker.post(t, "/queue/result", hubapi.JobResult{
		ID: job.ID, ExitCode: 0, Stdout: "built\n", Seconds: 3.5,
	}, nil); code != http.StatusOK {
		t.Fatalf("result returned %d", code)
	}

	var list []hubapi.Job
	if code := alice.post(t, "/queue/list", map[string]string{"id": job.ID}, &list); code != http.StatusOK {
		t.Fatalf("list returned %d", code)
	}
	if len(list) != 1 {
		t.Fatalf("list returned %d jobs", len(list))
	}
	if list[0].State != hubapi.JobDone || list[0].Stdout != "built\n" {
		t.Errorf("finished job is %+v", list[0])
	}
}

// TestQueueClaimIsAuthenticated is the control the whole queue rests on: an
// unsigned request must not be able to take work, because taking work means
// being handed a command somebody expects to be run.
func TestQueueClaimIsAuthenticated(t *testing.T) {
	h := startHub(t)
	url := "http://" + h.addr + hubapi.APIVersion + "/queue/claim"

	resp, err := http.Post(url, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("an unsigned claim returned %s, wanted 401", resp.Status)
	}
}
