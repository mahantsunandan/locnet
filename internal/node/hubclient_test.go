package node

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mahantsunandan/locnet/internal/key"
)

// TestNoContentIsNotAFailure covers the bug behind
// "queue: could not ask the hub for work: EOF", logged every forty seconds on
// an idle machine.
//
// 204 is how the hub says there is nothing for you: no queued job, no newer
// netmap. It carries no body by definition, so decoding one yields EOF — and
// that EOF travelled up as a hub failure, which made tryHubs walk to the next
// hub address looking for a better answer that does not exist. An idle fleet
// spent its time re-polling every hub and filling the log with an error that
// described normal operation.
func TestNoContentIsNotAFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	e := testEngine(t)

	var job struct {
		ID string `json:"id"`
	}
	if err := e.postJSON(context.Background(), srv.Listener.Addr().String(), "/queue/claim", map[string]string{}, &job, false); err != nil {
		t.Fatalf("an empty answer was reported as an error: %v", err)
	}
	if job.ID != "" {
		t.Errorf("decoded a job out of an empty body: %+v", job)
	}
}

// TestHubErrorsStillSurface: tolerating an empty 204 must not turn a real
// failure into silence.
func TestHubErrorsStillSurface(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"this machine is not a member"}`, http.StatusForbidden)
	}))
	defer srv.Close()

	e := testEngine(t)

	var out struct{}
	err := e.postJSON(context.Background(), srv.Listener.Addr().String(), "/queue/claim", map[string]string{}, &out, false)
	if err == nil {
		t.Fatal("a 403 from the hub was reported as success")
	}
	if !strings.Contains(err.Error(), "not a member") {
		t.Errorf("the hub's own explanation was lost: %v", err)
	}
}

// TestTruncatedAnswerIsStillAnError: an answer that promises content and then
// cuts off is a failure, and must not be confused with 204.
func TestTruncatedAnswerIsStillAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":`))
	}))
	defer srv.Close()

	e := testEngine(t)

	var job struct {
		ID string `json:"id"`
	}
	if err := e.postJSON(context.Background(), srv.Listener.Addr().String(), "/queue/claim", map[string]string{}, &job, false); err == nil {
		t.Fatal("a truncated body was accepted")
	}
}

func testEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := NewEngine(t.TempDir(), t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

// TestJoinedAgentNeverSpeaksPlainHTTP: once a machine has a hub fingerprint,
// a bare hub address is TLS pinned to it and nothing else. A server answering
// in plain HTTP there — something in the way, pretending to be the hub —
// receives nothing, and the error says why.
func TestJoinedAgentNeverSpeaksPlainHTTP(t *testing.T) {
	var got atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Add(1)
	}))
	defer srv.Close()

	_, hubPub, err := key.NewMachine()
	if err != nil {
		t.Fatal(err)
	}
	e := testEngine(t)
	addr := srv.Listener.Addr().String()
	e.mu.Lock()
	e.st.SetHubs([]string{addr})
	e.st.SetFingerprint(hubPub.Fingerprint())
	e.st.NodeID = "n1"
	e.mu.Unlock()

	_, err = e.pollOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "without TLS") {
		t.Fatalf("poll against a plain-HTTP server: %v", err)
	}
	if n := got.Load(); n != 0 {
		t.Errorf("the plain-HTTP server received %d requests", n)
	}
}
