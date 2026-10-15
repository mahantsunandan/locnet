package hub

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/mahantsunandan/locnet/internal/hubapi"
)

// The queue's HTTP surface. Every call is authenticated as a node, using the
// same signature the netmap poll and the report use — there is no new
// credential to distribute and no way to submit work as somebody else.

// queuePollTimeout is how long an idle worker's claim is held open. Long
// enough that an idle fleet is nearly silent, short enough that a worker
// notices the hub restarting.
const queuePollTimeout = 25 * time.Second

func (s *Server) handleQueueSubmit(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		hubapi.WriteError(w, http.StatusBadRequest, "%v", err)
		return
	}
	nodeID, ok := s.authenticate(w, r, body)
	if !ok {
		return
	}
	name, _, ok := s.store.QueueMember(nodeID)
	if !ok {
		notAMember(w)
		return
	}

	var j Job
	if err := json.Unmarshal(body, &j); err != nil {
		hubapi.WriteError(w, http.StatusBadRequest, "malformed job: %v", err)
		return
	}
	// The submitter is taken from the signature, never from the body: it is
	// what every worker's access list is checked against.
	j.Submitter = name

	out, err := s.store.Submit(&j)
	if err != nil {
		hubapi.WriteError(w, http.StatusBadRequest, "%v", err)
		return
	}
	s.logf("queue: %s submitted %s", name, out.ID)
	writeJSON(w, out)
}

// handleQueueClaim hands a worker its next job, holding the request open while
// there is nothing to do.
func (s *Server) handleQueueClaim(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		hubapi.WriteError(w, http.StatusBadRequest, "%v", err)
		return
	}
	nodeID, ok := s.authenticate(w, r, body)
	if !ok {
		return
	}
	s.store.Touch(nodeID)

	if j, ok := s.store.Claim(nodeID); ok {
		writeJSON(w, j)
		return
	}

	// Nothing now. Hold the request open rather than making every worker ask
	// again in a second — an idle fleet should cost nothing. A worker may ask
	// for a shorter wait, which is what one that is shutting down wants; it
	// may not ask for a longer one.
	var req struct {
		WaitSeconds int `json:"wait_seconds,omitempty"`
	}
	_ = json.Unmarshal(body, &req)
	wait := queuePollTimeout
	if req.WaitSeconds > 0 && time.Duration(req.WaitSeconds)*time.Second < wait {
		wait = time.Duration(req.WaitSeconds) * time.Second
	}

	s.store.WaitForQueueChange(wait, r.Context().Done())
	if j, ok := s.store.Claim(nodeID); ok {
		writeJSON(w, j)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleQueueResult(w http.ResponseWriter, r *http.Request) {
	// A result carries the job's output, which a worker caps at a few
	// megabytes — far over the limit that suits every other request. Read
	// with the small limit, a job that printed more than 64 KiB could never
	// report back: the body arrived truncated, failed to parse, the job sat
	// "running" until its lease ran out, and then ran again somewhere else.
	body, err := readBodyLimit(r, maxResultSize)
	if err != nil {
		hubapi.WriteError(w, http.StatusBadRequest, "%v", err)
		return
	}
	nodeID, ok := s.authenticate(w, r, body)
	if !ok {
		return
	}
	var res JobResult
	if err := json.Unmarshal(body, &res); err != nil {
		hubapi.WriteError(w, http.StatusBadRequest, "malformed result: %v", err)
		return
	}
	if err := s.store.Complete(nodeID, res); err != nil {
		hubapi.WriteError(w, http.StatusConflict, "%v", err)
		return
	}
	writeJSON(w, map[string]string{"id": res.ID})
}

func (s *Server) handleQueueList(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		hubapi.WriteError(w, http.StatusBadRequest, "%v", err)
		return
	}
	nodeID, ok := s.authenticate(w, r, body)
	if !ok {
		return
	}
	name, admin, ok := s.store.QueueMember(nodeID)
	if !ok {
		notAMember(w)
		return
	}
	var req struct {
		ID string `json:"id,omitempty"`
		// Brief asks for the listing without each job's output; without it,
		// the listing is whole.
		Brief bool `json:"brief,omitempty"`
	}
	_ = json.Unmarshal(body, &req)

	if req.ID != "" {
		j, ok := s.store.JobByID(req.ID)
		if !ok {
			hubapi.WriteError(w, http.StatusNotFound, "no job called %q", req.ID)
			return
		}
		if req.Brief {
			j.OutputBytes = len(j.Stdout) + len(j.Stderr)
			j.Stdout, j.Stderr = "", ""
		}
		redactJob(&j, name, admin)
		writeJSON(w, []Job{j})
		return
	}
	jobs := s.store.Jobs(req.Brief)
	for i := range jobs {
		redactJob(&jobs[i], name, admin)
	}
	writeJSON(w, jobs)
}

// redactJob hides what one machine has no business reading in another's job.
//
// The listing is shared on purpose — everyone on a fleet should be able to see
// why the queue is not moving — but a job's environment is where people put
// API keys, and its output is whatever the program printed. Those are for the
// machine that submitted the job, the machine that ran it, and
// administrators. Everyone else sees the variable names, with the values
// replaced, and how much output there was.
func redactJob(j *Job, viewer string, admin bool) {
	if admin || j.Submitter == viewer || (j.Node == viewer && j.Node != "") {
		return
	}
	// A new slice: the job is a copy, but its Env still shares an array with
	// the one the hub keeps, and the worker that claims it needs the values.
	env := make([]string, len(j.Env))
	for i, kv := range j.Env {
		k, _, _ := strings.Cut(kv, "=")
		env[i] = k + "=…"
	}
	j.Env = env
	if j.Stdout != "" || j.Stderr != "" {
		j.OutputBytes = len(j.Stdout) + len(j.Stderr)
		j.Stdout, j.Stderr = "", ""
	}
}

// notAMember refuses a machine that is registered but not admitted.
func notAMember(w http.ResponseWriter) {
	hubapi.WriteError(w, http.StatusForbidden,
		"this machine is waiting for an administrator to admit it. On an administrator machine: locnet admin approve <this machine>")
}

func (s *Server) handleQueueCancel(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		hubapi.WriteError(w, http.StatusBadRequest, "%v", err)
		return
	}
	nodeID, ok := s.authenticate(w, r, body)
	if !ok {
		return
	}
	name, admin, ok := s.store.QueueMember(nodeID)
	if !ok {
		notAMember(w)
		return
	}

	var req struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		hubapi.WriteError(w, http.StatusBadRequest, "malformed request: %v", err)
		return
	}
	if err := s.store.Cancel(name, admin, req.ID); err != nil {
		hubapi.WriteError(w, http.StatusBadRequest, "%v", err)
		return
	}
	writeJSON(w, map[string]string{"cancelled": req.ID})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
