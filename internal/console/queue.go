package console

import (
	"encoding/json"
	"net/http"

	"github.com/mahantsunandan/locnet/internal/hubapi"
)

// The console's view of the queue is a pass-through to the daemon, which is
// the thing holding this machine's identity key — every queue call is signed
// with it. Nothing is decided here.

func (s *Server) handleQueue(w http.ResponseWriter, r *http.Request) {
	// Brief: the listing is polled every few seconds while it is open, and
	// the output of every finished job is most of its weight. The output of
	// one job is fetched when somebody asks to see it.
	var jobs []hubapi.Job
	if err := s.daemon.Post("/queue/list", map[string]any{"brief": true}, &jobs); err != nil {
		writeErr(w, http.StatusBadGateway, "%v", err)
		return
	}
	writeJSON(w, jobs)
}

func (s *Server) handleQueueSubmit(w http.ResponseWriter, r *http.Request) {
	var job hubapi.Job
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&job); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed job")
		return
	}
	if len(job.Command) == 0 {
		writeErr(w, http.StatusBadRequest, "there is no command to run")
		return
	}
	var out hubapi.Job
	if err := s.daemon.Post("/queue/submit", job, &out); err != nil {
		writeErr(w, http.StatusBadGateway, "%v", err)
		return
	}
	writeJSON(w, out)
}

func (s *Server) handleQueueCancel(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		writeErr(w, http.StatusBadRequest, "which job?")
		return
	}
	if err := s.daemon.Post("/queue/cancel", req, nil); err != nil {
		writeErr(w, http.StatusBadGateway, "%v", err)
		return
	}
	writeJSON(w, map[string]string{"cancelled": req.ID})
}
