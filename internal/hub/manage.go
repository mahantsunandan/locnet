package hub

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/mahantsunandan/locnet/internal/hubapi"
)

// Managing the network from a member machine.
//
// The admin API is guarded by a token that lives in the hub's state file, on
// the hub machine, readable by root. That is the right default and a poor
// everyday tool: the machine somebody actually sits at is rarely the hub, and
// "ssh to the hub, sudo, run a command" is three steps between a person and a
// join code for their new laptop.
//
// So a node can be made an administrator, and then sign management requests
// with its own identity key — the same signature every node already puts on
// its netmap polls. Nothing new to distribute, nothing to leak: the authority
// is the machine key, which never leaves the machine, and it can be withdrawn
// from the hub at any time. The node running on the hub machine is an
// administrator without being listed, since whoever controls that machine
// already holds the token.

// isAdminLocked reports whether n may administer the network. Callers must
// hold s.mu.
func (s *Store) isAdminLocked(n *Node) bool {
	return n.Hub || slices.Contains(s.st.Admins, n.ID)
}

// IsAdmin reports whether the node with this ID may administer the network.
func (s *Store) IsAdmin(nodeID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.st.Nodes[nodeID]
	return ok && s.isAdminLocked(n)
}

// AdminNames lists the machines that may administer the network, the hub's
// own included, sorted.
func (s *Store) AdminNames() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, n := range s.st.Nodes {
		if s.isAdminLocked(n) {
			out = append(out, n.Name)
		}
	}
	sort.Strings(out)
	return out
}

// SetAdmin grants or withdraws the right to administer the network.
func (s *Store) SetAdmin(actor, idOrName string, on bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var target *Node
	for id, n := range s.st.Nodes {
		if id == idOrName || n.Name == idOrName {
			target = n
			break
		}
	}
	if target == nil {
		return fmt.Errorf("hub: no node called %q", idOrName)
	}
	has := slices.Contains(s.st.Admins, target.ID)
	switch {
	case on && has, !on && !has:
		if !on && target.Hub {
			return fmt.Errorf("hub: %s runs the hub, and is an administrator because of that, not because it is listed", target.Name)
		}
		return nil
	case on:
		s.st.Admins = append(s.st.Admins, target.ID)
		s.auditLocked(actor, "admin.grant", target.Name)
	default:
		s.st.Admins = slices.DeleteFunc(s.st.Admins, func(a string) bool { return a == target.ID })
		s.auditLocked(actor, "admin.revoke", target.Name)
	}
	// The flag travels in the machine's own network map, which is how its
	// console learns to show the controls.
	s.bump()
	return s.save()
}

// NodeRow is one machine as an administrator sees it.
type NodeRow struct {
	Node
	Online bool     `json:"online"`
	Groups []string `json:"groups,omitempty"`
	Relay  string   `json:"relay_addr,omitempty"`
	Admin  bool     `json:"admin,omitempty"`
}

// nodeRows builds the administrator's view of every machine.
func (s *Server) nodeRows() []NodeRow {
	nodes := s.store.Nodes()
	pol := s.store.Policy()
	admins := map[string]bool{}
	for _, name := range s.store.AdminNames() {
		admins[name] = true
	}
	out := make([]NodeRow, 0, len(nodes))
	for _, n := range nodes {
		row := NodeRow{
			Node:   n,
			Online: time.Since(n.LastSeen) < onlineWindow,
			Groups: pol.GroupsFor(n.Name),
			Admin:  admins[n.Name],
		}
		if relayAddr, ok := s.relay.ObservedFor(n.ID); ok {
			row.Relay = relayAddr.String()
		}
		out = append(out, row)
	}
	return out
}

// ------------------------------------------------------------------ HTTP

// manage authenticates a node-signed management request and checks that the
// node is an administrator. The handler gets the caller's name, for the audit
// log, and the request body it signed.
func (s *Server) manage(next func(w http.ResponseWriter, r *http.Request, actor string, body []byte)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := readBody(r)
		if err != nil {
			hubapi.WriteError(w, http.StatusBadRequest, "%v", err)
			return
		}
		nodeID, ok := s.authenticate(w, r, body)
		if !ok {
			return
		}
		name, _ := s.store.NodeName(nodeID)
		if !s.store.IsAdmin(nodeID) {
			s.logf("hub: %s asked to %s but is not an administrator", name, r.URL.Path)
			hubapi.WriteError(w, http.StatusForbidden,
				"%s is not allowed to administer this network. On the hub machine: sudo locnet-hub admins add %s", name, name)
			return
		}
		next(w, r, name, body)
	}
}

func (s *Server) handleManageNodes(w http.ResponseWriter, r *http.Request, actor string, body []byte) {
	hubapi.WriteJSON(w, http.StatusOK, s.nodeRows())
}

func (s *Server) handleManageInvite(w http.ResponseWriter, r *http.Request, actor string, body []byte) {
	var req InviteRequest
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			hubapi.WriteError(w, http.StatusBadRequest, "malformed request: %v", err)
			return
		}
	}
	if req.Uses == 0 {
		req.Uses = 1
	}
	var ttl time.Duration
	if req.TTL != "" {
		d, err := time.ParseDuration(req.TTL)
		if err != nil || d < 0 {
			hubapi.WriteError(w, http.StatusBadRequest, "bad ttl %q — use something like 24h or 30m", req.TTL)
			return
		}
		ttl = d
	}
	if req.Label == "" {
		req.Label = "from " + actor
	}
	t, err := s.store.CreateTokenAs(actor, req.Label, req.Uses, ttl)
	if err != nil {
		hubapi.WriteError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	code, err := s.JoinCodeFor(t.Token)
	if err != nil {
		hubapi.WriteError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	s.logf("hub: %s minted a join code (%q)", actor, t.Label)
	hubapi.WriteJSON(w, http.StatusOK, InviteResponse{
		Code: code, Token: t.Token, Label: t.Label, Uses: t.Uses, ExpiresAt: t.ExpiresAt,
	})
}

// InviteRow is a join code as an administrator sees it: enough to recognise and
// revoke it, and nothing that would let it be used.
type InviteRow struct {
	ID        string    `json:"id"`
	Label     string    `json:"label"`
	Uses      int       `json:"uses"`
	Active    bool      `json:"active"`
	Why       string    `json:"why,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
}

func (s *Server) handleManageInvites(w http.ResponseWriter, r *http.Request, actor string, body []byte) {
	now := time.Now()
	tokens := s.store.Tokens()
	out := make([]InviteRow, 0, len(tokens))
	for _, t := range tokens {
		row := InviteRow{
			// Eight characters is what `locnet-hub revoke` takes, and too few
			// to redeem: the code itself is never sent back out.
			ID: t.Token[:8], Label: t.Label, Uses: t.Uses,
			CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, Active: true,
		}
		if err := t.Valid(now); err != nil {
			row.Active, row.Why = false, err.Error()
		}
		out = append(out, row)
	}
	hubapi.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) handleManageRevoke(w http.ResponseWriter, r *http.Request, actor string, body []byte) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &req); err != nil || len(req.ID) < 4 {
		hubapi.WriteError(w, http.StatusBadRequest, "which join code?")
		return
	}
	if err := s.store.RevokeTokenAs(actor, req.ID); err != nil {
		hubapi.WriteError(w, http.StatusNotFound, "%v", err)
		return
	}
	hubapi.WriteJSON(w, http.StatusOK, map[string]string{"revoked": req.ID})
}

// nodeRequest is the body of every request that names one machine.
type nodeRequest struct {
	Node string `json:"node"`
}

func (s *Server) handleManageRemove(w http.ResponseWriter, r *http.Request, actor string, body []byte) {
	var req nodeRequest
	if err := json.Unmarshal(body, &req); err != nil || req.Node == "" {
		hubapi.WriteError(w, http.StatusBadRequest, "which machine?")
		return
	}
	// A machine removing itself would lose the network in the middle of the
	// request and have no way back except a new join code. That is what
	// `locnet leave` plus an administrator elsewhere is for.
	if req.Node == actor {
		hubapi.WriteError(w, http.StatusBadRequest,
			"%s cannot remove itself — run `locnet leave` there, and remove it from another administrator", actor)
		return
	}
	if err := s.store.RemoveNodeAs(actor, req.Node); err != nil {
		hubapi.WriteError(w, http.StatusNotFound, "%v", err)
		return
	}
	s.logf("hub: %s removed %s", actor, req.Node)
	hubapi.WriteJSON(w, http.StatusOK, map[string]string{"removed": req.Node})
}

func (s *Server) handleManageApprove(w http.ResponseWriter, r *http.Request, actor string, body []byte) {
	var req nodeRequest
	if err := json.Unmarshal(body, &req); err != nil || req.Node == "" {
		hubapi.WriteError(w, http.StatusBadRequest, "which machine?")
		return
	}
	if err := s.store.ApproveNodeAs(actor, req.Node); err != nil {
		hubapi.WriteError(w, http.StatusNotFound, "%v", err)
		return
	}
	hubapi.WriteJSON(w, http.StatusOK, map[string]string{"approved": req.Node})
}

func (s *Server) handleManageAudit(w http.ResponseWriter, r *http.Request, actor string, body []byte) {
	var req struct {
		Limit int `json:"limit"`
	}
	_ = json.Unmarshal(body, &req)
	if req.Limit <= 0 || req.Limit > 200 {
		req.Limit = 50
	}
	hubapi.WriteJSON(w, http.StatusOK, s.store.Audit(req.Limit))
}

// ------------------------------------------------- token-guarded admin side

// handleAdmins lists administrators (GET) or grants and withdraws (POST),
// behind the admin token: only someone on the hub machine can hand out the
// right to administer it from elsewhere.
func (s *Server) handleAdmins(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var req struct {
			Node   string `json:"node"`
			Remove bool   `json:"remove"`
		}
		body, err := readBody(r)
		if err == nil {
			err = json.Unmarshal(body, &req)
		}
		if err != nil || req.Node == "" {
			hubapi.WriteError(w, http.StatusBadRequest, "which machine?")
			return
		}
		if err := s.store.SetAdmin("admin", req.Node, !req.Remove); err != nil {
			hubapi.WriteError(w, http.StatusBadRequest, "%v", err)
			return
		}
	}
	hubapi.WriteJSON(w, http.StatusOK, s.store.AdminNames())
}

// handleManageAccess shows who may connect to whom, and with an action in the
// body changes one pair: {"action":"block","src":"winpc-01","dst":"hubpc",
// "services":["ssh"]}. Either way the answer is the whole matrix afterwards.
func (s *Server) handleManageAccess(w http.ResponseWriter, r *http.Request, actor string, body []byte) {
	var req AccessChange
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			hubapi.WriteError(w, http.StatusBadRequest, "malformed request: %v", err)
			return
		}
	}
	if req.Action == "" {
		hubapi.WriteJSON(w, http.StatusOK, s.store.AccessView())
		return
	}
	view, err := s.store.ChangeAccess(actor, req)
	if err != nil {
		hubapi.WriteError(w, http.StatusBadRequest, "%v", err)
		return
	}
	s.logf("hub: %s %sed %s → %s (%s)", actor, req.Action, req.Src, req.Dst, strings.Join(req.Services, ","))
	hubapi.WriteJSON(w, http.StatusOK, view)
}
