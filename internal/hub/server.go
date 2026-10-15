package hub

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mahantsunandan/locnet/internal/hubapi"
	"github.com/mahantsunandan/locnet/internal/hubtls"
	"github.com/mahantsunandan/locnet/internal/joincode"
	"github.com/mahantsunandan/locnet/internal/policy"
	"github.com/mahantsunandan/locnet/internal/resource"
)

// pollTimeout is how long a netmap long poll is held open with nothing to
// report. Short enough to stay ahead of the idle timeouts middleboxes impose,
// long enough that a quiet network is nearly free.
const pollTimeout = 25 * time.Second

// maxBodySize caps request bodies. Every legitimate request here is well under
// a kilobyte, except a job result — see maxResultSize.
const maxBodySize = 64 << 10

// maxResultSize caps a queued job's result, which carries its output. Workers
// send at most resource.MaxOutputBytes of stdout and a quarter of that of
// stderr; this leaves room for JSON escaping on top.
const maxResultSize = 12 << 20

// Version is reported by GET /v1/info.
var Version = "0.1.0"

// Server is the hub's HTTP surface.
type Server struct {
	store *Store
	relay *Relay
	// advertiseAddrs are the host:port addresses nodes should be told to
	// contact, most specific first. Not necessarily what the hub is bound
	// to, and more than one because no single address reaches a hub behind
	// NAT from both inside and outside.
	advertiseAddrs []string
	logf           func(string, ...any)

	replay replayGuard
}

// NewServer builds the HTTP server. advertiseAddr is what goes into join
// codes and what nodes use to reach the relay.
func NewServer(store *Store, relay *Relay, advertiseAddrs []string, logf func(string, ...any)) *Server {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if len(advertiseAddrs) == 0 {
		advertiseAddrs = []string{""}
	}
	store.SetRelayAddrs(advertiseAddrs)
	store.SetHubAddrs(advertiseAddrs)
	return &Server{store: store, relay: relay, advertiseAddrs: advertiseAddrs, logf: logf}
}

// TLSListener wraps the API's TCP listener so that it serves TLS pinned to
// the hub's identity key; see package hubtls. Plain HTTP on the same port is
// answered only from this machine (see transportGate).
func (s *Server) TLSListener(ln net.Listener) (net.Listener, error) {
	cfg, err := hubtls.ServerConfig(s.store.HubKey())
	if err != nil {
		return nil, err
	}
	return hubtls.Listen(ln, cfg), nil
}

// SetStandbyAddrs publishes spare hubs to every node.
//
// They go into the netmap rather than only into new join codes, so a machine
// that joined a year ago learns where the spare is without anyone touching it.
// They are not added to the relay list: a standby relays nothing until it is
// promoted, and pointing traffic at it would only make packets disappear.
func (s *Server) SetStandbyAddrs(addrs []string) {
	all := append([]string(nil), s.advertiseAddrs...)
	for _, a := range addrs {
		if a != "" {
			all = append(all, a)
		}
	}
	s.store.SetHubAddrs(all)
}

// Handler returns the mux serving the whole API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("GET "+hubapi.APIVersion+"/info", s.handleInfo)
	mux.HandleFunc("POST "+hubapi.APIVersion+"/register", s.handleRegister)
	mux.HandleFunc("GET "+hubapi.APIVersion+"/netmap", s.handleNetMap)
	mux.HandleFunc("POST "+hubapi.APIVersion+"/report", s.handleReport)

	mux.HandleFunc("POST "+hubapi.APIVersion+"/admin/invite", s.admin(s.handleInvite))
	mux.HandleFunc("POST "+hubapi.APIVersion+"/admin/revoke", s.admin(s.handleRevoke))
	mux.HandleFunc("GET "+hubapi.APIVersion+"/admin/nodes", s.admin(s.handleAdminNodes))
	mux.HandleFunc("GET "+hubapi.APIVersion+"/admin/invites", s.admin(s.handleAdminInvites))
	mux.HandleFunc("POST "+hubapi.APIVersion+"/admin/remove", s.admin(s.handleAdminRemove))
	mux.HandleFunc("GET "+hubapi.APIVersion+"/admin/policy", s.admin(s.handleGetPolicy))
	mux.HandleFunc("POST "+hubapi.APIVersion+"/admin/policy", s.admin(s.handleSetPolicy))
	mux.HandleFunc("GET "+hubapi.APIVersion+"/admin/alerts", s.admin(s.handleAlerts))
	mux.HandleFunc("GET "+hubapi.APIVersion+"/admin/audit", s.admin(s.handleAudit))
	mux.HandleFunc("GET "+hubapi.APIVersion+"/admin/health", s.admin(s.handleGetHealth))
	mux.HandleFunc("POST "+hubapi.APIVersion+"/admin/health", s.admin(s.handleSetHealth))
	mux.HandleFunc("POST "+hubapi.APIVersion+"/admin/approve", s.admin(s.handleApprove))
	mux.HandleFunc("GET "+hubapi.APIVersion+"/admin/snapshot", s.admin(s.handleSnapshot))
	mux.HandleFunc("GET "+hubapi.APIVersion+"/admin/admins", s.admin(s.handleAdmins))
	mux.HandleFunc("POST "+hubapi.APIVersion+"/admin/admins", s.admin(s.handleAdmins))

	// The same powers, for a member machine the hub has made an
	// administrator, signed with that machine's own key. See manage.go.
	mux.HandleFunc("POST "+hubapi.APIVersion+"/manage/nodes", s.manage(s.handleManageNodes))
	mux.HandleFunc("POST "+hubapi.APIVersion+"/manage/invite", s.manage(s.handleManageInvite))
	mux.HandleFunc("POST "+hubapi.APIVersion+"/manage/invites", s.manage(s.handleManageInvites))
	mux.HandleFunc("POST "+hubapi.APIVersion+"/manage/revoke", s.manage(s.handleManageRevoke))
	mux.HandleFunc("POST "+hubapi.APIVersion+"/manage/remove", s.manage(s.handleManageRemove))
	mux.HandleFunc("POST "+hubapi.APIVersion+"/manage/approve", s.manage(s.handleManageApprove))
	mux.HandleFunc("POST "+hubapi.APIVersion+"/manage/audit", s.manage(s.handleManageAudit))
	mux.HandleFunc("POST "+hubapi.APIVersion+"/manage/access", s.manage(s.handleManageAccess))
	mux.HandleFunc("POST "+hubapi.APIVersion+"/manage/webshare", s.manage(s.handleManageWebShare))
	mux.HandleFunc("GET "+hubapi.APIVersion+"/admin/webshare", s.admin(s.handleAdminWebShare))
	mux.HandleFunc("POST "+hubapi.APIVersion+"/admin/webshare", s.admin(s.handleAdminWebShare))

	mux.HandleFunc("POST "+hubapi.APIVersion+"/queue/submit", s.handleQueueSubmit)
	mux.HandleFunc("POST "+hubapi.APIVersion+"/queue/claim", s.handleQueueClaim)
	mux.HandleFunc("POST "+hubapi.APIVersion+"/queue/result", s.handleQueueResult)
	mux.HandleFunc("POST "+hubapi.APIVersion+"/queue/list", s.handleQueueList)
	mux.HandleFunc("POST "+hubapi.APIVersion+"/queue/cancel", s.handleQueueCancel)
	return s.transportGate(mux)
}

// transportGate refuses plain HTTP from other machines.
//
// The control plane carries join codes, every machine's endpoints, queue jobs
// and their output, and — for a standby — the hub's signing key, so it crosses
// a network only inside TLS. Plain HTTP is still answered from this machine
// itself, which never leaves it and is what the hub's own admin commands use,
// and on /healthz, which carries nothing.
func (s *Server) transportGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil || r.URL.Path == "/healthz" || isLocalRequest(r) {
			next.ServeHTTP(w, r)
			return
		}
		hubapi.WriteError(w, http.StatusUpgradeRequired,
			"this hub is reached only over TLS pinned to its key, which locnetd does by itself; "+
				"to look by hand: curl -k https://<hub>:8420/healthz")
	})
}

// handleSnapshot hands a standby hub a copy of the whole register.
//
// Everything in it is already on the primary's disk; what makes this endpoint
// sensitive is that it puts the signing key on the wire. It is behind the
// admin token, it leaves this machine only inside TLS (transportGate), and the
// standby that reads it becomes as trusted as the hub itself — which is the
// trade a warm spare is.
func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	raw, err := s.store.Snapshot()
	if err != nil {
		hubapi.WriteError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	s.logf("hub: state snapshot taken by %s", r.RemoteAddr)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(raw)
}

// AdvertiseAddrs are the addresses this hub tells nodes to use.
func (s *Server) AdvertiseAddrs() []string { return s.advertiseAddrs }

// JoinCodeFor renders a pasteable join code for a token.
func (s *Server) JoinCodeFor(token string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(token)
	if err != nil || len(raw) != 16 {
		return "", fmt.Errorf("hub: join token is not 16 bytes")
	}
	c := joincode.Code{
		HubAddrs:       s.advertiseAddrs,
		HubFingerprint: s.store.HubKey().Public().Fingerprint(),
		Token:          [16]byte(raw),
	}
	return c.Encode()
}

func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	hubapi.WriteJSON(w, http.StatusOK, hubapi.HubInfo{
		HubKey:  s.store.HubKey().Public(),
		Version: Version,
		Relay:   s.advertiseAddrs[0],
	})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		hubapi.WriteError(w, http.StatusBadRequest, "%v", err)
		return
	}
	var req hubapi.RegisterRequest
	if err := json.Unmarshal(body, &req); err != nil {
		hubapi.WriteError(w, http.StatusBadRequest, "malformed request: %v", err)
		return
	}
	if req.MachineKey.IsZero() || req.WGKey.IsZero() || req.DiscoKey.IsZero() {
		hubapi.WriteError(w, http.StatusBadRequest, "registration is missing key material")
		return
	}

	n, err := s.store.Register(req.Token, &Node{
		Name:       req.Hostname,
		OS:         req.OS,
		MachineKey: req.MachineKey,
		WGKey:      req.WGKey,
		DiscoKey:   req.DiscoKey,
		// See isLocalAddr: a registration arriving from one of this
		// machine's own addresses is the node running alongside the hub.
		Hub: isLocalRequest(r),
	})
	if err != nil {
		// Deliberately a 403 rather than a 404: distinguishing "no such
		// token" from "token is spent" would let someone probe for valid
		// codes.
		s.logf("hub: registration refused from %s: %v", r.RemoteAddr, err)
		hubapi.WriteError(w, http.StatusForbidden, "%v", err)
		return
	}
	s.logf("hub: registered %s (%s) as %s", n.Name, n.OS, n.IP)

	signed, err := s.store.NetMapFor(n.ID)
	if err != nil {
		hubapi.WriteError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	hubapi.WriteJSON(w, http.StatusOK, hubapi.RegisterResponse{
		NodeID: n.ID,
		IP:     n.IP,
		Name:   n.Name,
		NetMap: signed,
	})
}

func (s *Server) handleNetMap(w http.ResponseWriter, r *http.Request) {
	nodeID, ok := s.authenticate(w, r, nil)
	if !ok {
		return
	}
	s.store.Touch(nodeID)
	s.store.SetHub(nodeID, isLocalRequest(r))

	since, _ := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
	if !s.store.WaitForChange(since, pollTimeout, r.Context().Done()) {
		hubapi.WriteJSON(w, http.StatusOK, hubapi.NetMapResponse{Changed: false})
		return
	}
	signed, err := s.store.NetMapFor(nodeID)
	if err != nil {
		hubapi.WriteError(w, http.StatusNotFound, "%v", err)
		return
	}
	hubapi.WriteJSON(w, http.StatusOK, hubapi.NetMapResponse{Changed: true, NetMap: signed})
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		hubapi.WriteError(w, http.StatusBadRequest, "%v", err)
		return
	}
	nodeID, ok := s.authenticate(w, r, body)
	if !ok {
		return
	}
	var req hubapi.ReportRequest
	if err := json.Unmarshal(body, &req); err != nil {
		hubapi.WriteError(w, http.StatusBadRequest, "malformed request: %v", err)
		return
	}

	// Prefer the address the relay actually saw over the one the node
	// claims: a node behind NAT cannot know its own public address, and a
	// hostile one should not get to choose what peers dial.
	observed := req.Observed
	if relayObserved, ok := s.relay.ObservedFor(nodeID); ok {
		observed = relayObserved
	}

	// Strip local paths. A node has no business telling the hub where a
	// shared folder lives on its disk, and the hub has no business
	// forwarding that to peers.
	shares := make([]resource.Share, 0, len(req.Shares))
	for _, sh := range req.Shares {
		if sh.Kind == resource.KindFiles {
			sh.Target = ""
		}
		shares = append(shares, sh)
	}

	err = s.store.Report(nodeID, Report{
		Local:    filterEndpoints(req.Local, s.store.Network().Prefix),
		Observed: observed,
		Services: req.Services,
		SSH:      req.SSH,
		Shares:   shares,
		Stats:    req.Stats,
		Compute:  req.Compute,
		LAN:      req.LAN,
		Desktop:  req.Desktop,
		Screen:   req.Screen,
	})
	if err != nil {
		hubapi.WriteError(w, http.StatusNotFound, "%v", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// authenticate verifies the request signature. body must be the exact bytes
// already read from the request, or nil for a request with no body.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request, body []byte) (string, bool) {
	nodeID, err := hubapi.VerifyRequest(r, body, s.store.MachineKey)
	if err != nil {
		s.logf("hub: rejected %s %s from %s: %v", r.Method, r.URL.Path, r.RemoteAddr, err)
		hubapi.WriteError(w, http.StatusUnauthorized, "%v", err)
		return "", false
	}
	if r.Method == http.MethodPost && !s.replay.first(r.Header.Get(hubapi.HeaderSignature)) {
		s.logf("hub: refused a replayed %s from %s (signed by %s)", r.URL.Path, r.RemoteAddr, nodeID)
		hubapi.WriteError(w, http.StatusConflict, "this exact request was already received; send it again")
		return "", false
	}
	return nodeID, true
}

// replayGuard remembers the signatures of requests that changed something,
// for as long as their timestamps would still be accepted.
//
// A signed request is good for five minutes either side of the hub's clock.
// TLS keeps it off the wire, but a request that changes something should
// still never count twice — a retried "remove" or "cancel", or a queue
// submission, sent again by anything that captured it. Agents put a nonce in
// every signed body, so a genuine repeat is never identical; a signature is
// accepted once.
type replayGuard struct {
	mu     sync.Mutex
	seen   map[string]time.Time
	pruned time.Time
}

// first reports whether sig has not been seen within the acceptance window,
// and records it.
func (g *replayGuard) first(sig string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if g.seen == nil {
		g.seen = map[string]time.Time{}
	}
	// A request is accepted up to MaxClockSkew either side of now, so it can
	// come back for twice that long.
	window := 2*hubapi.MaxClockSkew + time.Minute
	if now.Sub(g.pruned) > time.Minute {
		g.pruned = now
		for k, at := range g.seen {
			if now.Sub(at) > window {
				delete(g.seen, k)
			}
		}
	}
	if at, ok := g.seen[sig]; ok && now.Sub(at) <= window {
		return false
	}
	g.seen[sig] = now
	return true
}

// ------------------------------------------------------------------ admin

func (s *Server) admin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		want := s.store.AdminToken()
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			hubapi.WriteError(w, http.StatusUnauthorized, "admin token required")
			return
		}
		next(w, r)
	}
}

// InviteRequest asks the hub for a new join code.
type InviteRequest struct {
	Label string `json:"label"`
	Uses  int    `json:"uses"`
	TTL   string `json:"ttl"` // Go duration, empty for no expiry
}

// InviteResponse carries the generated code.
type InviteResponse struct {
	Code      string    `json:"code"`
	Token     string    `json:"token"`
	Label     string    `json:"label"`
	Uses      int       `json:"uses"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

func (s *Server) handleInvite(w http.ResponseWriter, r *http.Request) {
	var req InviteRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBodySize)).Decode(&req); err != nil && err != io.EOF {
		hubapi.WriteError(w, http.StatusBadRequest, "malformed request: %v", err)
		return
	}
	if req.Uses == 0 {
		req.Uses = 1
	}
	var ttl time.Duration
	if req.TTL != "" {
		d, err := time.ParseDuration(req.TTL)
		if err != nil {
			hubapi.WriteError(w, http.StatusBadRequest, "bad ttl %q: %v", req.TTL, err)
			return
		}
		ttl = d
	}

	t, err := s.store.CreateToken(req.Label, req.Uses, ttl)
	if err != nil {
		hubapi.WriteError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	code, err := s.JoinCodeFor(t.Token)
	if err != nil {
		hubapi.WriteError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	hubapi.WriteJSON(w, http.StatusOK, InviteResponse{
		Code:      code,
		Token:     t.Token,
		Label:     t.Label,
		Uses:      t.Uses,
		ExpiresAt: t.ExpiresAt,
	})
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBodySize)).Decode(&req); err != nil {
		hubapi.WriteError(w, http.StatusBadRequest, "malformed request: %v", err)
		return
	}
	if err := s.store.RevokeToken(req.Token); err != nil {
		hubapi.WriteError(w, http.StatusNotFound, "%v", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAdminNodes(w http.ResponseWriter, r *http.Request) {
	hubapi.WriteJSON(w, http.StatusOK, s.nodeRows())
}

func (s *Server) handleAdminInvites(w http.ResponseWriter, r *http.Request) {
	hubapi.WriteJSON(w, http.StatusOK, s.store.Tokens())
}

func (s *Server) handleAdminRemove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Node string `json:"node"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBodySize)).Decode(&req); err != nil {
		hubapi.WriteError(w, http.StatusBadRequest, "malformed request: %v", err)
		return
	}
	if err := s.store.RemoveNode(req.Node); err != nil {
		hubapi.WriteError(w, http.StatusNotFound, "%v", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	hubapi.WriteJSON(w, http.StatusOK, s.store.Policy())
}

func (s *Server) handleSetPolicy(w http.ResponseWriter, r *http.Request) {
	var p policy.Policy
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBodySize)).Decode(&p); err != nil {
		hubapi.WriteError(w, http.StatusBadRequest, "that is not a valid policy: %v", err)
		return
	}
	if err := s.store.SetPolicy(&p); err != nil {
		hubapi.WriteError(w, http.StatusBadRequest, "%v", err)
		return
	}
	s.logf("hub: policy updated (%d groups, %d rules)", len(p.Groups), len(p.Rules))
	hubapi.WriteJSON(w, http.StatusOK, s.store.Policy())
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	hubapi.WriteJSON(w, http.StatusOK, s.store.Alerts())
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	hubapi.WriteJSON(w, http.StatusOK, s.store.Audit(limit))
}

func (s *Server) handleGetHealth(w http.ResponseWriter, r *http.Request) {
	hubapi.WriteJSON(w, http.StatusOK, map[string]any{
		"rules":            s.store.HealthRules(),
		"require_approval": s.store.RequireApproval(),
	})
}

func (s *Server) handleSetHealth(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Rules           *HealthRules `json:"rules"`
		RequireApproval *bool        `json:"require_approval"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBodySize)).Decode(&req); err != nil {
		hubapi.WriteError(w, http.StatusBadRequest, "malformed request: %v", err)
		return
	}
	if req.Rules != nil {
		if err := s.store.SetHealthRules(*req.Rules); err != nil {
			hubapi.WriteError(w, http.StatusInternalServerError, "%v", err)
			return
		}
	}
	if req.RequireApproval != nil {
		if err := s.store.SetRequireApproval(*req.RequireApproval); err != nil {
			hubapi.WriteError(w, http.StatusInternalServerError, "%v", err)
			return
		}
	}
	s.handleGetHealth(w, r)
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Node string `json:"node"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBodySize)).Decode(&req); err != nil {
		hubapi.WriteError(w, http.StatusBadRequest, "malformed request: %v", err)
		return
	}
	if err := s.store.ApproveNode(req.Node); err != nil {
		hubapi.WriteError(w, http.StatusNotFound, "%v", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --------------------------------------------------------------- helpers

func readBody(r *http.Request) ([]byte, error) { return readBodyLimit(r, maxBodySize) }

// readBodyLimit reads at most limit bytes, and refuses a body that is longer
// rather than handing back a prefix of it. A truncated body fails its
// signature check or its JSON parse, and either of those reads like a bug in
// the sender rather than "too big".
func readBodyLimit(r *http.Request, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("reading body: %w", err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("request body is over the %d KiB limit", limit>>10)
	}
	return body, nil
}

// filterEndpoints drops addresses no peer could usefully dial. Loopback in
// particular would have every peer on the machine probing itself, and an
// address inside the overlay would have them trying to reach the tunnel
// through the tunnel.
func filterEndpoints(in []netip.AddrPort, overlay netip.Prefix) []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(in))
	for _, ap := range in {
		if !ap.IsValid() || ap.Port() == 0 {
			continue
		}
		ip := ap.Addr()
		if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
			continue
		}
		if overlay.IsValid() && overlay.Contains(ip) {
			continue
		}
		out = append(out, ap)
		if len(out) >= 8 {
			break
		}
	}
	return out
}
