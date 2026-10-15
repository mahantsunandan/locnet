package hub

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/mahantsunandan/locnet/internal/hubapi"
	"github.com/mahantsunandan/locnet/internal/resource"
)

// WebShare: publishing one HTTPS service on a member machine to the internet,
// through the hub — LocNet's counterpart to Tailscale Funnel.
//
// Three parties must agree before anything is public, and each can withdraw:
//
//   - the machine asks, with a port share carrying a Web name
//     (`locnet webshare add`), which only someone at that machine can create;
//   - an administrator approves that name for that machine on the hub;
//   - the access policy lets the hub machine reach the share's port.
//
// The hub then answers https://<name>.<domain>, with a certificate it gets
// from Let's Encrypt itself, and passes each request through the tunnel to
// that one port and nothing else (webshare_server.go).

// WebShareConfig is the hub's side of it. The DuckDNS token is a secret: it
// lives in the state file, which only the hub user can read, and is never
// sent to a node or shown by the API.
type WebShareConfig struct {
	// Domain is what sites hang off, e.g. "yourname.duckdns.org". Empty
	// means WebShare is off: nothing listens on 80 or 443.
	Domain string `json:"domain,omitempty"`
	// AcceptedTOS records that the operator agreed to Let's Encrypt's
	// subscriber agreement, which getting a certificate requires.
	AcceptedTOS bool   `json:"accepted_tos,omitempty"`
	Email       string `json:"email,omitempty"`
	// DuckDNSToken keeps Domain pointing at this house.
	DuckDNSToken string `json:"duckdns_token,omitempty"`

	// Sites are the approved names, each tied to one machine.
	Sites map[string]*SiteGrant `json:"sites,omitempty"`
}

// SiteGrant is an administrator's approval of one name for one machine.
type SiteGrant struct {
	NodeID     string    `json:"node_id"`
	Enabled    bool      `json:"enabled"`
	ApprovedBy string    `json:"approved_by"`
	ApprovedAt time.Time `json:"approved_at"`
}

// Site states, as shown to administrators and to the machine.
const (
	SiteLive     = "live"
	SiteWaiting  = "waiting for approval"
	SiteOff      = "turned off on the hub"
	SiteTaken    = "name taken by another machine"
	SiteOffline  = "machine offline"
	SiteNoDomain = "no domain set on the hub"
	SiteBlocked  = "the access policy keeps the hub machine out of its port"
	SiteNoHub    = "the hub machine is not a member of the network"
	SiteGone     = "approved, but the machine no longer offers it"
)

// Site is one name, as an administrator sees it.
type Site struct {
	Name    string `json:"name"`
	URL     string `json:"url,omitempty"`
	Machine string `json:"machine"`
	NodeID  string `json:"node_id"`
	Share   string `json:"share,omitempty"`
	Target  string `json:"target,omitempty"` // the service on that machine
	Port    uint16 `json:"port,omitempty"`   // its overlay port
	State   string `json:"state"`
	Live    bool   `json:"live"`
	// Requests and LastError come from the proxy, since the hub started.
	Requests  uint64 `json:"requests,omitempty"`
	LastError string `json:"last_error,omitempty"`
}

// WebShareView is everything an administrator is shown. The token is not.
type WebShareView struct {
	Domain      string    `json:"domain,omitempty"`
	AcceptedTOS bool      `json:"accepted_tos"`
	DuckDNS     bool      `json:"duckdns"`
	DNS         DNSStatus `json:"dns"`
	Sites       []Site    `json:"sites"`
}

// DNSStatus is the dynamic DNS updater's last result.
type DNSStatus struct {
	At    time.Time `json:"at,omitzero"`
	IP    string    `json:"ip,omitempty"`
	Error string    `json:"error,omitempty"`
}

// siteRoute is where the proxy sends one host name.
type siteRoute struct {
	name string
	addr netip.AddrPort
}

// webShareLocked is the config, never nil. Callers must hold s.mu.
func (s *Store) webShareLocked() *WebShareConfig {
	if s.st.WebShare == nil {
		s.st.WebShare = &WebShareConfig{}
	}
	if s.st.WebShare.Sites == nil {
		s.st.WebShare.Sites = map[string]*SiteGrant{}
	}
	return s.st.WebShare
}

// hubNodeLocked is the member running on the hub machine — the one the proxy
// connects from. Callers must hold s.mu.
func (s *Store) hubNodeLocked() *Node {
	for _, n := range s.st.Nodes {
		if n.Hub {
			return n
		}
	}
	return nil
}

// sitesLocked works out every site's state: every name a machine asks for,
// plus approved names nobody offers any more. Callers must hold s.mu.
func (s *Store) sitesLocked() []Site {
	cfg := s.webShareLocked()
	hubNode := s.hubNodeLocked()
	names := allNames(s.st.Nodes)
	pol := s.policyLocked()
	now := time.Now()

	var out []Site
	seen := map[string]bool{} // name + node
	for _, n := range s.st.Nodes {
		for _, sh := range n.Shares {
			if sh.Web == "" {
				continue
			}
			site := Site{Name: sh.Web, Machine: n.Name, NodeID: n.ID, Share: sh.Name,
				Target: sh.Target, Port: sh.Port}
			if cfg.Domain != "" {
				site.URL = "https://" + sh.Web + "." + cfg.Domain
			}
			grant := cfg.Sites[sh.Web]
			switch {
			case grant == nil:
				site.State = SiteWaiting
			case grant.NodeID != n.ID:
				site.State = SiteTaken
			case !grant.Enabled:
				site.State = SiteOff
			case cfg.Domain == "":
				site.State = SiteNoDomain
			case now.Sub(n.LastSeen) >= onlineWindow:
				site.State = SiteOffline
			case hubNode == nil:
				site.State = SiteNoHub
			default:
				if hubNode.ID != n.ID {
					if ok, _ := pol.CanReach(hubNode.Name, n.Name, sh.Port, names); !ok {
						site.State = SiteBlocked
						break
					}
				}
				site.State, site.Live = SiteLive, true
			}
			seen[sh.Web+"\x00"+n.ID] = true
			out = append(out, site)
		}
	}
	for name, g := range cfg.Sites {
		if seen[name+"\x00"+g.NodeID] {
			continue
		}
		machine := g.NodeID
		if n, ok := s.st.Nodes[g.NodeID]; ok {
			machine = n.Name
		}
		out = append(out, Site{Name: name, Machine: machine, NodeID: g.NodeID, State: SiteGone})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Machine < out[j].Machine
	})
	return out
}

// WebShare returns the administrator's view.
func (s *Store) WebShare() WebShareView {
	s.mu.Lock()
	cfg := s.webShareLocked()
	v := WebShareView{
		Domain: cfg.Domain, AcceptedTOS: cfg.AcceptedTOS, DuckDNS: cfg.DuckDNSToken != "",
		DNS: s.dnsStatus, Sites: s.sitesLocked(),
	}
	stats := s.siteStats
	s.mu.Unlock()
	// Outside the lock: the proxy takes its own lock while it holds none of
	// the store's, and the two must never nest the other way round.
	if stats != nil {
		for i := range v.Sites {
			v.Sites[i].Requests, v.Sites[i].LastError = stats(v.Sites[i].Name)
		}
	}
	return v
}

func (s *Store) setSiteStats(f func(string) (uint64, string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.siteStats = f
}

// siteRouteFor is where a request for host goes, if anywhere: a live site's
// machine, at the overlay port of its share.
func (s *Store) siteRouteFor(host string) (siteRoute, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg := s.webShareLocked()
	if cfg.Domain == "" {
		return siteRoute{}, false
	}
	name, ok := strings.CutSuffix(strings.ToLower(host), "."+cfg.Domain)
	if !ok || name == "" || strings.Contains(name, ".") {
		return siteRoute{}, false
	}
	for _, site := range s.sitesLocked() {
		if site.Name == name && site.Live {
			n := s.st.Nodes[site.NodeID]
			return siteRoute{name: name, addr: netip.AddrPortFrom(n.IP, site.Port)}, true
		}
	}
	return siteRoute{}, false
}

// siteStatusesFor is the Sites entry of one node's own netmap.
func (s *Store) siteStatusesForLocked(nodeID string) []resource.SiteStatus {
	var out []resource.SiteStatus
	for _, site := range s.sitesLocked() {
		if site.NodeID == nodeID && site.State != SiteGone {
			out = append(out, resource.SiteStatus{Name: site.Name, URL: site.URL, State: site.State, Live: site.Live})
		}
	}
	return out
}

// SetWebShareDomain turns WebShare on (or off, with an empty domain). Only the
// hub's own admin token reaches this: it carries a secret and an agreement to
// someone else's terms, which are the operator's to give.
func (s *Store) SetWebShareDomain(domain, duckToken, email string, acceptTOS bool) error {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain != "" {
		if !acceptTOS {
			return fmt.Errorf("WebShare needs certificates from Let's Encrypt, which needs agreement to their " +
				"subscriber agreement (https://letsencrypt.org/repository/). Pass -accept-tos to agree")
		}
		if strings.Count(domain, ".") < 1 || strings.ContainsAny(domain, " /:") {
			return fmt.Errorf("%q is not a domain name", domain)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg := s.webShareLocked()
	cfg.Domain, cfg.AcceptedTOS, cfg.Email = domain, acceptTOS && domain != "", email
	if duckToken != "" {
		cfg.DuckDNSToken = duckToken
	}
	if domain == "" {
		cfg.DuckDNSToken = ""
		s.auditLocked("admin", "webshare.off", "")
	} else {
		s.auditLocked("admin", "webshare.domain", domain)
	}
	s.bump()
	return s.save()
}

// ChangeSite approves, turns off, turns back on or forgets one site name.
func (s *Store) ChangeSite(actor, action, name, machine string) (WebShareView, error) {
	s.mu.Lock()
	cfg := s.webShareLocked()
	err := func() error {
		switch action {
		case "approve":
			var requesters []*Node
			for _, n := range s.st.Nodes {
				for _, sh := range n.Shares {
					if sh.Web == name && (machine == "" || n.Name == machine) {
						requesters = append(requesters, n)
						break
					}
				}
			}
			switch len(requesters) {
			case 0:
				return fmt.Errorf("no machine is asking for %q. On the machine: locnet webshare add %s <port>", name, name)
			case 1:
			default:
				var ms []string
				for _, n := range requesters {
					ms = append(ms, n.Name)
				}
				sort.Strings(ms)
				return fmt.Errorf("%d machines ask for %q (%s); name the one to approve", len(ms), name, strings.Join(ms, ", "))
			}
			cfg.Sites[name] = &SiteGrant{NodeID: requesters[0].ID, Enabled: true, ApprovedBy: actor, ApprovedAt: time.Now()}
			s.auditLocked(actor, "webshare.approve", fmt.Sprintf("%s on %s", name, requesters[0].Name))
		case "off", "on":
			g := cfg.Sites[name]
			if g == nil {
				return fmt.Errorf("%q has not been approved", name)
			}
			g.Enabled = action == "on"
			s.auditLocked(actor, "webshare."+action, name)
		case "remove":
			if cfg.Sites[name] == nil {
				return fmt.Errorf("%q has not been approved", name)
			}
			delete(cfg.Sites, name)
			s.auditLocked(actor, "webshare.remove", name)
		default:
			return fmt.Errorf("unknown action %q: approve, off, on or remove", action)
		}
		s.bump()
		return s.save()
	}()
	s.mu.Unlock()
	if err != nil {
		return WebShareView{}, err
	}
	return s.WebShare(), nil
}

// setDNSStatus records the updater's result for the admin view.
func (s *Store) setDNSStatus(st DNSStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dnsStatus = st
}

// duckDNS returns what the updater needs.
func (s *Store) duckDNS() (domain, token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg := s.webShareLocked()
	return cfg.Domain, cfg.DuckDNSToken
}

// acmeConfig returns what the certificate manager needs.
func (s *Store) acmeConfig() (domain, email string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg := s.webShareLocked()
	return cfg.Domain, cfg.Email, cfg.Domain != "" && cfg.AcceptedTOS
}

// SiteChange is a request about WebShare, from the CLI or the console.
type SiteChange struct {
	// Action is approve, off, on or remove — or, with the hub's own admin
	// token only, domain.
	Action  string `json:"action"`
	Name    string `json:"name,omitempty"`
	Machine string `json:"machine,omitempty"`

	// For "domain".
	Domain       string `json:"domain,omitempty"`
	DuckDNSToken string `json:"duckdns_token,omitempty"`
	Email        string `json:"email,omitempty"`
	AcceptTOS    bool   `json:"accept_tos,omitempty"`
}

// handleManageWebShare is the administrator's view and site controls, signed
// by an administrator machine. The domain and the DNS token are not on offer
// here: they are set on the hub machine, by whoever holds it.
func (s *Server) handleManageWebShare(w http.ResponseWriter, r *http.Request, actor string, body []byte) {
	var req SiteChange
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			hubapi.WriteError(w, http.StatusBadRequest, "malformed request: %v", err)
			return
		}
	}
	if req.Action == "domain" {
		hubapi.WriteError(w, http.StatusForbidden,
			"the domain and DNS token are set on the hub machine: sudo locnet-hub webshare domain <name> -accept-tos")
		return
	}
	s.webShareAction(w, actor, req)
}

// handleAdminWebShare is the same with the hub's admin token, which may also
// set the domain.
func (s *Server) handleAdminWebShare(w http.ResponseWriter, r *http.Request) {
	var req SiteChange
	if r.Method == http.MethodPost {
		if err := json.NewDecoder(io.LimitReader(r.Body, maxBodySize)).Decode(&req); err != nil {
			hubapi.WriteError(w, http.StatusBadRequest, "malformed request: %v", err)
			return
		}
	}
	if req.Action == "domain" {
		if err := s.store.SetWebShareDomain(req.Domain, req.DuckDNSToken, req.Email, req.AcceptTOS); err != nil {
			hubapi.WriteError(w, http.StatusBadRequest, "%v", err)
			return
		}
		hubapi.WriteJSON(w, http.StatusOK, s.store.WebShare())
		return
	}
	s.webShareAction(w, "admin", req)
}

func (s *Server) webShareAction(w http.ResponseWriter, actor string, req SiteChange) {
	if req.Action == "" {
		hubapi.WriteJSON(w, http.StatusOK, s.store.WebShare())
		return
	}
	view, err := s.store.ChangeSite(actor, req.Action, req.Name, req.Machine)
	if err != nil {
		hubapi.WriteError(w, http.StatusBadRequest, "%v", err)
		return
	}
	s.logf("hub: webshare %s %s by %s", req.Action, req.Name, actor)
	hubapi.WriteJSON(w, http.StatusOK, view)
}
