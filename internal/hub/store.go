// Package hub is the coordination server: the one always-on machine that
// knows which nodes belong to a network, hands out addresses, and relays
// packets for pairs that cannot reach each other directly.
//
// It is deliberately not a gateway. Tunnel traffic between two nodes is
// encrypted end to end by WireGuard with keys the hub never sees, so a
// compromised hub can disrupt a network — by refusing service, or by adding a
// node — but it cannot read what flows across one.
package hub

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mahantsunandan/locnet/internal/key"
	"github.com/mahantsunandan/locnet/internal/netmap"
	"github.com/mahantsunandan/locnet/internal/policy"
	"github.com/mahantsunandan/locnet/internal/resource"
)

// DefaultPrefix is the overlay address range.
//
// The obvious choice would be carrier-grade NAT space (100.64.0.0/10), which
// exists for exactly this and never appears on a real LAN. Tailscale claims
// all of it, and a machine running both would eventually hand the same address
// to two different networks — a failure that produces no error, just traffic
// quietly going to the wrong interface.
//
// So: 10.99.0.0/16. Private, and picked to miss the ranges that container
// runtimes grab by default — Docker's 172.17, Podman's 10.88, k3s's 10.42.
// Override with -prefix on first run if it still clashes with your LAN.
const DefaultPrefix = "10.99.0.0/16"

// DefaultDomain is the MagicDNS-style suffix appended to node names.
const DefaultDomain = "locnet.private"

// DefaultMTU leaves room for WireGuard's own overhead plus a relay header
// inside a 1500-byte path, without relying on path MTU discovery working.
const DefaultMTU = 1280

// JoinToken is a credential that lets a machine register itself.
type JoinToken struct {
	Token     string    `json:"token"` // base64 of 16 random bytes
	Label     string    `json:"label"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	// Uses remaining. -1 means unlimited, which is what you want for a
	// reusable key baked into an unattended installer.
	Uses    int  `json:"uses"`
	Revoked bool `json:"revoked"`
}

// Valid reports whether the token may still be redeemed, and why not if it
// cannot.
func (t *JoinToken) Valid(now time.Time) error {
	switch {
	case t.Revoked:
		return fmt.Errorf("this join code was revoked")
	case t.Uses == 0:
		return fmt.Errorf("this join code has already been used the maximum number of times")
	case !t.ExpiresAt.IsZero() && now.After(t.ExpiresAt):
		return fmt.Errorf("this join code expired on %s", t.ExpiresAt.Format(time.RFC3339))
	}
	return nil
}

// Node is the hub's record of one machine.
type Node struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	OS         string            `json:"os"`
	MachineKey key.MachinePublic `json:"machine_key"`
	WGKey      key.WGPublic      `json:"wg_key"`
	DiscoKey   key.DiscoPublic   `json:"disco_key"`
	IP         netip.Addr        `json:"ip"`

	LocalEndpoints []netip.AddrPort `json:"local_endpoints,omitempty"`
	Observed       netip.AddrPort   `json:"observed,omitempty"`

	Services []resource.Service     `json:"services,omitempty"`
	SSH      resource.SSHKeys       `json:"ssh,omitzero"`
	Shares   []resource.Share       `json:"shares,omitempty"`
	LAN      []resource.LANIface    `json:"lan,omitempty"`
	Stats    resource.Stats         `json:"stats,omitzero"`
	Compute  resource.ComputeConfig `json:"compute,omitzero"`
	Desktop  resource.DesktopConfig `json:"desktop,omitzero"`

	// Screen is live state rather than configuration: whether a desktop
	// session is open on that machine right now. It is deliberately not
	// persisted — a hub restarting must not tell everyone that a machine
	// has a logged-in user because it did an hour ago.
	Screen resource.DesktopStatus `json:"-"`

	// Approved matters only when the network requires approval. An
	// unapproved node holds an address and can talk to the hub, but appears
	// in nobody's network map — so it has joined the register without
	// joining the network.
	// Hub is true when this node registered from the hub machine itself.
	Hub bool `json:"hub,omitempty"`

	Approved   bool      `json:"approved"`
	ApprovedAt time.Time `json:"approved_at,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
}

// onlineWindow is how long after its last contact a node is still shown as
// online. A node polls at least every pollTimeout, so this is roughly two
// missed polls.
const onlineWindow = 90 * time.Second

// State is everything the hub persists.
type State struct {
	// HubKey is the identity this hub signs with. Its fingerprint is what
	// join codes pin, so regenerating it invalidates every existing code
	// and every node's trust.
	HubKey     key.MachinePrivate    `json:"hub_key"`
	AdminToken string                `json:"admin_token"`
	Network    netmap.Network        `json:"network"`
	Nodes      map[string]*Node      `json:"nodes"`
	Tokens     map[string]*JoinToken `json:"tokens"`

	// Policy decides which machines may reach which.
	Policy *policy.Policy `json:"policy,omitempty"`
	// Health holds the alert thresholds.
	Health HealthRules `json:"health"`
	// RequireApproval makes a newly joined machine invisible to the network
	// until an administrator approves it. Off by default: it is the right
	// setting for an organisation and the wrong one for a person with three
	// computers.
	RequireApproval bool `json:"require_approval"`

	Audit []AuditEntry `json:"audit,omitempty"`

	// Admins are the IDs of nodes allowed to administer the network with
	// their own signature — mint join codes, admit and remove machines —
	// rather than with the admin token, which lives only on the hub machine.
	// The node running on the hub machine is always one, and need not be
	// listed.
	Admins []string `json:"admins,omitempty"`

	// WebShare publishes approved sites on member machines to the internet.
	WebShare *WebShareConfig `json:"webshare,omitempty"`

	// Queue is the work waiting for a machine to run it, and the recent
	// history of work that has. It is persisted so that a hub restart does
	// not lose a night's batch.
	Queue []*Job `json:"queue,omitempty"`

	// Version increments on every change a node would care about.
	Version uint64 `json:"version"`
}

// Store is the persistent state plus the change notification nodes long-poll
// on.
type Store struct {
	path string

	mu sync.Mutex
	st *State
	// relayAddrs are where nodes should send relayed traffic, most specific
	// first. Not persisted: they come from the -advertise flag every time
	// the hub starts, so moving a hub needs no state surgery.
	relayAddrs []string
	// hubAddrs are the control-plane addresses handed to nodes so they know
	// where to look when the one they were using stops answering.
	hubAddrs []string
	// hubTLS is whether the control plane is served over pinned TLS. Not
	// persisted, for the same reason.
	hubTLS bool
	// changed is closed and replaced whenever Version increases. A waiter
	// grabs the current channel under the lock, releases it, and blocks —
	// so there is no window where a change can be missed.
	changed chan struct{}
	// queueChanged is the same trick for the job queue, kept separate so
	// that a busy queue does not re-sign a network map for every machine
	// every time a job starts.
	queueChanged chan struct{}
	// online is each node's online state as of the last liveness check, so
	// the check can tell a transition from a steady state. Not persisted.
	online map[string]bool
	// dnsStatus is the WebShare DNS updater's last result. Not persisted.
	dnsStatus DNSStatus
	// siteStats reports the proxy's counters for one site, when a
	// WebServer is running. Not persisted.
	siteStats func(name string) (uint64, string)

	logf func(string, ...any)
}

// SetLogger installs the logger used for audit lines.
func (s *Store) SetLogger(logf func(string, ...any)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logf = logf
}

var nameSanitiser = regexp.MustCompile(`[^a-z0-9-]+`)

// Open loads the store at path, creating and initialising it if absent.
func Open(path, networkName, prefix string) (*Store, error) {
	s := &Store{path: path, changed: make(chan struct{}), queueChanged: make(chan struct{})}

	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		var st State
		if err := json.Unmarshal(raw, &st); err != nil {
			return nil, fmt.Errorf("hub: %s is not valid state: %w", path, err)
		}
		if st.Nodes == nil {
			st.Nodes = map[string]*Node{}
		}
		if st.Tokens == nil {
			st.Tokens = map[string]*JoinToken{}
		}
		// A state file written before policies existed has none. Give it the
		// permissive default rather than locking the operator out of their
		// own network on upgrade.
		if st.Policy == nil {
			st.Policy = policy.Default()
		}
		if st.Health.OfflineAfter == 0 {
			st.Health = DefaultHealthRules()
		}
		s.st = &st
		return s, nil
	case !os.IsNotExist(err):
		return nil, fmt.Errorf("hub: read %s: %w", path, err)
	}

	st, err := newState(networkName, prefix)
	if err != nil {
		return nil, err
	}
	s.st = st
	if err := s.save(); err != nil {
		return nil, err
	}
	return s, nil
}

func newState(networkName, prefix string) (*State, error) {
	if networkName == "" {
		networkName = "locnet"
	}
	if prefix == "" {
		prefix = DefaultPrefix
	}
	p, err := netip.ParsePrefix(prefix)
	if err != nil {
		return nil, fmt.Errorf("hub: bad prefix %q: %w", prefix, err)
	}
	if !p.Addr().Is4() {
		return nil, fmt.Errorf("hub: prefix must be IPv4 for now, got %s", prefix)
	}
	priv, _, err := key.NewMachine()
	if err != nil {
		return nil, err
	}
	admin, err := randomToken()
	if err != nil {
		return nil, err
	}
	return &State{
		HubKey:     priv,
		AdminToken: admin,
		Network: netmap.Network{
			ID:     strings.ToLower(nameSanitiser.ReplaceAllString(strings.ToLower(networkName), "-")),
			Name:   networkName,
			Prefix: p.Masked(),
			Domain: DefaultDomain,
			MTU:    DefaultMTU,
		},
		Nodes:   map[string]*Node{},
		Tokens:  map[string]*JoinToken{},
		Policy:  policy.Default(),
		Health:  DefaultHealthRules(),
		Version: 1,
	}, nil
}

func randomToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b[:]), nil
}

// save writes state atomically. A half-written state file would cost the
// operator every node registration, so the temp-and-rename is not optional.
// Callers must hold s.mu.
func (s *Store) save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// bump increases the version and wakes every long poll. Callers must hold
// s.mu.
func (s *Store) bump() {
	s.st.Version++
	close(s.changed)
	s.changed = make(chan struct{})
}

// HubKey returns the hub's signing key.
func (s *Store) HubKey() key.MachinePrivate {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.HubKey
}

// AdminToken returns the bearer token for the admin API.
func (s *Store) AdminToken() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.AdminToken
}

// Network returns the network configuration.
func (s *Store) Network() netmap.Network {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.Network
}

// SetRelayAddrs sets the relay addresses handed to nodes in every netmap.
// Changing them bumps the version so nodes pick it up without waiting.
func (s *Store) SetRelayAddrs(addrs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.Join(s.relayAddrs, ",") == strings.Join(addrs, ",") {
		return
	}
	s.relayAddrs = append(s.relayAddrs[:0], addrs...)
	s.bump()
}

// SetHubAddrs sets the control-plane addresses every node is told about.
//
// These are not the same list as the relay addresses even though they usually
// hold the same strings: a standby hub is somewhere a node should look for the
// network map, and is not somewhere to send relayed packets, because it is not
// relaying anything until it is promoted.
func (s *Store) SetHubAddrs(addrs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.Join(s.hubAddrs, ",") == strings.Join(addrs, ",") {
		return
	}
	s.hubAddrs = append(s.hubAddrs[:0], addrs...)
	s.bump()
}

// SetHubTLS records that the control plane is served over pinned TLS, which
// every netmap then says. See Server.TLSListener.
func (s *Store) SetHubTLS(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hubTLS == on {
		return
	}
	s.hubTLS = on
	s.bump()
}

// HubTLS reports whether the control plane is served over pinned TLS.
func (s *Store) HubTLS() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hubTLS
}

// Version returns the current netmap version.
func (s *Store) Version() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.Version
}

// MachineKey resolves a node ID to its identity key, for request verification.
func (s *Store) MachineKey(nodeID string) (key.MachinePublic, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.st.Nodes[nodeID]
	if !ok {
		return key.MachinePublic{}, false
	}
	return n.MachineKey, true
}

// NodeName resolves a node ID to the name every access list is written in
// terms of.
func (s *Store) NodeName(nodeID string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.st.Nodes[nodeID]
	if !ok {
		return "", false
	}
	return n.Name, true
}

// QueueMember resolves a node for the job queue: its name, whether it may
// administer the network, and whether it takes part in the network at all.
//
// A machine waiting for approval is registered — it holds a node ID and signs
// its requests — but approval promises it "reaches nothing until admitted".
// The queue used to check only registration, so a waiting machine could read
// every job's command, environment and output, cancel anybody's work, and, by
// allowing "*" in its own compute setting, be handed other people's jobs and
// report invented results for them.
func (s *Store) QueueMember(nodeID string) (name string, admin, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, found := s.st.Nodes[nodeID]
	if !found || !s.visibleLocked(n) {
		return "", false, false
	}
	return n.Name, s.isAdminLocked(n), true
}

// NodeByWGKey resolves a WireGuard key to a node, which is what the relay
// needs to check a bind signature.
func (s *Store) NodeByWGKey(k key.WGPublic) (*Node, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, n := range s.st.Nodes {
		if n.WGKey == k {
			cp := *n
			return &cp, true
		}
	}
	return nil, false
}

// Nodes returns a copy of every node, sorted by name.
func (s *Store) Nodes() []Node {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nodesLocked()
}

func (s *Store) nodesLocked() []Node {
	out := make([]Node, 0, len(s.st.Nodes))
	for _, n := range s.st.Nodes {
		out = append(out, *n)
	}
	sortNodes(out)
	return out
}

// Tokens returns a copy of every join token, newest first.
func (s *Store) Tokens() []JoinToken {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]JoinToken, 0, len(s.st.Tokens))
	for _, t := range s.st.Tokens {
		out = append(out, *t)
	}
	sortTokens(out)
	return out
}

// CreateToken mints a join token. uses of -1 means unlimited; ttl of 0 means
// no expiry.
func (s *Store) CreateToken(label string, uses int, ttl time.Duration) (*JoinToken, error) {
	return s.CreateTokenAs("admin", label, uses, ttl)
}

// CreateTokenAs is CreateToken, recording who asked for it in the audit log.
func (s *Store) CreateTokenAs(actor, label string, uses int, ttl time.Duration) (*JoinToken, error) {
	tok, err := randomToken()
	if err != nil {
		return nil, err
	}
	t := &JoinToken{
		Token:     tok,
		Label:     label,
		CreatedAt: time.Now(),
		Uses:      uses,
	}
	if ttl > 0 {
		t.ExpiresAt = t.CreatedAt.Add(ttl)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Tokens[tok] = t
	s.auditLocked(actor, "token.create", fmt.Sprintf("%q, %s use(s)", label, usesDescription(uses)))
	if err := s.save(); err != nil {
		return nil, err
	}
	cp := *t
	return &cp, nil
}

// RevokeToken marks a token unusable. Machines that already joined with it
// stay joined; revoking a code is not the same as removing a node.
func (s *Store) RevokeToken(prefix string) error { return s.RevokeTokenAs("admin", prefix) }

// RevokeTokenAs is RevokeToken, recording who asked for it.
func (s *Store) RevokeTokenAs(actor, prefix string) error {
	if strings.TrimSpace(prefix) == "" {
		return fmt.Errorf("hub: which join code?")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var found *JoinToken
	for tok, t := range s.st.Tokens {
		if strings.HasPrefix(tok, prefix) {
			if found != nil {
				return fmt.Errorf("hub: %q matches more than one join code", prefix)
			}
			found = t
		}
	}
	if found == nil {
		return fmt.Errorf("hub: no join code matches %q", prefix)
	}
	found.Revoked = true
	s.auditLocked(actor, "token.revoke", fmt.Sprintf("%q", found.Label))
	return s.save()
}

// Register redeems a join token and creates or updates a node.
//
// A machine that re-registers with the same identity key keeps its address.
// That is what makes reinstalling locnetd on an existing machine harmless, and
// it is safe because the identity key is the thing being authenticated.
func (s *Store) Register(token string, n *Node) (*Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.st.Tokens[token]
	if !ok {
		return nil, fmt.Errorf("unrecognised join code")
	}
	if err := t.Valid(time.Now()); err != nil {
		return nil, err
	}

	for _, existing := range s.st.Nodes {
		if existing.MachineKey.IsZero() || n.MachineKey.IsZero() {
			continue
		}
		if string(existing.MachineKey.Bytes()) == string(n.MachineKey.Bytes()) {
			existing.WGKey = n.WGKey
			existing.DiscoKey = n.DiscoKey
			existing.OS = n.OS
			existing.Hub = n.Hub
			existing.LastSeen = time.Now()
			s.bump()
			if err := s.save(); err != nil {
				return nil, err
			}
			cp := *existing
			return &cp, nil
		}
	}

	ip, err := s.allocIPLocked()
	if err != nil {
		return nil, err
	}
	n.ID = "n-" + strings.ToLower(strings.ReplaceAll(base64.RawURLEncoding.EncodeToString(n.MachineKey.Bytes()[:8]), "-", "_"))
	n.Name = s.allocNameLocked(n.Name)
	n.IP = ip
	n.CreatedAt = time.Now()
	n.LastSeen = n.CreatedAt
	n.Approved = !s.st.RequireApproval
	if n.Approved {
		n.ApprovedAt = n.CreatedAt
	}
	s.st.Nodes[n.ID] = n

	if t.Uses > 0 {
		t.Uses--
	}
	detail := fmt.Sprintf("%s (%s) as %s", n.Name, n.OS, n.IP)
	if !n.Approved {
		detail += " — awaiting approval"
	}
	s.auditLocked(n.Name, "node.join", detail)
	s.bump()
	if err := s.save(); err != nil {
		return nil, err
	}
	cp := *n
	return &cp, nil
}

// RemoveNode deletes a node by ID or name.
func (s *Store) RemoveNode(idOrName string) error { return s.RemoveNodeAs("admin", idOrName) }

// RemoveNodeAs is RemoveNode, recording who asked for it.
func (s *Store) RemoveNodeAs(actor, idOrName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, n := range s.st.Nodes {
		if id == idOrName || n.Name == idOrName {
			delete(s.st.Nodes, id)
			// A removed machine is no longer anybody's administrator, and its
			// name may be taken by the next machine to join.
			s.st.Admins = slices.DeleteFunc(s.st.Admins, func(a string) bool { return a == id })
			s.auditLocked(actor, "node.remove", fmt.Sprintf("%s (%s)", n.Name, n.IP))
			s.bump()
			return s.save()
		}
	}
	return fmt.Errorf("hub: no node called %q", idOrName)
}

// Report records a node's periodic account of itself.
//
// It only bumps the netmap version when something a peer would act on has
// changed. That filter is what keeps a large fleet quiet: without it, every
// node reporting its load every thirty seconds would wake every long poll in
// the network, forever, for nothing.
func (s *Store) Report(nodeID string, r Report) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.st.Nodes[nodeID]
	if !ok {
		return fmt.Errorf("hub: unknown node %q", nodeID)
	}
	n.LastSeen = time.Now()

	changed := !sameAddrPorts(n.LocalEndpoints, r.Local) ||
		n.Observed != r.Observed ||
		!sameServices(n.Services, r.Services) ||
		!sameShares(n.Shares, r.Shares) ||
		n.Compute.Enabled != r.Compute.Enabled ||
		n.Compute.AllowText() != r.Compute.AllowText() ||
		n.Desktop.Enabled != r.Desktop.Enabled ||
		n.Desktop.Control != r.Desktop.Control ||
		n.Desktop.AllowText() != r.Desktop.AllowText() ||
		n.Screen != r.Screen ||
		statsMovedMaterially(n.Stats, r.Stats)

	n.LocalEndpoints = r.Local
	n.Observed = r.Observed
	n.Services = r.Services
	n.SSH = r.SSH
	n.Shares = r.Shares
	n.Stats = r.Stats
	n.LAN = r.LAN
	n.Compute = r.Compute
	n.Desktop = r.Desktop
	n.Screen = r.Screen

	if !changed {
		return nil
	}
	s.bump()
	return s.save()
}

// Report is what a node tells the hub about itself.
type Report struct {
	Local    []netip.AddrPort
	Observed netip.AddrPort
	Services []resource.Service
	SSH      resource.SSHKeys
	Shares   []resource.Share
	Stats    resource.Stats
	LAN      []resource.LANIface
	Compute  resource.ComputeConfig
	Desktop  resource.DesktopConfig
	Screen   resource.DesktopStatus
}

// Touch records that a node made contact, without changing the netmap.
func (s *Store) Touch(nodeID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n, ok := s.st.Nodes[nodeID]; ok {
		n.LastSeen = time.Now()
	}
}

// livenessInterval is how often the hub looks for machines that have crossed
// the online/offline line. Small against onlineWindow, so a machine that goes
// away is shown as gone within about a minute and a half.
const livenessInterval = 10 * time.Second

// WatchLiveness re-issues the network map whenever a machine goes offline or
// comes back, until done is closed.
//
// Whether a peer is online is worked out when a map is signed, and a map is
// only signed when something changes. A machine that simply stops talking
// changes nothing — so without this, everyone else went on being told it was
// online for as long as the rest of the network stayed quiet, which on a small
// network of idle machines could be hours.
func (s *Store) WatchLiveness(done <-chan struct{}) {
	t := time.NewTicker(livenessInterval)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			s.checkLiveness(time.Now())
		}
	}
}

// checkLiveness bumps the version if any machine's online state differs from
// what the current maps say.
func (s *Store) checkLiveness(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.online == nil {
		s.online = make(map[string]bool, len(s.st.Nodes))
	}
	changed := false
	for id, n := range s.st.Nodes {
		on := now.Sub(n.LastSeen) < onlineWindow
		if was, known := s.online[id]; !known || was != on {
			// A machine seen for the first time is not news: the maps
			// already describe it correctly, having been signed just now
			// or at startup.
			if known {
				changed = true
				if s.logf != nil {
					s.logf("hub: %s is now %s", n.Name, onlineWord(on))
				}
			}
			s.online[id] = on
		}
	}
	for id := range s.online {
		if _, ok := s.st.Nodes[id]; !ok {
			delete(s.online, id)
		}
	}
	if changed {
		s.bump()
		_ = s.save()
	}
}

func onlineWord(on bool) string {
	if on {
		return "online"
	}
	return "offline"
}

// NetMapFor builds and signs the network map from one node's point of view.
//
// This is where the access policy is enforced, and it is enforced by omission:
// a machine the policy does not permit this node to reach is simply not in the
// map. No entry means no WireGuard peer, no key exchange, and no path — the
// isolation is a property of the cryptography rather than of a check somewhere
// that could be skipped. It also means a node cannot enumerate machines it has
// no business knowing about.
func (s *Store) NetMapFor(nodeID string) (*netmap.Signed, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	self, ok := s.st.Nodes[nodeID]
	if !ok {
		return nil, fmt.Errorf("hub: unknown node %q", nodeID)
	}

	pol := s.st.Policy
	if pol == nil {
		pol = policy.Default()
	}
	all := make([]string, 0, len(s.st.Nodes))
	for _, n := range s.st.Nodes {
		if s.visibleLocked(n) {
			all = append(all, n.Name)
		}
	}
	sort.Strings(all)
	reachable := pol.Reachable(self.Name, all)

	network := s.st.Network
	network.Health = s.st.Health
	network.Hubs = append([]string(nil), s.hubAddrs...)
	network.HubTLS = s.hubTLS

	m := &netmap.NetMap{
		Version:  s.st.Version,
		IssuedAt: time.Now(),
		Network:  network,
		Self:     toNetmapNode(self, self.Name, true),
	}
	m.Self.Groups = pol.GroupsFor(self.Name)
	m.Self.Sites = s.siteStatusesForLocked(nodeID)
	m.Self.Admin = s.isAdminLocked(self)

	for id, n := range s.st.Nodes {
		if id == nodeID || !s.visibleLocked(n) || !reachable[n.Name] {
			continue
		}
		peer := toNetmapNode(n, self.Name, false)
		peer.Groups = pol.GroupsFor(n.Name)
		// Resolve what this peer may reach on us, so the agent's packet
		// filter needs no policy engine of its own.
		if ranges, all := pol.InboundPorts(n.Name, self.Name, allNames(s.st.Nodes)); !all {
			if len(ranges) == 0 {
				// The peer is in this map only because a rule lets *us*
				// reach *it*; it may reach nothing here. An empty list
				// reads as "every port" to the agent, so a one-way rule
				// used to open the reverse direction completely. Port 0
				// is never a connection's destination, so this range
				// grants nothing — and agents from before the fix
				// enforce it too.
				ranges = []policy.PortRange{policy.NoPorts}
			}
			peer.InboundPorts = ranges
		}
		m.Peers = append(m.Peers, peer)
	}
	sortNetmapNodes(m.Peers)

	for i, a := range s.relayAddrs {
		if a == "" {
			continue
		}
		m.Relays = append(m.Relays, netmap.Relay{
			ID:   fmt.Sprintf("hub-%d", i),
			Addr: stripScheme(a),
		})
	}
	return netmap.Sign(m, s.st.HubKey)
}

// visibleLocked reports whether a node participates in the network at all.
// Callers must hold s.mu.
func (s *Store) visibleLocked(n *Node) bool {
	return n.Approved || !s.st.RequireApproval
}

func allNames(nodes map[string]*Node) []string {
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.Name)
	}
	sort.Strings(out)
	return out
}

// Policy returns the current access policy.
func (s *Store) Policy() *policy.Policy {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.policyLocked().Clone()
}

// policyLocked is the policy in force, the default when none was set. Callers
// must hold s.mu and must not modify it.
func (s *Store) policyLocked() *policy.Policy {
	if s.st.Policy == nil {
		return policy.Default()
	}
	return s.st.Policy
}

// SetPolicy replaces the access policy.
//
// It refuses a policy that would cut every machine off from every other,
// because that is almost never what someone meant and it locks the operator
// out of the network they are administering.
func (s *Store) SetPolicy(p *policy.Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.setPolicyLocked(p, "admin", "policy.set",
		fmt.Sprintf("%d group(s), %d rule(s), %d block(s)", len(p.Groups), len(p.Rules), len(p.Blocks)))
}

// setPolicyLocked checks and installs a policy. Callers must hold s.mu.
func (s *Store) setPolicyLocked(p *policy.Policy, actor, action, detail string) error {
	if err := p.Validate(); err != nil {
		return err
	}
	names := allNames(s.st.Nodes)
	if len(names) > 1 {
		anyPair := false
		for _, a := range names {
			if len(p.Reachable(a, names)) > 0 {
				anyPair = true
				break
			}
		}
		if !anyPair {
			return fmt.Errorf("this policy would isolate every machine from every other — check the group and machine names against `locnet-hub nodes`")
		}
	}

	s.st.Policy = p
	s.auditLocked(actor, action, detail)
	s.bump()
	return s.save()
}

// AccessChange switches one kind of connection between two machines on or off.
type AccessChange struct {
	Action string `json:"action"` // "allow" or "block"
	Src    string `json:"src"`
	Dst    string `json:"dst"`
	// Services are names (ssh, vnc, rdp, smb, locnet), "all", or ports.
	// None means all.
	Services []string `json:"services,omitempty"`
}

// AccessView is the policy resolved into every pair of machines.
func (s *Store) AccessView() policy.AccessView {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.policyLocked().View(allNames(s.st.Nodes))
}

// ChangeAccess applies one allow or block, as actor, and returns the result.
//
// It goes through the same checks as a whole policy: the change is made on a
// copy, validated, refused if it would isolate everything, and only then
// installed — and it is in the audit log under the machine that asked.
func (s *Store) ChangeAccess(actor string, c AccessChange) (policy.AccessView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	names := allNames(s.st.Nodes)
	known := func(ref string) bool {
		if ref == policy.Wildcard || slices.Contains(names, ref) {
			return true
		}
		_, isGroup := s.policyLocked().Groups[ref]
		return isGroup
	}
	for _, ref := range []string{c.Src, c.Dst} {
		if !known(ref) {
			return policy.AccessView{}, fmt.Errorf("no machine or group called %q (machines: %s)", ref, strings.Join(names, ", "))
		}
	}
	if c.Src == c.Dst {
		return policy.AccessView{}, fmt.Errorf("a machine can always reach itself")
	}
	ports, err := policy.ParseServices(c.Services)
	if err != nil {
		return policy.AccessView{}, err
	}

	next := s.policyLocked().Clone()
	note := fmt.Sprintf("set by %s on %s", actor, time.Now().Format("2006-01-02"))
	switch c.Action {
	case "allow":
		if err := next.Allow(c.Src, c.Dst, ports, note, names); err != nil {
			return policy.AccessView{}, err
		}
	case "block":
		next.Block(c.Src, c.Dst, ports, note)
	default:
		return policy.AccessView{}, fmt.Errorf("unknown action %q: allow or block", c.Action)
	}

	detail := fmt.Sprintf("%s → %s: %s", c.Src, c.Dst, policy.DescribePorts(ports))
	if err := s.setPolicyLocked(next, actor, "access."+c.Action, detail); err != nil {
		return policy.AccessView{}, err
	}
	return next.View(names), nil
}

// SetRequireApproval turns the approval workflow on or off. Turning it on
// leaves existing machines approved: it governs what happens next, not a
// retroactive audit of what already joined.
func (s *Store) SetRequireApproval(on bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.RequireApproval == on {
		return nil
	}
	s.st.RequireApproval = on
	if on {
		for _, n := range s.st.Nodes {
			if n.ApprovedAt.IsZero() {
				n.Approved = true
				n.ApprovedAt = time.Now()
			}
		}
	}
	s.auditLocked("admin", "approval.set", fmt.Sprintf("required=%v", on))
	s.bump()
	return s.save()
}

// RequireApproval reports whether new machines need approving.
func (s *Store) RequireApproval() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.RequireApproval
}

// ApproveNode admits a waiting machine to the network.
func (s *Store) ApproveNode(idOrName string) error { return s.ApproveNodeAs("admin", idOrName) }

// ApproveNodeAs is ApproveNode, recording who asked for it.
func (s *Store) ApproveNodeAs(actor, idOrName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, n := range s.st.Nodes {
		if id != idOrName && n.Name != idOrName {
			continue
		}
		if n.Approved {
			return fmt.Errorf("hub: %s is already approved", n.Name)
		}
		n.Approved = true
		n.ApprovedAt = time.Now()
		s.auditLocked(actor, "node.approve", fmt.Sprintf("%s (%s)", n.Name, n.IP))
		s.bump()
		return s.save()
	}
	return fmt.Errorf("hub: no node called %q", idOrName)
}

// WaitForChange blocks until the version exceeds since, the timeout elapses,
// or done is closed. It reports whether there is something new.
//
// A node asking about a version *newer* than this hub's is answered at once.
// That happens after a restart: a bump that was never saved is lost, the hub
// comes back counting from an older number, and a node holding a map from the
// previous run would otherwise sit in its long poll until the new run happened
// to count past it — receiving nothing, however much changed, in the meantime.
func (s *Store) WaitForChange(since uint64, timeout time.Duration, done <-chan struct{}) bool {
	s.mu.Lock()
	if s.st.Version != since {
		s.mu.Unlock()
		return true
	}
	ch := s.changed
	s.mu.Unlock()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ch:
		return true
	case <-timer.C:
		return false
	case <-done:
		return false
	}
}

// toNetmapNode renders a node as one viewer sees it. Shares are filtered to
// what that viewer may actually use, except in a node's own Self entry, where
// it sees everything it offers.
func toNetmapNode(n *Node, viewer string, isSelf bool) netmap.Node {
	eps := append([]netip.AddrPort(nil), n.LocalEndpoints...)
	if n.Observed.IsValid() {
		eps = append(eps, n.Observed)
	}
	shares := resource.Advertise(n.Shares, viewer)
	if isSelf {
		shares = resource.Advertise(n.Shares, "*")
	}
	// A compute offer is only visible to peers actually on its access list.
	var offer *resource.ComputeOffer
	if n.Compute.AllowsPeer(viewer) || (isSelf && n.Compute.Enabled) {
		offer = &resource.ComputeOffer{
			Label:      n.Compute.Label,
			MaxSeconds: n.Compute.Timeout(),
		}
	}
	// A screen is offered only to peers on its access list, and control is
	// reported per viewer: the machine may permit control in general while
	// this particular viewer is only allowed to watch.
	var desk *resource.DesktopOffer
	if n.Desktop.AllowsPeer(viewer) || (isSelf && n.Desktop.Enabled) {
		desk = &resource.DesktopOffer{
			Control: n.Desktop.Control,
			Ready:   n.Screen.Ready,
			Label:   n.Desktop.Label,
			Width:   n.Screen.Width,
			Height:  n.Screen.Height,
			Problem: n.Screen.Error,
			Via:     n.Screen.Via,
		}
		// A platform that cannot inject input cannot be driven however the
		// operator has configured it.
		if !n.Screen.Control {
			desk.Control = false
		}
	}
	return netmap.Node{
		ID:         n.ID,
		Name:       n.Name,
		OS:         n.OS,
		MachineKey: n.MachineKey,
		WGKey:      n.WGKey,
		DiscoKey:   n.DiscoKey,
		IP:         n.IP,
		Endpoints:  eps,
		Services:   n.Services,
		SSH:        n.SSH,
		Shares:     shares,
		Compute:    offer,
		Desktop:    desk,
		LAN:        n.LAN,
		Stats:      n.Stats,
		Hub:        n.Hub,
		LastSeen:   n.LastSeen,
		Online:     time.Since(n.LastSeen) < onlineWindow,
	}
}

// SetHub records whether a node runs on the hub machine.
//
// Called on every netmap poll rather than only at registration, so a node that
// joined before this flag existed — or a hub that moved to another machine —
// corrects itself without anyone re-running `locnet join`. It bumps the map
// version only when the answer actually changes, which after the first poll is
// never.
func (s *Store) SetHub(nodeID string, isHub bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	n, ok := s.st.Nodes[nodeID]
	if !ok || n.Hub == isHub {
		return
	}
	n.Hub = isHub
	s.bump()
	s.save()
}

// allocIPLocked hands out the lowest free address in the prefix.
//
// Lowest-free rather than random keeps addresses short and memorable in small
// networks, and makes the mapping stable enough to write into a firewall rule.
// Callers must hold s.mu.
func (s *Store) allocIPLocked() (netip.Addr, error) {
	taken := make(map[netip.Addr]bool, len(s.st.Nodes))
	for _, n := range s.st.Nodes {
		taken[n.IP] = true
	}
	p := s.st.Network.Prefix
	// Skip the network address itself; start at .1.
	addr := p.Addr().Next()
	for p.Contains(addr) {
		// Skip anything ending in .0 or .255: some stacks and a lot of
		// firewall rules still treat those as special.
		if last := addr.As4()[3]; last != 0 && last != 255 && !taken[addr] {
			return addr, nil
		}
		addr = addr.Next()
	}
	return netip.Addr{}, fmt.Errorf("hub: no addresses left in %s — the network is full", p)
}

// allocNameLocked derives a unique DNS label from a hostname. Callers must
// hold s.mu.
func (s *Store) allocNameLocked(hostname string) string {
	base := strings.ToLower(hostname)
	if i := strings.IndexByte(base, '.'); i > 0 {
		base = base[:i] // strip any domain the machine reports
	}
	base = strings.Trim(nameSanitiser.ReplaceAllString(base, "-"), "-")
	if base == "" {
		base = "node"
	}
	if len(base) > 40 {
		base = base[:40]
	}

	taken := make(map[string]bool, len(s.st.Nodes))
	for _, n := range s.st.Nodes {
		taken[n.Name] = true
	}
	if !taken[base] {
		return base
	}
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s-%d", base, i)
		if !taken[candidate] {
			return candidate
		}
	}
}

// stripScheme drops an http:// or https:// prefix. The advertised address may
// carry one for the control plane's benefit; the relay is raw UDP and cannot
// use it.
func stripScheme(s string) string {
	if i := strings.Index(s, "://"); i >= 0 {
		return s[i+3:]
	}
	return s
}

// usesDescription renders a token's use limit for the audit log.
func usesDescription(uses int) string {
	if uses < 0 {
		return "unlimited"
	}
	return fmt.Sprintf("%d", uses)
}

func sameServices(a, b []resource.Service) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameShares(a, b []resource.Share) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || a[i].Kind != b[i].Kind ||
			a[i].Port != b[i].Port || a[i].ReadOnly != b[i].ReadOnly ||
			a[i].Description != b[i].Description ||
			a[i].Web != b[i].Web || a[i].Target != b[i].Target ||
			strings.Join(a[i].Allow, ",") != strings.Join(b[i].Allow, ",") {
			return false
		}
	}
	return true
}

// statsMovedMaterially reports whether a machine's condition changed enough to
// be worth telling anyone.
//
// Raw comparison would be true on almost every report — load and free memory
// never hold still. Rounding first means an idle machine stays quiet and a
// machine that starts working, or whose disk starts filling, does not.
func statsMovedMaterially(a, b resource.Stats) bool {
	bucket := func(v float64, size float64) int {
		if size <= 0 {
			return 0
		}
		return int(v / size)
	}
	return a.CPUs != b.CPUs ||
		bucket(a.LoadPercent, 10) != bucket(b.LoadPercent, 10) ||
		bucket(a.MemUsedPercent(), 5) != bucket(b.MemUsedPercent(), 5) ||
		bucket(a.DiskUsedPercent(), 2) != bucket(b.DiskUsedPercent(), 2) ||
		a.DiskTotalGB != b.DiskTotalGB ||
		a.MemTotalMB != b.MemTotalMB
}

func sameAddrPorts(a, b []netip.AddrPort) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
