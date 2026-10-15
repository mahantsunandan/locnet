package node

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mahantsunandan/locnet/internal/hubapi"
	"github.com/mahantsunandan/locnet/internal/hubtls"
	"github.com/mahantsunandan/locnet/internal/joincode"
	"github.com/mahantsunandan/locnet/internal/key"
	"github.com/mahantsunandan/locnet/internal/magicsock"
	"github.com/mahantsunandan/locnet/internal/netmap"
	"github.com/mahantsunandan/locnet/internal/paths"
	"github.com/mahantsunandan/locnet/internal/policy"
	"github.com/mahantsunandan/locnet/internal/resource"
	"github.com/mahantsunandan/locnet/internal/shareclient"
	"github.com/mahantsunandan/locnet/internal/sshkeys"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	// DefaultListenPort is the shared WireGuard and discovery port. Fixed
	// rather than random so that a port forward, once configured, keeps
	// working across restarts.
	DefaultListenPort = 41820

	// keepalive keeps NAT mappings open between peers. 25s is the WireGuard
	// convention: comfortably under the 30s that the shortest-lived NAT
	// tables use.
	keepalive = 25

	// reportInterval is how often we tell the hub about ourselves.
	reportInterval = 30 * time.Second

	// serviceScanInterval is how often we look for listening services. Much
	// rarer than the report: starting an SSH server is not something that
	// needs to be noticed within thirty seconds, and the scan opens a
	// connection per catalog entry.
	serviceScanInterval = 5 * time.Minute

	// pollBackoff is the pause after a failed hub poll. Long enough not to
	// hammer a hub that is down, short enough that recovery is quick.
	pollBackoff = 5 * time.Second
)

// TransportNote describes Status.HubTransport for people, or "" for none.
func TransportNote(t string) string {
	switch t {
	case "tls":
		return "encrypted, pinned to the hub's key"
	case "https":
		return "encrypted, through a TLS proxy"
	case "http":
		return "not encrypted: the hub is older than 0.10.4, or its address says http://"
	}
	return ""
}

// AgentVersion is the running locnetd's version, set by its main package and
// reported in Status.
var AgentVersion string

// Status is the snapshot `locnet status` prints.
type Status struct {
	Registered bool       `json:"registered"`
	Running    bool       `json:"running"`
	NodeID     string     `json:"node_id,omitempty"`
	Name       string     `json:"name,omitempty"`
	OS         string     `json:"os,omitempty"`
	IP         netip.Addr `json:"ip,omitempty"`
	Network    string     `json:"network,omitempty"`
	HubAddr    string     `json:"hub_addr,omitempty"`
	Interface  string     `json:"interface,omitempty"`
	ListenPort uint16     `json:"listen_port,omitempty"`
	Observed   string     `json:"observed,omitempty"`
	Relay      string     `json:"relay,omitempty"`
	Version    uint64     `json:"netmap_version,omitempty"`
	LastError  string     `json:"last_error,omitempty"`
	// HubOK is true once some hub address has actually answered. Without it
	// the CLI cannot tell "the hub is fine" from "nothing has asked it yet",
	// and it reported the former either way — naming, at startup, whichever
	// stale address happened to be first in the list.
	HubOK bool `json:"hub_ok,omitempty"`
	// HubTransport is how the hub last answered: "tls" (pinned to its
	// fingerprint), "https" (through a proxy with a real certificate) or
	// "http" (in the clear: a hub older than 0.10.4, or an http:// address).
	HubTransport string `json:"hub_transport,omitempty"`

	Stats    resource.Stats     `json:"stats,omitzero"`
	Services []resource.Service `json:"services,omitempty"`
	// Shares are this machine's own, with their local paths — the CLI runs
	// on the machine that owns them, so there is nothing to hide.
	Shares []resource.Share `json:"shares,omitempty"`
	// Groups this machine belongs to under the network's access policy.
	Groups []string `json:"groups,omitempty"`
	// Compute is this machine's own compute configuration.
	Compute resource.ComputeConfig `json:"compute,omitzero"`
	// Desktop is this machine's own screen-sharing configuration, and
	// DesktopStatus is what the session helper says about the screen it can
	// actually see.
	Desktop       resource.DesktopConfig `json:"desktop,omitzero"`
	DesktopStatus resource.DesktopStatus `json:"desktop_status,omitzero"`
	// LAN is this machine's own real interfaces.
	LAN []resource.LANIface `json:"lan,omitempty"`
	// FilteredPackets counts inbound packets the access policy has dropped.
	FilteredPackets uint64 `json:"filtered_packets,omitempty"`
	// Conflicts are overlapping routes or addresses found on this machine.
	Conflicts []string `json:"conflicts,omitempty"`
	// IsHub is true when this machine also runs locnet-hub.
	IsHub bool `json:"is_hub,omitempty"`
	// Sites is how this machine's WebShare sites stand, as the hub says.
	Sites []resource.SiteStatus `json:"sites,omitempty"`
	// ManageHosts is whether peer names are written to the hosts file.
	ManageHosts bool `json:"manage_hosts,omitempty"`
	// IsAdmin is true when the hub accepts network administration — invite
	// codes, removing machines — signed by this machine.
	IsAdmin bool `json:"is_admin,omitempty"`
	// Version is this agent's own version, so a console or a peer can tell
	// which build it is talking to.
	AgentVersion string `json:"agent_version,omitempty"`
	// Alerts are evaluated locally from the thresholds in the netmap, so a
	// node flags a peer running out of disk without needing an admin token.
	Alerts []resource.Alert `json:"alerts,omitempty"`

	Peers []PeerStatus `json:"peers,omitempty"`
}

// PeerStatus is one row of `locnet status`.
type PeerStatus struct {
	Name    string     `json:"name"`
	IP      netip.Addr `json:"ip"`
	OS      string     `json:"os,omitempty"`
	Path    string     `json:"path"`
	Addr    string     `json:"addr,omitempty"`
	Latency string     `json:"latency,omitempty"`
	Online  bool       `json:"online"`

	Services []resource.Service `json:"services,omitempty"`
	Shares   []resource.Advert  `json:"shares,omitempty"`
	// SSH are this peer's public SSH keys: host keys for known_hosts, and
	// its operator's key for authorized_keys if we have accepted it.
	SSH    resource.SSHKeys `json:"ssh,omitzero"`
	Stats  resource.Stats   `json:"stats,omitzero"`
	Groups []string         `json:"groups,omitempty"`
	// Compute describes this peer's offer to run work for us, if it makes one.
	Compute *resource.ComputeOffer `json:"compute,omitempty"`
	// Desktop describes this peer's offer to show us its screen.
	Desktop *resource.DesktopOffer `json:"desktop,omitempty"`
	// LAN is this peer's real interfaces, used to work out who is on the
	// same piece of Ethernet as a machine that needs waking.
	LAN []resource.LANIface `json:"lan,omitempty"`
	// Restricted is true when the policy limits this peer to certain ports.
	Restricted bool `json:"restricted,omitempty"`
	// InboundPorts are the ports the policy lets this peer reach here;
	// empty means all of them.
	InboundPorts []policy.PortRange `json:"inbound_ports,omitempty"`
	// Hub is true for the machine that also runs locnet-hub.
	Hub bool `json:"hub,omitempty"`
	// LastSeen is when the hub last heard from this peer, which is what an
	// offline machine is best described by.
	LastSeen time.Time `json:"last_seen,omitzero"`
}

// Engine ties the agent's state, its hub connection, and its WireGuard device
// together. Every exported method is safe to call from the control socket
// while the engine is running.
type Engine struct {
	dir  string
	logf magicsock.Logf
	hc   *http.Client

	mu      sync.Mutex
	st      *State
	dev     *device.Device
	tunDev  tun.Device
	ms      *magicsock.Conn
	nm      *netmap.NetMap
	ifName  string
	running bool
	lastErr string

	// hubPref is the address that last answered. Tried first next time, so
	// the common case costs one request rather than a walk down the list.
	hubPref string
	// hubTransport is how the last answer came: see Status.HubTransport.
	hubTransport string
	// pinnedHC reaches bare hub addresses over TLS pinned to pinnedFP.
	pinnedHC *http.Client
	pinnedFP [16]byte
	// plainHubs are bare addresses that answered a TLS handshake in plain
	// HTTP — a hub older than 0.10.4 — and when. They are spoken to in
	// plain HTTP until plainRetry has passed, unless the hub is known to do
	// TLS, in which case that answer is refused instead.
	plainHubs map[string]time.Time
	// wgPeers is the peer set WireGuard was last configured with, so a new
	// netmap can be applied as a difference rather than as a replacement.
	// See wgUpdate for why that distinction is not a micro-optimisation.
	wgPeers  map[key.WGPublic]netip.Addr
	shareSrv *shareServer
	filter   *filteredTUN
	services []resource.Service
	stats    resource.Stats

	// The last conflict check and what it was for. See conflicts.
	conflictsKey   string
	conflictsAt    time.Time
	conflictsCache []string
	// lastVerify is the last service-verification result logged.
	lastVerify string
	// reached records peer services this machine connected to itself, and
	// when. See checkPeerServices.
	reached map[netip.AddrPort]time.Time
	// rescan asks the service scan to run now rather than at its next tick.
	rescan chan struct{}

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewEngine loads state from dir.
func NewEngine(dir string, logf magicsock.Logf) (*Engine, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	st, err := LoadState(dir)
	if err != nil {
		return nil, err
	}
	return &Engine{
		dir:    dir,
		logf:   logf,
		st:     st,
		hc:     newHubClient(),
		rescan: make(chan struct{}, 1),
	}, nil
}

// newHubClient talks to the hub.
//
// The overall timeout has to exceed the netmap long poll, which the hub holds
// open for 25 seconds — so it is 40. But applying that to the *dial* would
// mean a hub that has moved takes 40 seconds to fail and another 5 to retry,
// and a node stranded on a stale address recovers at roughly one attempt a
// minute. Separating the two makes an unreachable address fail in 5 seconds
// while a legitimate long poll still gets its full time.
func newHubClient() *http.Client {
	return &http.Client{Timeout: 40 * time.Second, Transport: newHubTransport()}
}

func newHubTransport() *http.Transport {
	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second,
		// A stale keep-alive connection to an address the hub no longer
		// answers on is worse than no connection: it fails slowly.
		IdleConnTimeout: 60 * time.Second,
	}
}

// State returns a copy of the persisted state.
func (e *Engine) State() State {
	e.mu.Lock()
	defer e.mu.Unlock()
	return *e.st
}

// ------------------------------------------------------------------ join

// Join redeems a join code: it confirms the hub's identity, registers this
// machine, and stores what came back.
//
// It does not bring the tunnel up. Joining and running are separate so that a
// failure to configure the network interface does not look like a failure to
// join, and so an installer can join during provisioning and start later.
func (e *Engine) Join(ctx context.Context, code string) error {
	c, err := joincode.Parse(code)
	if err != nil {
		return err
	}
	// Everything from here talks to the hub the code names, not the one in
	// the state file (if any): the TLS pin comes from the code too, so the
	// token goes only to that hub, and never in the clear to a hub that
	// minted a code saying it speaks TLS.
	jp := &joinPin{fp: c.HubFingerprint, required: c.TLS}
	ctx = context.WithValue(ctx, joinPinKey{}, jp)

	// Try every address the code carries and keep the first that answers.
	// A hub behind NAT publishes both a LAN and a public address, and which
	// one works depends entirely on where the joining machine is standing.
	reachable, info, err := e.probeHubs(ctx, c.HubAddrs)
	if err != nil {
		return err
	}
	if got := info.HubKey.Fingerprint(); got != c.HubFingerprint {
		return fmt.Errorf("the hub at %s is not the one this code was issued for "+
			"(expected fingerprint %x, got %x) — do not use this code here", reachable, c.HubFingerprint, got)
	}

	hostname, _ := os.Hostname()
	e.mu.Lock()
	req := hubapi.RegisterRequest{
		Token:      base64.StdEncoding.EncodeToString(c.Token[:]),
		Hostname:   hostname,
		OS:         runtime.GOOS,
		MachineKey: e.st.MachineKey.Public(),
		WGKey:      e.st.WGKey.Public(),
		DiscoKey:   e.st.DiscoKey.Public(),
	}
	e.mu.Unlock()

	var resp hubapi.RegisterResponse
	if err := e.postJSON(ctx, reachable, "/register", req, &resp, false); err != nil {
		return err
	}
	if resp.NetMap == nil {
		return fmt.Errorf("hub returned no network map")
	}
	nm, err := resp.NetMap.Open(c.HubFingerprint)
	if err != nil {
		return err
	}

	e.mu.Lock()
	e.st.SetHubs(c.HubAddrs)
	e.hubPref = reachable
	e.st.SetFingerprint(c.HubFingerprint)
	e.st.HubTLS = c.TLS || jp.sawTLS.Load() || nm.Network.HubTLS
	e.st.JoinToken = req.Token
	e.st.NodeID = resp.NodeID
	e.st.Name = resp.Name
	e.st.IP = resp.IP
	if e.st.ListenPort == 0 {
		e.st.ListenPort = DefaultListenPort
	}
	e.st.CachedNetMap, _ = json.Marshal(resp.NetMap)
	// Hold the map even though the tunnel is not up yet, so `locnet status`
	// can name the network the machine just joined. Without this, a join
	// that succeeds but cannot start the tunnel reports no network at all,
	// which reads like the join failed.
	e.nm = nm
	st := *e.st
	e.mu.Unlock()

	if err := SaveState(e.dir, &st); err != nil {
		return err
	}
	e.logf("joined %q as %s (%s) via %s", nm.Network.Name, resp.Name, resp.IP, reachable)
	if len(c.HubAddrs) > 1 {
		e.logf("hub addresses: %s", strings.Join(c.HubAddrs, ", "))
	}
	return nil
}

// Leave forgets the network. The node record stays on the hub until an
// operator removes it, which is deliberate: a machine that has been stolen
// should not be able to erase its own membership.
func (e *Engine) Leave() error {
	_ = e.Down()
	e.mu.Lock()
	e.st.Reset()
	st := *e.st
	e.mu.Unlock()
	return SaveState(e.dir, &st)
}

// --------------------------------------------------------------- up/down

// Up brings the tunnel up and starts the hub sync loops.
func (e *Engine) Up() error {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return nil
	}
	if !e.st.Registered() {
		e.mu.Unlock()
		return errors.New("this machine has not joined a network yet — run `locnet join <code>` first")
	}
	st := *e.st
	e.mu.Unlock()

	nm, err := e.cachedNetMap(&st)
	if err != nil {
		return err
	}

	mtu := nm.Network.MTU
	if mtu <= 0 {
		mtu = 1280
	}
	// Each stage is logged before it runs. Bringing a tunnel up touches the
	// kernel, the routing table and two sockets, and when one of those wedges
	// the only useful question is which one — a silent hang answers nothing.
	e.logf("up: creating tunnel interface (mtu %d)", mtu)
	rawTUN, err := tun.CreateTUN(paths.DefaultInterface(), mtu)
	if err != nil {
		return fmt.Errorf("create tunnel interface: %w%s", err, tunHint(err))
	}
	ifName, err := rawTUN.Name()
	if err != nil {
		rawTUN.Close()
		return fmt.Errorf("read tunnel interface name: %w", err)
	}
	// Port-level policy is applied here, between WireGuard and the kernel.
	// Machine-level policy needs no code: a peer the policy forbids is not in
	// the netmap, so there is no tunnel to filter.
	tunDev := newFilteredTUN(rawTUN)

	ms := magicsock.New(magicsock.Options{
		NodeID:     st.NodeID,
		MachineKey: st.MachineKey,
		WGKey:      st.WGKey.Public(),
		DiscoKey:   st.DiscoKey,
		Logf:       e.logf,
	})

	logger := device.NewLogger(device.LogLevelError, "wireguard: ")
	dev := device.NewDevice(tunDev, ms, logger)

	e.logf("up: configuring wireguard on %s (%d peer(s), udp port %d)", ifName, len(nm.Peers), st.ListenPort)
	if err := dev.IpcSet(wgConfig(&st, nm)); err != nil {
		dev.Close()
		return fmt.Errorf("configure wireguard: %w", err)
	}
	e.logf("up: starting wireguard device")
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("bring wireguard up: %w", err)
	}

	// The interface must carry an address and a route before anything can
	// use it. This is the part that needs privileges and the part most
	// likely to fail on an unusual host, so it happens last, after the
	// tunnel itself is known to be working.
	e.logf("up: configuring %s with %s and a route for %s", ifName, st.IP, nm.Network.Prefix)
	if err := configureInterface(ifName, st.IP, nm.Network.Prefix, mtu); err != nil {
		dev.Close()
		return fmt.Errorf("configure %s: %w", ifName, err)
	}
	// In the background: on Windows it waits for the network location
	// service, which takes seconds, and the tunnel is already usable.
	go trustOverlay(ifName, nm.Network.Prefix, e.logf)

	ctx, cancel := context.WithCancel(context.Background())

	e.logf("up: starting the share server on %s", st.IP)
	shareSrv := newShareServer(e.logf)
	if err := shareSrv.start(st.IP); err != nil {
		// A share server that will not bind is not a reason to refuse the
		// tunnel — the network is still useful without file sharing.
		e.logf("%v", err)
		shareSrv = nil
	}

	e.mu.Lock()
	e.dev, e.tunDev, e.ms = dev, tunDev, ms
	e.filter = tunDev
	e.ifName, e.running, e.cancel = ifName, true, cancel
	e.shareSrv = shareSrv
	e.wgPeers = wgPeers(nm)
	e.lastErr = ""
	e.mu.Unlock()

	e.logf("up: applying the network map")
	e.applyNetMap(nm)

	e.wg.Add(4)
	go func() { defer e.wg.Done(); e.pollLoop(ctx) }()
	go func() { defer e.wg.Done(); e.reportLoop(ctx) }()
	go func() { defer e.wg.Done(); e.scanLoop(ctx) }()
	go func() { defer e.wg.Done(); e.workerLoop(ctx) }()

	for _, w := range CheckPrefixConflicts(nm.Network.Prefix, ifName) {
		// Not fatal. The tunnel may work perfectly; it may also silently
		// send half its traffic to the wrong place. Either way the operator
		// needs to know, and only they can decide.
		e.logf("WARNING: %s", w)
	}

	e.logf("locnet up: %s on %s (mtu %d, udp port %d)", st.IP, ifName, mtu, st.ListenPort)
	return nil
}

// Down tears the tunnel down. It is safe to call when nothing is running.
func (e *Engine) Down() error {
	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return nil
	}
	cancel, dev, ifName := e.cancel, e.dev, e.ifName
	shareSrv := e.shareSrv
	manageHosts := e.st.ManageHosts
	e.running = false
	e.dev, e.tunDev, e.ms, e.cancel = nil, nil, nil, nil
	e.shareSrv, e.filter = nil, nil
	e.ifName = ""
	e.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	e.wg.Wait()
	if shareSrv != nil {
		shareSrv.stop()
	}

	// Closing the device closes the TUN and the bind with it.
	if dev != nil {
		dev.Close()
	}
	if manageHosts {
		if err := clearHosts(); err != nil {
			e.logf("could not clean the hosts file: %v", err)
		}
	}
	e.logf("locnet down (%s removed)", ifName)
	return nil
}

// Close shuts the engine down for good.
func (e *Engine) Close() error { return e.Down() }

// ------------------------------------------------------------- hub sync

// pollLoop keeps the netmap current using long polls.
func (e *Engine) pollLoop(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		changed, err := e.pollOnce(ctx)
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return
			}
			e.setLastError(fmt.Sprintf("hub poll: %v", err))
			select {
			case <-ctx.Done():
				return
			case <-time.After(pollBackoff):
			}
		case changed:
			e.setLastError("")
		default:
			e.setLastError("")
		}
	}
}

func (e *Engine) pollOnce(ctx context.Context) (bool, error) {
	e.mu.Lock()
	st := *e.st
	var since uint64
	if e.nm != nil {
		since = e.nm.Version
	}
	e.mu.Unlock()

	var resp hubapi.NetMapResponse
	path := fmt.Sprintf("/netmap?since=%d", since)
	if err := e.hubGet(ctx, path, &resp); err != nil {
		return false, err
	}
	if !resp.Changed || resp.NetMap == nil {
		return false, nil
	}

	fp, err := st.Fingerprint()
	if err != nil {
		return false, err
	}
	nm, err := resp.NetMap.Open(fp)
	if err != nil {
		return false, err
	}

	e.mu.Lock()
	e.st.CachedNetMap, _ = json.Marshal(resp.NetMap)
	if nm.Network.HubTLS && !e.st.HubTLS {
		// The map is verified, so this cannot have been injected by
		// someone on the path — even if this request itself was plain.
		e.st.HubTLS = true
		e.logf("hub: the hub serves TLS; plain HTTP to it is now refused")
	}
	if nm.Self.IP.IsValid() {
		e.st.IP = nm.Self.IP
	}
	if nm.Self.Name != "" {
		e.st.Name = nm.Self.Name
	}
	saveCopy := *e.st
	e.mu.Unlock()
	_ = SaveState(e.dir, &saveCopy)

	e.applyNetMap(nm)
	return true, nil
}

// applyNetMap pushes a new map into WireGuard and magicsock.
func (e *Engine) applyNetMap(nm *netmap.NetMap) {
	e.mu.Lock()
	dev, ms, running := e.dev, e.ms, e.running
	prevWG := e.wgPeers
	st := *e.st
	e.nm = nm
	e.mu.Unlock()

	if !running || dev == nil || ms == nil {
		return
	}

	// Only reconfigure WireGuard when WireGuard's own view of the network has
	// changed. A netmap arrives every few seconds because someone's load
	// average moved; rebuilding the tunnel for that would cost a handshake
	// each time. See wgUpdate.
	nextWG := wgPeers(nm)
	peersChanged := false
	if cfg := wgUpdate(prevWG, nextWG); cfg != "" {
		if err := dev.IpcSet(cfg); err != nil {
			e.setLastError(fmt.Sprintf("apply netmap: %v", err))
			return
		}
		peersChanged = true
		e.logf("wireguard: peer set updated (%d peer(s))", len(nextWG))
	}
	e.mu.Lock()
	e.wgPeers = nextWG
	e.mu.Unlock()

	peers := make([]magicsock.PeerConfig, 0, len(nm.Peers))
	for _, p := range nm.Peers {
		peers = append(peers, magicsock.PeerConfig{
			NodeID:    p.Name,
			WGKey:     p.WGKey,
			DiscoKey:  p.DiscoKey,
			Endpoints: p.Endpoints,
		})
	}
	ms.SetPeers(peers)
	ms.SetOverlay(nm.Network.Prefix)

	// Offer magicsock every relay the hub advertises rather than only the
	// first. Which one works depends on where this machine currently is, and
	// that is not something the hub can know when it signs the map.
	var relays []netip.AddrPort
	for _, r := range nm.Relays {
		addr, err := resolveUDP(r.Addr)
		if err != nil {
			e.logf("cannot resolve relay %q: %v", r.Addr, err)
			continue
		}
		relays = append(relays, addr)
	}
	ms.SetRelays(relays)

	// Install the port rules the hub resolved for us. A peer with no entry
	// is unrestricted, which is the common case and costs nothing.
	e.mu.Lock()
	filter := e.filter
	e.mu.Unlock()
	if filter != nil {
		rules := make(map[netip.Addr]peerPorts, len(nm.Peers))
		restricted := 0
		for _, p := range nm.Peers {
			if !p.IP.IsValid() {
				continue
			}
			if len(p.InboundPorts) == 0 {
				continue
			}
			rules[p.IP] = peerPorts{ranges: p.InboundPorts}
			restricted++
		}
		filter.setRules(rules)
		if restricted > 0 {
			e.logf("policy: %d peer(s) restricted to specific ports", restricted)
		}
	}

	// Learn about any hub we did not know about. The netmap is signed by the
	// hub whose fingerprint this node already pinned, so a hub address that
	// arrives this way is no less trustworthy than the one in the join code
	// — and every map from any of them still has to verify against the same
	// fingerprint before a single byte of it is believed.
	e.learnHubs(nm.Network.Hubs)

	// The share server needs a fresh view of who is who: an overlay address
	// only identifies a peer if the map that maps it is current.
	e.mu.Lock()
	shareSrv := e.shareSrv
	shares := append([]resource.Share(nil), e.st.Shares...)
	compute := e.st.Compute
	desktop := e.st.Desktop
	e.mu.Unlock()
	if shareSrv != nil {
		shareSrv.setCompute(compute)
		shareSrv.setDesktop(desktop)
	}
	if shareSrv != nil {
		shareSrv.setPeerLookup(peerLookupFor(nm))
		shareSrv.setShares(shares)
	}

	if st.ManageHosts {
		if err := writeHosts(nm); err != nil {
			e.logf("could not update the hosts file: %v", err)
		}
	}
	// Most maps differ from the last only in somebody's load figure, so the
	// line is kept for the ones that change who is on the network.
	if peersChanged {
		e.logf("netmap v%d applied: %d peer(s)", nm.Version, len(nm.Peers))
	}
}

// reportLoop tells the hub where we are, what we run, and how we are doing.
func (e *Engine) reportLoop(ctx context.Context) {
	// The first report goes out quickly: until peers know where we are,
	// nobody can probe us and everything stays on the relay.
	t := time.NewTimer(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := e.report(ctx); err != nil && ctx.Err() == nil {
			e.logf("report to hub: %v", err)
		}
		t.Reset(reportInterval)
	}
}

func (e *Engine) report(ctx context.Context) error {
	e.mu.Lock()
	ms := e.ms
	services := append([]resource.Service(nil), e.services...)
	shares := append([]resource.Share(nil), e.st.Shares...)
	compute := e.st.Compute
	desktop := e.st.Desktop
	e.mu.Unlock()
	if ms == nil {
		return nil
	}

	stats := resource.CollectStats()
	// GPUs are probed here rather than inside CollectStats because this runs
	// on a slow timer, while CollectStats is cheap enough to call anywhere.
	// Shelling out to nvidia-smi is neither.
	stats.GPUs = resource.DetectGPUs()
	e.mu.Lock()
	e.stats = stats
	e.mu.Unlock()

	req := hubapi.ReportRequest{
		Local:    ms.LocalEndpoints(),
		Observed: ms.Observed(),
		Services: services,
		Shares:   shares,
		Stats:    stats,
		LAN:      resource.LocalInterfaces(),
		Compute:  compute,
		Desktop:  desktop,
		Screen:   e.DesktopStatus(),
		SSH:      e.sshIdentity(),
	}
	return e.hubPost(ctx, "/report", req)
}

// scanLoop looks for services listening on this machine's own overlay address,
// then asks a peer to confirm that any of them are reachable from outside.
//
// The self-scan alone was wrong in the one direction that matters. Dialling
// this machine's own overlay address was chosen precisely because it looked
// like what a peer would experience, and on Windows it is not: traffic to a
// machine's own address is exempt from its firewall, so the scan succeeds
// against a port every other machine is blocked from. The result was advertised
// as fact, next to live latency figures, and there was no way to tell from any
// other machine that it was fiction.
//
// A peer's opinion is the correction. It is advisory rather than authoritative:
// services the peer could not reach stay in the list marked unverified, because
// "nobody was online to ask" and "the port is shut" must not look the same.
func (e *Engine) scanLoop(ctx context.Context) {
	// Wait for the interface to settle before the first scan, or everything
	// looks closed.
	t := time.NewTimer(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-e.rescan:
			if !t.Stop() {
				select {
				case <-t.C:
				default:
				}
			}
		}

		e.mu.Lock()
		ip := e.st.IP
		behind := portShareTargets(e.st.Shares)
		e.mu.Unlock()

		scanCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		found := resource.DetectServices(scanCtx, ip, behind)
		cancel()

		verifyCtx, cancelVerify := context.WithTimeout(ctx, 30*time.Second)
		e.verifyWithPeer(verifyCtx, found)
		cancelVerify()
		checkCtx, cancelCheck := context.WithTimeout(ctx, 30*time.Second)
		e.checkPeerServices(checkCtx)
		cancelCheck()

		e.mu.Lock()
		changed := !sameServiceList(found, e.services)
		e.services = found
		e.mu.Unlock()
		if changed {
			e.logf("found %d service(s) on %s%s", len(found), ip, serviceProblems(found))
			// Tell the hub now: a server that has just started working, or
			// just stopped, should not wait half a minute to be believed.
			go e.reportSoon()
		}
		t.Reset(serviceScanInterval)
	}
}

// Rescan runs the service scan now, for something that has just changed what
// this machine serves — `locnet setup rdp` giving the RDP server a login.
func (e *Engine) Rescan() {
	select {
	case e.rescan <- struct{}{}:
	default: // one is already pending
	}
}

func sameServiceList(a, b []resource.Service) bool {
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

// serviceProblems is the log suffix naming services that answer but refuse.
func serviceProblems(found []resource.Service) string {
	var out []string
	for _, s := range found {
		if s.Problem != "" {
			out = append(out, s.Name+": "+s.Problem)
		}
	}
	if len(out) == 0 {
		return ""
	}
	return " — not usable: " + strings.Join(out, "; ")
}

// sshIdentity is what this machine publishes about its SSH identity.
//
// Host keys are read from disk every time rather than cached: regenerating them
// is rare but it happens — a cloned VM, a reinstalled sshd — and a peer holding
// a stale host key sees the loud failure that means a man-in-the-middle, which
// is a bad way to learn that somebody rebuilt a machine.
//
// The operator's own public key is published only if one has been offered
// through `locnet ssh-keys publish`. The daemon runs as root and has no way to
// know which human it works for, so it does not guess: a key appears here
// because somebody ran a command, not because a file was found in a home
// directory the daemon happened to be able to read.
func (e *Engine) sshIdentity() resource.SSHKeys {
	e.mu.Lock()
	user := e.st.SSHUserKey
	e.mu.Unlock()
	return resource.SSHKeys{User: user, Host: sshkeys.HostKeys()}
}

// SetSSHUserKey records the operator's public key and publishes it.
func (e *Engine) SetSSHUserKey(pub string) error {
	e.mu.Lock()
	e.st.SSHUserKey = strings.TrimSpace(pub)
	st := *e.st
	e.mu.Unlock()
	go e.reportSoon()
	return SaveState(e.dir, &st)
}

// SSHAcceptFrom returns the peers whose operator keys this machine installs.
func (e *Engine) SSHAcceptFrom() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.st.SSHAcceptFrom...)
}

// SetSSHAcceptFrom replaces the accept list.
func (e *Engine) SetSSHAcceptFrom(peers []string) error {
	e.mu.Lock()
	e.st.SSHAcceptFrom = append([]string(nil), peers...)
	st := *e.st
	e.mu.Unlock()
	return SaveState(e.dir, &st)
}

// MayReach reports whether the access policy lets this peer connect to the
// port here.
func (p PeerStatus) MayReach(port uint16) bool {
	if len(p.InboundPorts) == 0 {
		return true
	}
	for _, r := range p.InboundPorts {
		if port >= r.Lo && port <= r.Hi {
			return true
		}
	}
	return false
}

// Probers lists the online peers worth asking to connect back to this
// machine, the ones the policy lets reach the most of ports first.
//
// The first online peer used to be asked, whoever it was. Under a one-way
// policy that is often a peer forbidden from connecting here at all, so
// every port came back closed: the background check marked this machine's
// services unreachable for the whole network, and `locnet doctor` reported a
// firewall problem and prescribed a fix for it. A peer that may reach none of
// the ports is left out entirely.
func Probers(peers []PeerStatus, ports []uint16) []PeerStatus {
	type cand struct {
		p PeerStatus
		n int
	}
	var cs []cand
	for _, p := range peers {
		if !p.Online || !p.IP.IsValid() {
			continue
		}
		n := 0
		for _, port := range ports {
			if p.MayReach(port) {
				n++
			}
		}
		if n > 0 {
			cs = append(cs, cand{p, n})
		}
	}
	sort.SliceStable(cs, func(i, j int) bool { return cs[i].n > cs[j].n })
	out := make([]PeerStatus, len(cs))
	for i, c := range cs {
		out[i] = c.p
	}
	return out
}

// verifyPeerAttempts caps how many peers are asked before giving up. One
// usually answers; trying every machine on a large network would turn a scan
// into a broadcast.
const verifyPeerAttempts = 3

// verifyWithPeer marks the services a peer could actually reach, in place.
//
// Failure is silent and leaves everything unverified, which is the correct
// reading: nobody was available to confirm. The alternative — treating an
// unanswered probe as proof the port is shut — would strip a machine's services
// from the network map every time the network was briefly quiet.
func (e *Engine) verifyWithPeer(ctx context.Context, found []resource.Service) {
	if len(found) == 0 {
		return
	}
	ports := make([]uint16, 0, len(found))
	for _, s := range found {
		ports = append(ports, s.Port)
	}
	if len(ports) > resource.MaxProbePorts {
		ports = ports[:resource.MaxProbePorts]
	}

	tried := 0
	for _, p := range Probers(e.Status().Peers, ports) {
		if tried >= verifyPeerAttempts {
			return
		}
		tried++

		res, err := shareclient.New(p.IP).Probe(ctx, p.Name, ports)
		if err != nil {
			// This peer could not be asked. That says nothing about our own
			// ports, so move on rather than concluding anything.
			continue
		}
		for i := range found {
			// A port the policy keeps this peer out of proves nothing
			// either way, so it stays unverified rather than "blocked".
			if p.MayReach(found[i].Port) {
				found[i].Verified = res.IsOpen(found[i].Port)
			}
		}
		// Said once, and again only if the answer changes: the same line every
		// five minutes for months is noise that hides the line that matters.
		summary := fmt.Sprintf("services verified from %s: %d of %d reachable",
			p.Name, len(res.Open), len(ports))
		e.mu.Lock()
		repeat := e.lastVerify == summary
		e.lastVerify = summary
		e.mu.Unlock()
		if !repeat {
			e.logf("%s", summary)
		}
		return
	}
}

// reachedTTL is how long a connection this machine made to a peer's service
// counts as confirming it: three scans, so one missed round does not flicker.
const reachedTTL = 3 * serviceScanInterval

// maxPeerChecks bounds the connections one round of checkPeerServices makes.
const maxPeerChecks = 256

// checkPeerServices connects to peers' services that nobody has confirmed,
// and remembers the ones that answered.
//
// Confirmation used to come only from the machine itself asking a peer to
// connect back (verifyWithPeer). A machine that may not open connections to
// anyone — the laptop under a "home reaches everything, the laptop reaches
// nothing" policy — can never ask, so every service it offered showed "?"
// forever on every machine, including the ones connecting to it every day.
// Whether *this* machine can reach a port is also the question its user is
// actually asking when they look at the list.
//
// Only unconfirmed services are tried, with a short timeout: a port the
// policy keeps us out of is dropped by the far machine's filter, and simply
// stays unconfirmed, which is the truth.
func (e *Engine) checkPeerServices(ctx context.Context) {
	var targets []netip.AddrPort
	for _, p := range e.Status().Peers {
		if !p.Online || !p.IP.IsValid() {
			continue
		}
		for _, sv := range p.Services {
			if !sv.Verified && sv.Problem == "" && sv.Port != 0 {
				targets = append(targets, netip.AddrPortFrom(p.IP, sv.Port))
			}
		}
	}
	if len(targets) > maxPeerChecks {
		targets = targets[:maxPeerChecks]
	}
	if len(targets) == 0 {
		return
	}

	var (
		wg  sync.WaitGroup
		mu  sync.Mutex
		ok  []netip.AddrPort
		sem = make(chan struct{}, 16)
	)
	d := net.Dialer{Timeout: 3 * time.Second}
	for _, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			c, err := d.DialContext(ctx, "tcp", t.String())
			if err != nil {
				return
			}
			c.Close()
			mu.Lock()
			ok = append(ok, t)
			mu.Unlock()
		}()
	}
	wg.Wait()

	now := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.reached == nil {
		e.reached = map[netip.AddrPort]time.Time{}
	}
	for ap, at := range e.reached {
		if now.Sub(at) >= reachedTTL {
			delete(e.reached, ap)
		}
	}
	for _, ap := range ok {
		e.reached[ap] = now
	}
}

// markReached returns services with those this machine reached itself marked
// verified. The netmap's slice is never modified: it is shared with every
// other reader of the map.
func markReached(ip netip.Addr, services []resource.Service, reached map[netip.AddrPort]bool) []resource.Service {
	var out []resource.Service
	for i, sv := range services {
		if sv.Verified || !reached[netip.AddrPortFrom(ip, sv.Port)] {
			continue
		}
		if out == nil {
			out = append([]resource.Service(nil), services...)
		}
		out[i].Verified = true
	}
	if out == nil {
		return services
	}
	return out
}

// ------------------------------------------------------------- shares

// ListShares returns this machine's shares.
func (e *Engine) ListShares() []resource.Share {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]resource.Share(nil), e.st.Shares...)
}

// AddShare adds or replaces a share by name.
func (e *Engine) AddShare(sh resource.Share) error {
	if err := sh.Validate(); err != nil {
		return err
	}
	if sh.Kind == resource.KindFiles {
		info, err := os.Stat(sh.Target)
		if err != nil {
			return fmt.Errorf("cannot share %s: %w", sh.Target, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("cannot share %s: it is a file, not a directory", sh.Target)
		}
	}

	e.mu.Lock()
	replaced := false
	for i := range e.st.Shares {
		if e.st.Shares[i].Name == sh.Name {
			e.st.Shares[i] = sh
			replaced = true
			break
		}
	}
	if !replaced {
		e.st.Shares = append(e.st.Shares, sh)
	}
	st := *e.st
	shareSrv := e.shareSrv
	shares := append([]resource.Share(nil), e.st.Shares...)
	e.mu.Unlock()

	if err := SaveState(e.dir, &st); err != nil {
		return err
	}
	if shareSrv != nil {
		shareSrv.setShares(shares)
	}
	// Push it to the hub now rather than waiting for the next tick: a share
	// nobody has been told about is not a share.
	go e.reportSoon()
	return nil
}

// RemoveShare deletes a share by name.
func (e *Engine) RemoveShare(name string) error {
	e.mu.Lock()
	kept := e.st.Shares[:0]
	found := false
	for _, sh := range e.st.Shares {
		if sh.Name == name {
			found = true
			continue
		}
		kept = append(kept, sh)
	}
	e.st.Shares = kept
	st := *e.st
	shareSrv := e.shareSrv
	shares := append([]resource.Share(nil), e.st.Shares...)
	e.mu.Unlock()

	if !found {
		return fmt.Errorf("no share called %q", name)
	}
	if err := SaveState(e.dir, &st); err != nil {
		return err
	}
	if shareSrv != nil {
		shareSrv.setShares(shares)
	}
	go e.reportSoon()
	return nil
}

// Manage sends a network-administration request to the hub, signed with this
// machine's identity key. The hub decides whether this machine may; nothing
// here does.
//
// in and out are passed through as JSON: the daemon is a courier for these,
// not an interpreter, so the console and the CLI can grow a field without the
// agent having to learn it.
func (e *Engine) Manage(ctx context.Context, op string, in json.RawMessage) (json.RawMessage, error) {
	e.mu.Lock()
	registered := e.st.Registered()
	e.mu.Unlock()
	if !registered {
		return nil, errors.New("this machine has not joined a network")
	}
	if len(in) == 0 {
		in = json.RawMessage("{}")
	}
	var out json.RawMessage
	err := e.tryHubs(ctx, func(addr string) error {
		return e.postJSON(ctx, addr, "/manage/"+op, in, &out, true)
	})
	return out, err
}

// reportSoon pushes a report outside the normal schedule.
func (e *Engine) reportSoon() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := e.report(ctx); err != nil {
		e.logf("could not tell the hub about the share change: %v", err)
	}
}

// peerLookupFor turns a netmap into an address-to-name function.
func peerLookupFor(nm *netmap.NetMap) resource.PeerLookup {
	byIP := make(map[netip.Addr]string, len(nm.Peers)+1)
	for _, p := range nm.Peers {
		if p.IP.IsValid() {
			byIP[p.IP] = p.Name
		}
	}
	// This machine is itself. A connection from its own overlay address
	// comes from a process here, which could reach the share's local target
	// directly anyway — so naming it grants nothing. It matters for the hub
	// machine's WebShare proxy reaching a site on the hub machine.
	if nm.Self.IP.IsValid() {
		byIP[nm.Self.IP] = nm.Self.Name
	}
	return func(a netip.Addr) (string, bool) {
		name, ok := byIP[a]
		return name, ok
	}
}

// ------------------------------------------------------------- status

// Status snapshots the engine for the CLI.
func (e *Engine) Status() Status {
	e.mu.Lock()
	st := *e.st
	nm, ms, running, ifName, lastErr := e.nm, e.ms, e.running, e.ifName, e.lastErr
	s0 := Status{Stats: e.stats, Services: append([]resource.Service(nil), e.services...)}
	reached := make(map[netip.AddrPort]bool, len(e.reached))
	for ap, at := range e.reached {
		if time.Since(at) < reachedTTL {
			reached[ap] = true
		}
	}
	if e.filter != nil {
		s0.FilteredPackets = e.filter.Dropped()
	}
	e.mu.Unlock()

	s := s0
	s.Registered = st.Registered()
	s.Running = running
	s.AgentVersion = AgentVersion
	s.NodeID = st.NodeID
	s.Name = st.Name
	s.OS = runtime.GOOS
	s.IP = st.IP
	s.HubAddr = e.currentHub()
	e.mu.Lock()
	s.HubOK = e.hubPref != ""
	if s.HubOK {
		s.HubTransport = e.hubTransport
	}
	e.mu.Unlock()
	s.Interface = ifName
	s.ListenPort = st.ListenPort
	s.LastError = lastErr
	if ms != nil {
		if relay := ms.Relay(); relay.IsValid() {
			s.Relay = relay.String()
		}
	}
	s.Shares = append([]resource.Share(nil), st.Shares...)
	s.ManageHosts = st.ManageHosts
	s.Compute = st.Compute
	s.Desktop = st.Desktop
	s.DesktopStatus = e.DesktopStatus()
	s.LAN = resource.LocalInterfaces()
	if nm != nil {
		s.Network = nm.Network.Name
		s.Version = nm.Version
		s.Groups = nm.Self.Groups
		s.IsHub = nm.Self.Hub
		s.Sites = nm.Self.Sites
		s.IsAdmin = nm.Self.Admin
		s.Conflicts = e.conflicts(nm.Network.Prefix, ifName)
	}
	if ms != nil {
		if obs := ms.Observed(); obs.IsValid() {
			s.Observed = obs.String()
		}
	}
	if nm == nil {
		return s
	}

	machines := make([]resource.Machine, 0, len(nm.Peers)+1)
	machines = append(machines, resource.Machine{
		Name: nm.Self.Name, Stats: s.Stats, LastSeen: time.Now(), Approved: true,
	})
	for _, p := range nm.Peers {
		machines = append(machines, resource.Machine{
			Name: p.Name, Stats: p.Stats, LastSeen: p.LastSeen, Approved: true,
		})
	}
	s.Alerts = resource.Evaluate(machines, nm.Network.Health, false)

	pathByKey := map[string]magicsock.PeerStatus{}
	if ms != nil {
		for _, ps := range ms.Status() {
			pathByKey[ps.WGKey.Hex()] = ps
		}
	}
	for _, p := range nm.Peers {
		row := PeerStatus{
			Name: p.Name, IP: p.IP, OS: p.OS, Online: p.Online, Path: "idle",
			Services: p.Services, Shares: p.Shares, Stats: p.Stats, SSH: p.SSH,
			Groups: p.Groups, Compute: p.Compute, Desktop: p.Desktop, LAN: p.LAN,
			Restricted:   len(p.InboundPorts) > 0,
			InboundPorts: p.InboundPorts,
			Hub:          p.Hub,
			LastSeen:     p.LastSeen,
		}
		row.Services = markReached(p.IP, p.Services, reached)
		if ps, ok := pathByKey[p.WGKey.Hex()]; ok {
			row.Path = ps.Path
			if ps.Addr.IsValid() {
				row.Addr = ps.Addr.String()
			}
			if ps.Latency > 0 {
				row.Latency = ps.Latency.Round(time.Millisecond).String()
			}
		}
		s.Peers = append(s.Peers, row)
	}
	return s
}

// conflictsTTL is how long a conflict check is reused. The check runs `ip
// route` and walks every interface; the console asks for status every few
// seconds, and the answer changes when somebody installs a VPN, not between
// one refresh and the next.
const conflictsTTL = time.Minute

// conflicts is CheckPrefixConflicts, cached for conflictsTTL.
func (e *Engine) conflicts(prefix netip.Prefix, ifName string) []string {
	key := prefix.String() + "|" + ifName
	e.mu.Lock()
	if e.conflictsKey == key && time.Since(e.conflictsAt) < conflictsTTL {
		out := append([]string(nil), e.conflictsCache...)
		e.mu.Unlock()
		return out
	}
	e.mu.Unlock()

	found := CheckPrefixConflicts(prefix, ifName)

	e.mu.Lock()
	e.conflictsKey, e.conflictsAt, e.conflictsCache = key, time.Now(), found
	e.mu.Unlock()
	return append([]string(nil), found...)
}

// tunHint adds a suggestion only when it fits the failure.
//
// The old message appended "(are you running as root/Administrator?)" to every
// error from here. When the real problem was something else it sent people to
// check a thing that was already true, which is worse than saying nothing:
// they stop reading the part of the message that was accurate.
func tunHint(err error) string {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "operation not permitted"),
		strings.Contains(msg, "permission denied"),
		strings.Contains(msg, "access is denied"):
		return " (are you running as root/Administrator?)"
	case strings.Contains(msg, "utun"):
		// The name is chosen by LocNet, not by the operator, so there is
		// nothing for them to fix — say so rather than implying there is.
		return " — this is a LocNet bug, not a setting on this machine;" +
			" please report it with the version from `locnet version`"
	case strings.Contains(msg, "file exists"), strings.Contains(msg, "busy"):
		return " (an interface from a previous run may still exist; try `locnet down` first)"
	}
	return ""
}

func (e *Engine) setLastError(msg string) {
	e.mu.Lock()
	e.lastErr = msg
	e.mu.Unlock()
}

// Compute returns this machine's compute configuration.
func (e *Engine) Compute() resource.ComputeConfig {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.st.Compute
}

// SetCompute replaces the compute configuration and pushes it everywhere it
// is needed.
func (e *Engine) SetCompute(cfg resource.ComputeConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	e.mu.Lock()
	e.st.Compute = cfg
	st := *e.st
	shareSrv := e.shareSrv
	e.mu.Unlock()

	if err := SaveState(e.dir, &st); err != nil {
		return err
	}
	if shareSrv != nil {
		shareSrv.setCompute(cfg)
	}
	go e.reportSoon()
	if cfg.Enabled {
		e.logf("compute: enabled for %s, running as %s", cfg.AllowText(), runAsText(cfg))
	} else {
		e.logf("compute: disabled")
	}
	return nil
}

func runAsText(cfg resource.ComputeConfig) string {
	if cfg.RunAs != "" {
		return cfg.RunAs
	}
	return "the locnetd account"
}

// SetManageHosts turns the hosts-file block on or off and persists the choice.
func (e *Engine) SetManageHosts(on bool) error {
	e.mu.Lock()
	e.st.ManageHosts = on
	st := *e.st
	nm := e.nm
	e.mu.Unlock()

	if err := SaveState(e.dir, &st); err != nil {
		return err
	}
	if on && nm != nil {
		return writeHosts(nm)
	}
	if !on {
		return clearHosts()
	}
	return nil
}

// ------------------------------------------------------------- helpers

func (e *Engine) cachedNetMap(st *State) (*netmap.NetMap, error) {
	if len(st.CachedNetMap) == 0 {
		return nil, errors.New("no cached network map — run `locnet join <code>` first")
	}
	var signed netmap.Signed
	if err := json.Unmarshal(st.CachedNetMap, &signed); err != nil {
		return nil, fmt.Errorf("cached network map is corrupt: %w", err)
	}
	fp, err := st.Fingerprint()
	if err != nil {
		return nil, err
	}
	return signed.Open(fp)
}

// wgConfig renders the UAPI configuration for a netmap.
//
// Peer endpoints are WireGuard public keys rather than addresses. magicsock's
// ParseEndpoint turns those into managed endpoints, which is what lets it
// choose between a direct path and the relay without WireGuard's involvement.
// wgConfig renders the whole device configuration. It runs exactly once per
// tunnel, when the device is created and has nothing to preserve.
func wgConfig(st *State, nm *netmap.NetMap) string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", st.WGKey.Hex())
	fmt.Fprintf(&b, "listen_port=%d\n", st.ListenPort)
	b.WriteString("replace_peers=true\n")

	for k, ip := range wgPeers(nm) {
		writeWGPeer(&b, k, ip)
	}
	return b.String()
}

// wgPeers reduces a netmap to what WireGuard itself needs: which keys are
// peers, and which overlay address each one owns.
//
// Everything else in the map — load averages, share lists, when a machine was
// last seen — changes constantly and means nothing to the tunnel. Separating
// the two is what makes it possible to tell a netmap that matters from one
// that does not.
func wgPeers(nm *netmap.NetMap) map[key.WGPublic]netip.Addr {
	out := make(map[key.WGPublic]netip.Addr, len(nm.Peers))
	for _, p := range nm.Peers {
		if p.WGKey.IsZero() || !p.IP.IsValid() {
			continue
		}
		out[p.WGKey] = p.IP
	}
	return out
}

// wgUpdate renders the configuration that turns prev into next, and returns
// "" when the two describe the same tunnel.
//
// It exists because the obvious implementation — re-send the whole config on
// every netmap — is quietly destructive. `replace_peers=true` makes
// wireguard-go drop every peer and build new ones, which discards the session
// keys, the handshake state and the packets queued behind them; `listen_port=`
// makes it close and reopen the UDP socket whether or not the port changed.
// The netmap version bumps every time any machine reports its load, so a
// three-machine network was rebuilding its tunnels every few seconds and
// spending much of its life waiting on a fresh handshake. That is what "shows
// connected but will not ping" looked like from the outside.
func wgUpdate(prev, next map[key.WGPublic]netip.Addr) string {
	var b strings.Builder
	for k := range prev {
		if _, still := next[k]; !still {
			fmt.Fprintf(&b, "public_key=%s\nremove=true\n", k.Hex())
		}
	}
	for k, ip := range next {
		if was, ok := prev[k]; ok && was == ip {
			continue
		}
		writeWGPeer(&b, k, ip)
	}
	return b.String()
}

// writeWGPeer emits one peer's configuration.
//
// The endpoint is the peer's own WireGuard key rather than an address:
// magicsock parses it back into a handle whose address is resolved at send
// time, which is what lets a peer move networks without WireGuard noticing.
func writeWGPeer(b *strings.Builder, k key.WGPublic, ip netip.Addr) {
	epKey, _ := k.MarshalText()
	fmt.Fprintf(b, "public_key=%s\n", k.Hex())
	fmt.Fprintf(b, "endpoint=%s\n", epKey)
	b.WriteString("replace_allowed_ips=true\n")
	fmt.Fprintf(b, "allowed_ip=%s/32\n", ip)
	fmt.Fprintf(b, "persistent_keepalive_interval=%d\n", keepalive)
}

func resolveUDP(hostPort string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(hostPort); err == nil {
		return ap, nil
	}
	host, port, err := net.SplitHostPort(stripScheme(hostPort))
	if err != nil {
		return netip.AddrPort{}, err
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	for _, a := range addrs {
		if ip, err := netip.ParseAddr(a); err == nil {
			ap, err := netip.ParseAddrPort(net.JoinHostPort(ip.String(), port))
			if err == nil {
				return ap, nil
			}
		}
	}
	return netip.AddrPort{}, fmt.Errorf("no usable address for %q", hostPort)
}

func stripScheme(s string) string {
	if i := strings.Index(s, "://"); i >= 0 {
		return s[i+3:]
	}
	return s
}

// plainRetry is how long a bare address that answered in plain HTTP is
// spoken to that way before TLS is tried on it again — so an agent notices
// within minutes that its hub has been upgraded, even before a netmap says.
const plainRetry = 10 * time.Minute

// hubRoute is how one hub address is reached.
type hubRoute struct {
	url    string // scheme://host:port
	client *http.Client
	// transport is what Status reports: "tls", "https" or "http".
	transport string
	// fallBack allows plain HTTP if the hub turns out to be too old for TLS.
	fallBack bool
}

// joinPinKey carries a joinPin in a request context.
type joinPinKey struct{}

// joinPin is the hub identity a join in progress talks to: the code's, not
// the state file's.
type joinPin struct {
	fp       [16]byte
	required bool
	sawTLS   atomic.Bool
}

// pin returns the fingerprint to pin the hub to, whether TLS is required,
// and false when there is none — before the first join, or in tests.
func (e *Engine) pin(ctx context.Context) (fp [16]byte, required, ok bool) {
	if jp, _ := ctx.Value(joinPinKey{}).(*joinPin); jp != nil {
		return jp.fp, jp.required, true
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.st.HubFingerprint == "" {
		return fp, false, false
	}
	fp, err := e.st.Fingerprint()
	if err != nil {
		return fp, false, false
	}
	return fp, e.st.HubTLS, true
}

// route decides how to reach a hub address.
//
// A bare host:port — what join codes and netmaps carry — is TLS pinned to
// the hub's fingerprint, and plain HTTP only while this machine has never
// learned the hub does TLS and the hub answers a handshake in plain HTTP.
// An explicit https:// is a TLS proxy with a real certificate, checked the
// usual way; an explicit http:// is the operator choosing the clear.
func (e *Engine) route(ctx context.Context, addr string) hubRoute {
	if strings.HasPrefix(addr, "https://") {
		return hubRoute{url: strings.TrimRight(addr, "/"), client: e.hc, transport: "https"}
	}
	if strings.HasPrefix(addr, "http://") {
		return hubRoute{url: strings.TrimRight(addr, "/"), client: e.hc, transport: "http"}
	}
	plain := hubRoute{url: "http://" + addr, client: e.hc, transport: "http"}
	fp, required, ok := e.pin(ctx)
	if !ok {
		return plain
	}
	if !required && e.knownPlain(addr) {
		return plain
	}
	return hubRoute{url: "https://" + addr, client: e.pinnedClient(fp), transport: "tls", fallBack: !required}
}

// pinnedClient returns the client for TLS pinned to fp, made once per
// fingerprint so connections are reused.
func (e *Engine) pinnedClient(fp [16]byte) *http.Client {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.pinnedHC == nil || e.pinnedFP != fp {
		e.pinnedHC = &http.Client{
			Timeout:   40 * time.Second,
			Transport: hubtls.NewTransport(fp, newHubTransport()),
		}
		e.pinnedFP = fp
	}
	return e.pinnedHC
}

func (e *Engine) knownPlain(addr string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	at, ok := e.plainHubs[addr]
	return ok && time.Since(at) < plainRetry
}

func (e *Engine) notePlainHub(addr string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.plainHubs == nil {
		e.plainHubs = map[string]time.Time{}
	}
	if _, seen := e.plainHubs[addr]; !seen {
		e.logf("hub %s does not speak TLS (it is older than 0.10.4); using plain HTTP until it is upgraded", addr)
	}
	e.plainHubs[addr] = time.Now()
}

// noteTransport records how the hub answered, and remembers for good that it
// does TLS once a pinned handshake has worked.
func (e *Engine) noteTransport(ctx context.Context, r hubRoute) {
	jp, _ := ctx.Value(joinPinKey{}).(*joinPin)
	if jp != nil {
		if r.transport == "tls" {
			jp.sawTLS.Store(true)
		}
		return
	}
	e.mu.Lock()
	e.hubTransport = r.transport
	if r.transport != "tls" || e.st.HubTLS || e.st.HubFingerprint == "" {
		e.mu.Unlock()
		return
	}
	e.st.HubTLS = true
	st := *e.st
	e.mu.Unlock()
	e.logf("hub: control plane encrypted (TLS pinned to the hub's fingerprint)")
	if err := SaveState(e.dir, &st); err != nil {
		e.logf("could not remember that the hub speaks TLS: %v", err)
	}
}

// send makes one request to one hub address. path includes the API version.
func (e *Engine) send(ctx context.Context, method, addr, path string, body []byte, sign bool) (*http.Response, error) {
	r := e.route(ctx, addr)
	resp, err := e.sendVia(ctx, r, method, path, body, sign)
	if err != nil && r.transport == "tls" && hubtls.IsPlainServer(err) {
		if !r.fallBack {
			return nil, fmt.Errorf("the hub at %s answered in plain HTTP, but it is known to speak TLS — "+
				"refusing to talk to it in the clear. If the hub really was downgraded below 0.10.4, "+
				"upgrade it again: %w", addr, err)
		}
		// The handshake failed before any request was sent, so the
		// retry is not a replay.
		e.notePlainHub(addr)
		r = hubRoute{url: "http://" + addr, client: e.hc, transport: "http"}
		resp, err = e.sendVia(ctx, r, method, path, body, sign)
	}
	if err == nil {
		e.noteTransport(ctx, r)
	}
	return resp, err
}

func (e *Engine) sendVia(ctx context.Context, r hubRoute, method, path string, body []byte, sign bool) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, r.url+path, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if sign {
		e.sign(req, body)
	}
	return r.client.Do(req)
}

// hubOrder returns the addresses to try, the one that last worked first.
func (e *Engine) hubOrder() []string {
	e.mu.Lock()
	defer e.mu.Unlock()

	all := e.st.Hubs()
	pref := e.hubPref
	if pref == "" {
		return append([]string(nil), all...)
	}
	out := make([]string, 0, len(all))
	out = append(out, pref)
	for _, a := range all {
		if a != pref {
			out = append(out, a)
		}
	}
	return out
}

// currentHub names the address in use, for status output.
func (e *Engine) currentHub() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.hubPref != "" {
		return e.hubPref
	}
	if h := e.st.Hubs(); len(h) > 0 {
		return h[0]
	}
	return ""
}

// noteHub records which address answered, so the next request starts there.
func (e *Engine) noteHub(addr string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.hubPref != addr {
		if e.hubPref != "" {
			e.logf("hub: switched to %s", addr)
		}
		e.hubPref = addr
	}
}

// hubGet and hubPost try each candidate address in turn.
//
// Walking the list on every failure is what makes a machine survive moving
// between networks: the address that worked at home stops answering, the next
// one does, and nothing had to be reconfigured. Only a transport failure moves
// on to the next address — an answer from the hub, even an error, means we
// found it.
func (e *Engine) hubGet(ctx context.Context, path string, out any) error {
	return e.tryHubs(ctx, func(addr string) error {
		return e.getJSON(ctx, addr, path, out)
	})
}

func (e *Engine) hubPost(ctx context.Context, path string, in any) error {
	return e.tryHubs(ctx, func(addr string) error {
		return e.postJSON(ctx, addr, path, in, nil, true)
	})
}

func (e *Engine) tryHubs(ctx context.Context, do func(addr string) error) error {
	addrs := e.hubOrder()
	if len(addrs) == 0 {
		return errors.New("no hub address configured")
	}

	// The address that answered last time is tried on its own first: it is
	// right almost always, and costs one request.
	e.mu.Lock()
	pref := e.hubPref
	e.mu.Unlock()
	var firstErr error
	if pref != "" {
		err := do(pref)
		if err == nil || !isUnreachable(err) || ctx.Err() != nil {
			if err == nil {
				e.noteHub(pref)
			}
			return err
		}
		firstErr = err
		addrs = addrs[1:]
		if len(addrs) == 0 {
			e.forgetHub(pref)
			return err
		}
	}

	// It did not answer, or nothing has yet. Rather than walk the rest one
	// dial timeout at a time — five seconds per dead address, paid on every
	// request by a laptop that has just left home and whose first address is
	// now the LAN one — ask all of them at once which is there, and start
	// with that one.
	if len(addrs) > 1 {
		found := e.raceHubs(ctx, addrs)
		if found == "" {
			if firstErr == nil {
				firstErr = errors.New("no address answered")
			}
			e.forgetHub(pref)
			return fmt.Errorf("none of the %d hub addresses answered (%s): %w",
				len(e.hubOrder()), strings.Join(e.hubOrder(), ", "), firstErr)
		}
		reordered := []string{found}
		for _, a := range addrs {
			if a != found {
				reordered = append(reordered, a)
			}
		}
		addrs = reordered
	}

	for _, addr := range addrs {
		err := do(addr)
		if err == nil {
			e.noteHub(addr)
			return nil
		}
		if firstErr == nil {
			firstErr = err
		}
		// An error carrying a reply from the hub is not a reason to try
		// somewhere else — we reached it, and it said no.
		if !isUnreachable(err) {
			return err
		}
		if ctx.Err() != nil {
			return err
		}
	}
	e.forgetHub(pref)
	if all := e.hubOrder(); len(all) > 1 {
		return fmt.Errorf("none of the %d hub addresses answered (%s): %w",
			len(all), strings.Join(all, ", "), firstErr)
	}
	return firstErr
}

// forgetHub drops the preference for an address that has stopped answering,
// so status stops naming it as the one in use.
func (e *Engine) forgetHub(addr string) {
	if addr == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.hubPref == addr {
		e.hubPref = ""
	}
}

// hubRaceTimeout bounds the parallel search for a hub address that answers.
const hubRaceTimeout = 4 * time.Second

// raceHubs asks every address at once whether the hub is there, and returns
// the first that says so, or "" if none does within hubRaceTimeout.
//
// The question is the unauthenticated health check: it costs the hub nothing,
// carries nothing worth stealing, and a hub that answers it will answer the
// real request.
func (e *Engine) raceHubs(ctx context.Context, addrs []string) string {
	ctx, cancel := context.WithTimeout(ctx, hubRaceTimeout)
	defer cancel()

	answered := make(chan string, len(addrs))
	for _, addr := range addrs {
		go func() {
			resp, err := e.send(ctx, http.MethodGet, addr, "/healthz", nil, false)
			if err != nil {
				answered <- ""
				return
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				answered <- ""
				return
			}
			answered <- addr
		}()
	}
	for range addrs {
		select {
		case a := <-answered:
			if a != "" {
				return a
			}
		case <-ctx.Done():
			return ""
		}
	}
	return ""
}

// isUnreachable distinguishes "could not get there" from "got there and was
// refused". Only the former is worth trying another address for.
func isUnreachable(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var opErr *net.OpError
	return errors.As(err, &opErr)
}

// probeHubs finds which candidate answers, for joining.
func (e *Engine) probeHubs(ctx context.Context, addrs []string) (string, *hubapi.HubInfo, error) {
	if len(addrs) == 0 {
		return "", nil, errors.New("the join code carries no hub address")
	}
	var firstErr error
	for _, addr := range addrs {
		info, err := e.fetchInfo(ctx, addr)
		if err == nil {
			return addr, info, nil
		}
		if firstErr == nil {
			firstErr = err
		}
		e.logf("hub %s did not answer: %v", addr, err)
	}
	if len(addrs) > 1 {
		return "", nil, fmt.Errorf("none of the hub addresses in this code answered (%s).\n"+
			"Check the hub is running and that this machine can reach one of them: %w",
			strings.Join(addrs, ", "), firstErr)
	}
	return "", nil, fmt.Errorf("cannot reach the hub at %s: %w", addrs[0], firstErr)
}

func (e *Engine) fetchInfo(ctx context.Context, hubAddr string) (*hubapi.HubInfo, error) {
	var info hubapi.HubInfo
	if err := e.getJSONUnsigned(ctx, hubAddr, "/info", &info); err != nil {
		return nil, err
	}
	if info.HubKey.IsZero() {
		return nil, errors.New("hub did not present an identity key")
	}
	return &info, nil
}

func (e *Engine) getJSON(ctx context.Context, hubAddr, path string, out any) error {
	return e.call(ctx, http.MethodGet, hubAddr, path, nil, true, out)
}

func (e *Engine) getJSONUnsigned(ctx context.Context, hubAddr, path string, out any) error {
	return e.call(ctx, http.MethodGet, hubAddr, path, nil, false, out)
}

func (e *Engine) postJSON(ctx context.Context, hubAddr, path string, in, out any, sign bool) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	if sign {
		// Makes every signed request unique, so the hub can refuse a replay
		// of one without refusing a genuine repeat.
		body = hubapi.WithNonce(body)
	}
	return e.call(ctx, http.MethodPost, hubAddr, path, body, sign, out)
}

// call sends a request to the API and decodes the answer into out.
func (e *Engine) call(ctx context.Context, method, hubAddr, path string, body []byte, sign bool, out any) error {
	resp, err := e.send(ctx, method, hubAddr, hubapi.APIVersion+path, body, sign)
	if err != nil {
		return err
	}
	return decodeHub(resp, out)
}

// sign attaches this node's identity signature. The path used for signing must
// exclude the query string, matching what the hub verifies.
func (e *Engine) sign(req *http.Request, body []byte) {
	e.mu.Lock()
	nodeID, mk := e.st.NodeID, e.st.MachineKey
	e.mu.Unlock()
	if nodeID == "" {
		return
	}
	hubapi.SignRequest(req, nodeID, mk, body)
}

func decodeHub(resp *http.Response, out any) error {
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		var er hubapi.ErrorResponse
		if json.NewDecoder(resp.Body).Decode(&er) == nil && er.Error != "" {
			return fmt.Errorf("hub: %s", er.Error)
		}
		return fmt.Errorf("hub returned %s", resp.Status)
	}
	// 204 is how the hub says "nothing for you" — an idle queue, a netmap
	// that has not changed. Decoding a body that is empty by definition
	// yields EOF, which then travels up as a hub failure: the agent logged
	// "could not ask the hub for work: EOF" every time it asked and found no
	// work, and tryHubs walked to the next hub address looking for a better
	// answer that does not exist.
	if resp.StatusCode == http.StatusNoContent || out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// portShareTargets maps each published port share to what it forwards to, so
// the service scan can ask the real server whether it is there rather than ask
// our own forwarder, which answers regardless.
func portShareTargets(shares []resource.Share) map[uint16]string {
	out := make(map[uint16]string)
	for _, sh := range shares {
		if sh.Kind != resource.KindPort || sh.Port == 0 {
			continue
		}
		target := sh.Target
		if !strings.Contains(target, ":") {
			target = "127.0.0.1:" + target
		}
		out[sh.Port] = target
	}
	return out
}

// learnHubs merges hub addresses from the netmap into the stored list.
//
// The addresses the join code carried stay first: they are the ones the
// operator chose and the ones known to work from wherever this machine was
// standing when it joined. Anything new is appended, so a standby is tried
// after the primary rather than instead of it.
func (e *Engine) learnHubs(addrs []string) {
	if len(addrs) == 0 {
		return
	}
	e.mu.Lock()
	have := e.st.Hubs()

	// The signed map is authoritative about which addresses are hubs, so this
	// is a reconciliation and not only an addition. Appending forever left
	// dead addresses at the head of the list — a machine whose home IP had
	// changed months earlier still tried the old one first and paid a dial
	// timeout on every single hub request before falling through to the one
	// that works.
	//
	// The exception is whichever address is answering right now. It has just
	// proved itself, and cutting the branch we are sitting on to obey a map
	// we only have *because* of that address would be a fine way to strand a
	// node permanently.
	merged := make([]string, 0, len(addrs)+1)
	seen := make(map[string]bool, len(addrs)+1)
	for _, a := range addrs {
		if a = strings.TrimSpace(a); a == "" || seen[a] {
			continue
		}
		seen[a] = true
		merged = append(merged, a)
	}
	if e.hubPref != "" && !seen[e.hubPref] {
		merged = append(merged, e.hubPref)
	}

	if slices.Equal(have, merged) {
		e.mu.Unlock()
		return
	}
	e.st.SetHubs(merged)
	st := *e.st
	e.mu.Unlock()

	if err := SaveState(e.dir, &st); err != nil {
		e.logf("could not remember the new hub address: %v", err)
		return
	}
	e.logf("hub addresses are now %s", strings.Join(merged, ", "))
}
