// Package magicsock is the UDP socket LocNet gives to WireGuard.
//
// It implements wireguard-go's conn.Bind interface, which means WireGuard
// hands it packets to send and takes packets it produces, without knowing that
// anything unusual is happening underneath. What happens underneath is the
// interesting part:
//
//   - Discovery probes and WireGuard traffic share one UDP port, so a NAT hole
//     punched by a probe is usable by the tunnel.
//   - Every peer is addressed by its WireGuard public key rather than by an
//     IP. Where that key currently lives is magicsock's problem, not
//     WireGuard's, so a peer can move between networks mid-connection and the
//     tunnel does not notice.
//   - Traffic starts on the relay and upgrades itself to a direct path the
//     moment one is proven to work. Connectivity is immediate; speed arrives a
//     second later.
//
// The upgrade is one-way in the sense that matters: a direct path is only
// adopted after a signed round trip over it, and abandoned if it goes quiet.
// There is no state in which a peer is unreachable while a working relay
// exists.
package magicsock

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mahantsunandan/locnet/internal/disco"
	"github.com/mahantsunandan/locnet/internal/key"
	"golang.zx2c4.com/wireguard/conn"
)

const (
	// probeIntervalSearching is how often to probe candidate paths while a
	// peer has no direct path. Aggressive: both ends must have packets in
	// flight at the same time for a hole punch to land.
	probeIntervalSearching = 2 * time.Second
	// probeIntervalEstablished keeps a working direct path's NAT mapping
	// alive and detects when it stops working.
	probeIntervalEstablished = 15 * time.Second
	// directPathTimeout is how long a direct path may go unanswered before
	// we fall back to the relay.
	directPathTimeout = 35 * time.Second
	// relayPathTimeout is how long a peer may go without any packet, by any
	// route, before its path stops being reported as a working relay. Probes
	// go out over the relay every few seconds, so silence this long means the
	// relay is not carrying anything either.
	relayPathTimeout = 35 * time.Second
	// relayBindInterval refreshes our mapping at the relay. Must be well
	// under the shortest common NAT UDP timeout, which is around 30s.
	relayBindInterval = 20 * time.Second
	// relayDeadTimeout is how long the chosen relay may go without answering
	// a bind before we start looking at the other advertised addresses again.
	// Three missed refreshes: long enough not to flap on packet loss.
	relayDeadTimeout = 70 * time.Second
	// maxCandidates caps how many addresses we will probe for one peer, so a
	// misconfigured or hostile netmap cannot turn us into a packet cannon.
	maxCandidates = 16
	// maxBareEndpoints caps the cache of endpoints for unattributed source
	// addresses, whose keys are chosen by whoever can reach this port.
	maxBareEndpoints = 1024
)

// Logf is a printf-style logging function.
type Logf func(format string, args ...any)

// PeerConfig is what magicsock needs to know about one peer. It comes
// straight from the signed netmap.
type PeerConfig struct {
	NodeID    string
	WGKey     key.WGPublic
	DiscoKey  key.DiscoPublic
	Endpoints []netip.AddrPort
}

// PeerStatus is a snapshot for `locnet status`.
type PeerStatus struct {
	NodeID  string
	WGKey   key.WGPublic
	Path    string // "direct", "relay", or "connecting"
	Addr    netip.AddrPort
	Latency time.Duration
	LastRx  time.Time
}

// Options configure a Conn.
type Options struct {
	// NodeID and MachineKey authenticate this node to the relay.
	NodeID     string
	MachineKey key.MachinePrivate
	// WGKey is our own WireGuard public key, echoed in probes so peers can
	// tell which node a probe came from.
	WGKey key.WGPublic
	// DiscoKey seals probes.
	DiscoKey key.DiscoPrivate
	Logf     Logf
}

// Conn is the shared UDP socket. It satisfies conn.Bind.
type Conn struct {
	opts Options
	logf Logf

	closed atomic.Bool
	// done is closed by Close and replaced by Open. wireguard-go closes and
	// reopens the bind on every BindUpdate — which it does at least twice
	// while a device starts — so this must survive being cycled. A one-shot
	// guard here leaves the second socket never closed and the maintenance
	// loop dead, which looks like a tunnel that comes up and then does
	// nothing.
	done chan struct{}

	mu    sync.Mutex
	pconn *net.UDPConn
	port  uint16
	// peers is keyed by WireGuard public key: the identity WireGuard itself
	// uses, so lookups from both directions agree.
	peers map[key.WGPublic]*peer
	// addrToPeer maps a proven source address back to a peer, so an inbound
	// packet can be attributed without decrypting it.
	addrToPeer map[netip.AddrPort]key.WGPublic
	bareEps    map[netip.AddrPort]*bareEndpoint

	// relayCands are every address the hub says it relays on, best first.
	// relayAddr is the one that has actually answered. They differ more often
	// than they should: a hub advertises its public address first, and from
	// inside its own LAN that address is only reachable if the router
	// hairpins — which many do not.
	relayCands []netip.AddrPort
	relayAddr  netip.AddrPort
	// relayNonces maps an outstanding bind's nonce to the candidate it was
	// sent to, so a reply says which address answered rather than merely
	// that one did.
	relayNonces map[uint64]netip.AddrPort
	relayHeard  time.Time
	observed    netip.AddrPort
	localEps    []netip.AddrPort
	// overlay is the tunnel's own address range. Addresses inside it are
	// never candidate paths — see LocalEndpoints.
	overlay netip.Prefix
}

// New creates an unopened Conn. WireGuard calls Open when the device starts.
func New(opts Options) *Conn {
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Conn{
		opts:        opts,
		logf:        logf,
		peers:       make(map[key.WGPublic]*peer),
		addrToPeer:  make(map[netip.AddrPort]key.WGPublic),
		bareEps:     make(map[netip.AddrPort]*bareEndpoint),
		relayNonces: make(map[uint64]netip.AddrPort),
	}
}

// ------------------------------------------------------------- conn.Bind

// Open binds the shared UDP socket and starts the maintenance loop.
func (c *Conn) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pconn != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	// A dual-stack socket lets one port serve v4 and v6 peers. Some
	// environments refuse it; falling back to v4-only is better than
	// failing to start, and IPv4 is where the NAT problems live anyway.
	pc, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(port)})
	if err != nil {
		pc, err = net.ListenUDP("udp4", &net.UDPAddr{Port: int(port)})
		if err != nil {
			return nil, 0, fmt.Errorf("magicsock: listen on port %d: %w", port, err)
		}
		c.logf("magicsock: dual-stack bind failed, running IPv4-only")
	}
	c.pconn = pc
	c.port = uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	c.closed.Store(false)

	// A fresh channel per Open, handed to the loop it belongs to, so a
	// maintenance loop from an earlier generation cannot outlive its socket
	// and a new one is not stopped by an old Close.
	c.done = make(chan struct{})
	go c.maintain(c.done)

	return []conn.ReceiveFunc{c.receive}, c.port, nil
}

// Close shuts the socket down. Receive functions return net.ErrClosed after
// this returns.
func (c *Conn) Close() error {
	c.mu.Lock()
	pc := c.pconn
	c.pconn = nil
	done := c.done
	c.done = nil
	c.mu.Unlock()

	c.closed.Store(true)
	if done != nil {
		close(done)
	}
	if pc == nil {
		// Already closed, or never opened. Both are fine: wireguard-go
		// calls Close on binds it never managed to open.
		return nil
	}
	return pc.Close()
}

// SetMark is a Linux routing feature LocNet does not use.
func (c *Conn) SetMark(uint32) error { return nil }

// BatchSize is 1: LocNet does not use segmentation offload. Each call moves
// one packet, which costs throughput on very fast links and buys a receive
// path simple enough to reason about.
func (c *Conn) BatchSize() int { return 1 }

// ParseEndpoint turns the string WireGuard was configured with into an
// endpoint. LocNet configures peers with a base64 WireGuard public key rather
// than an IP, because the whole point is that the address is not fixed.
func (c *Conn) ParseEndpoint(s string) (conn.Endpoint, error) {
	var k key.WGPublic
	if err := k.UnmarshalText([]byte(s)); err != nil {
		// Also accept a literal address, which makes the socket usable
		// with a hand-written WireGuard config for debugging.
		if ap, apErr := netip.ParseAddrPort(s); apErr == nil {
			return c.bareEndpoint(canon(ap)), nil
		}
		return nil, fmt.Errorf("magicsock: endpoint %q is neither a WireGuard key nor an address: %w", s, err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peerLocked(k).ep, nil
}

// Send transmits bufs to ep, choosing the direct path if one is proven and
// the relay otherwise.
func (c *Conn) Send(bufs [][]byte, ep conn.Endpoint) error {
	if c.closed.Load() {
		return net.ErrClosed
	}
	switch e := ep.(type) {
	case *bareEndpoint:
		// WireGuard pins a peer to whatever endpoint its last inbound packet
		// carried, and a packet from an address we had not yet tied to a peer
		// arrives as a bare address. Left alone that pin is permanent: every
		// later packet goes straight to that address, bypassing path
		// selection, so when the peer moves to another network the tunnel
		// dies with a relay sitting unused and the status output still saying
		// "relay". Resolving the address back to its peer on each send is
		// what makes the fallback real.
		if p := c.peerForAddr(e.addr); p != nil {
			return c.sendToPeer(bufs, p)
		}
		for _, b := range bufs {
			if err := c.sendRaw(b, e.addr); err != nil {
				return err
			}
		}
		return nil
	case *peerEndpoint:
		return c.sendToPeer(bufs, e.p)
	default:
		return conn.ErrWrongEndpointType
	}
}

// peerForAddr returns the peer known to live at addr, or nil.
func (c *Conn) peerForAddr(addr netip.AddrPort) *peer {
	c.mu.Lock()
	defer c.mu.Unlock()
	k, ok := c.addrToPeer[addr]
	if !ok {
		return nil
	}
	return c.peers[k]
}

func (c *Conn) sendToPeer(bufs [][]byte, p *peer) error {
	direct, ok := p.directPath()
	if ok {
		var firstErr error
		for _, b := range bufs {
			if err := c.sendRaw(b, direct); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if firstErr == nil {
			return nil
		}
		// A direct path that refuses writes is not a path. Drop it now so
		// the next packet takes the relay instead of failing again.
		p.clearDirect()
		c.logf("magicsock: direct path to %s failed (%v), falling back to relay", p.name(), firstErr)
	}

	c.mu.Lock()
	relay := c.relayAddr
	c.mu.Unlock()
	if !relay.IsValid() {
		return fmt.Errorf("magicsock: no path to %s: no direct route and no relay configured", p.name())
	}
	for _, b := range bufs {
		frame := disco.EncodeForward(p.wgKey, c.opts.WGKey, b)
		if err := c.sendRaw(frame, relay); err != nil {
			return err
		}
	}
	return nil
}

func (c *Conn) sendRaw(b []byte, to netip.AddrPort) error {
	c.mu.Lock()
	pc := c.pconn
	c.mu.Unlock()
	if pc == nil {
		return net.ErrClosed
	}
	_, err := pc.WriteToUDPAddrPort(b, to)
	return err
}

// receive reads until it has a packet WireGuard should see. Disco packets are
// consumed here and never surface to WireGuard.
func (c *Conn) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	for {
		if c.closed.Load() {
			return 0, net.ErrClosed
		}
		c.mu.Lock()
		pc := c.pconn
		c.mu.Unlock()
		if pc == nil {
			return 0, net.ErrClosed
		}

		n, src, err := pc.ReadFromUDPAddrPort(packets[0])
		if err != nil {
			if c.closed.Load() {
				return 0, net.ErrClosed
			}
			return 0, err
		}
		src = canon(src)
		pkt := packets[0][:n]

		if !disco.IsDisco(pkt) {
			// A plain WireGuard packet arriving directly.
			sizes[0] = n
			eps[0] = c.endpointForAddr(src)
			return 1, nil
		}

		wgPayload, from, ok := c.handleDisco(pkt, src)
		if !ok {
			continue // consumed, or junk
		}
		// A WireGuard packet that came through the relay. Move it to the
		// front of the caller's buffer and report the peer it came from.
		copy(packets[0], wgPayload)
		sizes[0] = len(wgPayload)
		eps[0] = from
		return 1, nil
	}
}

// handleDisco processes one disco packet. It returns a WireGuard payload when
// the packet was a relayed tunnel packet, and ok=false when there is nothing
// for WireGuard to see.
func (c *Conn) handleDisco(pkt []byte, src netip.AddrPort) (payload []byte, ep conn.Endpoint, ok bool) {
	typ, body, err := disco.Type(pkt)
	if err != nil {
		return nil, nil, false
	}

	switch typ {
	case disco.TypeBindReply:
		r, err := disco.ParseBindReply(body)
		if err != nil {
			return nil, nil, false
		}
		c.noteBindReply(r, src)

	case disco.TypeForwarded:
		srcKey, inner, err := disco.ParseForwarded(body)
		if err != nil {
			return nil, nil, false
		}
		c.mu.Lock()
		p := c.peerLocked(srcKey)
		c.mu.Unlock()
		p.noteRx()
		if disco.IsDisco(inner) {
			// A probe that took the relay because no direct path existed
			// yet. Handle it, but attribute it to the relay, not to a
			// direct address — it proves nothing about direct reachability.
			c.handleDiscoFromRelay(inner, p)
			return nil, nil, false
		}
		return inner, p.ep, true

	case disco.TypePing:
		c.handlePing(body, src, false)

	case disco.TypePong:
		c.handlePong(body, src)
	}
	return nil, nil, false
}

// noteBindReply records that a relay candidate answered, and adopts it when we
// have none or when the one we had has gone quiet.
//
// The reply is matched to the bind that caused it by nonce, so the address we
// adopt is the one we sent to. Believing the source address instead would let
// anything on the path nominate itself as our relay.
func (c *Conn) noteBindReply(r *disco.BindReply, src netip.AddrPort) {
	c.mu.Lock()
	defer c.mu.Unlock()

	cand, ok := c.relayNonces[r.Nonce]
	if !ok {
		return // stale or unsolicited
	}
	delete(c.relayNonces, r.Nonce)
	if cand != src {
		return // answered from somewhere other than where we asked
	}

	adopt := c.relayAddr != cand &&
		(!c.relayAddr.IsValid() || time.Since(c.relayHeard) > relayDeadTimeout)
	if adopt {
		c.relayAddr = cand
		c.observed = netip.AddrPort{}
		c.logf("magicsock: relaying through %s", cand)
	}
	if c.relayAddr != cand {
		return // a working relay answered too; nothing more to learn from it
	}
	c.relayHeard = time.Now()
	if r.Observed.IsValid() && c.observed != canon(r.Observed) {
		c.observed = canon(r.Observed)
		c.logf("magicsock: relay sees us at %s", c.observed)
	}
}

// handleDiscoFromRelay processes a probe that arrived wrapped in a relay
// frame. Such a probe must never be treated as evidence of a direct path.
func (c *Conn) handleDiscoFromRelay(inner []byte, from *peer) {
	typ, body, err := disco.Type(inner)
	if err != nil {
		return
	}
	switch typ {
	case disco.TypePing:
		c.handlePing(body, netip.AddrPort{}, true)
	case disco.TypePong:
		// A pong that came back by relay says nothing about the direct
		// path it was sent on, so it is deliberately ignored for path
		// selection. It still proves the peer is alive.
		from.noteRx()
	}
}

func (c *Conn) handlePing(body []byte, src netip.AddrPort, viaRelay bool) {
	ping, err := disco.OpenPing(body, c.opts.DiscoKey)
	if err != nil {
		return
	}
	c.mu.Lock()
	p := c.peerLocked(ping.WGKey)
	c.mu.Unlock()
	peerDisco := p.disco()
	if peerDisco.IsZero() {
		// A ping from a node not in our netmap. It authenticated, which
		// means it holds a disco key we sealed to — but we have no
		// configuration for it, so there is nothing useful to answer.
		return
	}
	p.noteRx()
	if src.IsValid() && !viaRelay {
		c.noteAddrForPeer(src, ping.WGKey)
	}

	pong := &disco.Pong{TxID: ping.TxID, WGKey: c.opts.WGKey, Src: src}
	out, err := disco.EncodePong(pong, c.opts.DiscoKey, peerDisco)
	if err != nil {
		return
	}
	if viaRelay || !src.IsValid() {
		c.mu.Lock()
		relay := c.relayAddr
		c.mu.Unlock()
		if relay.IsValid() {
			_ = c.sendRaw(disco.EncodeForward(p.wgKey, c.opts.WGKey, out), relay)
		}
		return
	}
	_ = c.sendRaw(out, src)
}

func (c *Conn) handlePong(body []byte, src netip.AddrPort) {
	pong, err := disco.OpenPong(body, c.opts.DiscoKey)
	if err != nil {
		return
	}
	c.mu.Lock()
	p := c.peerLocked(pong.WGKey)
	c.mu.Unlock()

	proven, rtt, switched, ok := p.completePing(pong.TxID, src)
	if !ok {
		return // unsolicited, or a reply that proves nothing about a path
	}
	c.noteAddrForPeer(src, pong.WGKey)
	if proven != src {
		// Symmetric NAT: their reply left from a different mapping than
		// the one we aimed at. Both addresses belong to this peer.
		c.noteAddrForPeer(proven, pong.WGKey)
	}

	// A pong tells us how a peer sees our source address. Peers behind
	// different NATs may see us differently; the relay's view is the one we
	// publish, so this is only recorded when we have nothing better.
	if pong.Src.IsValid() {
		c.mu.Lock()
		if !c.observed.IsValid() {
			c.observed = canon(pong.Src)
		}
		c.mu.Unlock()
	}
	if switched {
		c.logf("magicsock: direct path to %s via %s (%v)", p.name(), proven, rtt.Round(time.Millisecond))
	}
}

func (c *Conn) noteAddrForPeer(addr netip.AddrPort, k key.WGPublic) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.addrToPeer[addr] = k
}

// endpointForAddr attributes an inbound direct packet. Unknown sources get a
// plain address endpoint: WireGuard will decrypt the packet, discover which
// peer it belongs to, and reply to that address. That is a working state, and
// the next probe exchange promotes it to a managed peer endpoint.
func (c *Conn) endpointForAddr(src netip.AddrPort) conn.Endpoint {
	c.mu.Lock()
	defer c.mu.Unlock()
	if k, ok := c.addrToPeer[src]; ok {
		p := c.peerLocked(k)
		p.noteRx()
		return p.ep
	}
	return c.bareEndpoint(src)
}

// bareEndpoint returns the cached endpoint for a raw address. Caching keeps
// WireGuard's endpoint comparisons stable and avoids an allocation per packet.
// Callers must hold c.mu.
//
// The cache is bounded because its keys come from the network: anything that
// can send a packet to this port and be mistaken for WireGuard adds an entry,
// and an unbounded map fed by strangers is a way to run a machine out of
// memory. Dropping the cache costs nothing but a re-allocation.
func (c *Conn) bareEndpoint(addr netip.AddrPort) *bareEndpoint {
	if e, ok := c.bareEps[addr]; ok {
		return e
	}
	if len(c.bareEps) >= maxBareEndpoints {
		clear(c.bareEps)
	}
	e := &bareEndpoint{addr: addr}
	c.bareEps[addr] = e
	return e
}

// peerLocked returns the peer for k, creating a placeholder if the netmap has
// not described it yet. Callers must hold c.mu.
func (c *Conn) peerLocked(k key.WGPublic) *peer {
	if p, ok := c.peers[k]; ok {
		return p
	}
	p := newPeer(k)
	c.peers[k] = p
	return p
}

// -------------------------------------------------------------- control

// SetPeers replaces the peer set from a freshly applied netmap. Peers that
// disappear are dropped along with any paths learned for them.
func (c *Conn) SetPeers(cfgs []PeerConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()

	seen := make(map[key.WGPublic]bool, len(cfgs))
	for _, cfg := range cfgs {
		if len(cfg.Endpoints) > maxCandidates {
			cfg.Endpoints = cfg.Endpoints[:maxCandidates]
		}
		for i := range cfg.Endpoints {
			cfg.Endpoints[i] = canon(cfg.Endpoints[i])
		}
		p := c.peerLocked(cfg.WGKey)
		p.setConfig(cfg)
		seen[cfg.WGKey] = true
	}
	for k := range c.peers {
		if !seen[k] {
			delete(c.peers, k)
		}
	}
	for addr, k := range c.addrToPeer {
		if !seen[k] {
			delete(c.addrToPeer, addr)
		}
	}
}

// SetRelay points the socket at a single relay. It is SetRelays for the one
// case where there is nothing to choose between.
func (c *Conn) SetRelay(addr netip.AddrPort) {
	if !addr.IsValid() {
		c.SetRelays(nil)
		return
	}
	c.SetRelays([]netip.AddrPort{addr})
}

// SetRelays offers the socket every address the hub relays on, best first.
// Passing none disables relaying, leaving direct paths as the only option.
//
// All of them are tried, and the one that answers is used. Taking the first
// address on faith is how a node ends up with no fallback path at all while
// the status output cheerfully reports "relay": the hub's public address is
// listed first and is the right answer for machines elsewhere, but from
// inside the hub's own LAN it only works if the router hairpins.
func (c *Conn) SetRelays(addrs []netip.AddrPort) {
	cands := make([]netip.AddrPort, 0, len(addrs))
	seen := make(map[netip.AddrPort]bool, len(addrs))
	for _, a := range addrs {
		a = canon(a)
		if !a.IsValid() || seen[a] {
			continue
		}
		seen[a] = true
		cands = append(cands, a)
	}

	c.mu.Lock()
	if slicesEqual(c.relayCands, cands) {
		c.mu.Unlock()
		return
	}
	c.relayCands = cands
	if !seen[c.relayAddr] {
		// The relay we were using is no longer offered.
		c.relayAddr = netip.AddrPort{}
		c.observed = netip.AddrPort{}
		c.relayHeard = time.Time{}
	}
	c.mu.Unlock()

	c.logf("magicsock: relay candidates: %s", joinAddrs(cands))
	// Bind immediately rather than waiting for the next tick. The relay
	// addresses usually arrive with the first netmap, and until we have bound
	// we have neither a fallback path nor any idea of our public address —
	// twenty seconds of that at every startup would be visible as a stall.
	if len(cands) > 0 {
		go c.sendRelayBind()
	}
}

// Relay returns the relay currently in use, which is the candidate that last
// answered a bind. The zero value means no relay has answered — a state worth
// showing, because it is the difference between a fallback path and the belief
// that there is one.
func (c *Conn) Relay() netip.AddrPort {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.relayAddr.IsValid() || time.Since(c.relayHeard) > relayDeadTimeout {
		return netip.AddrPort{}
	}
	return c.relayAddr
}

// relayAnswered reports whether a relay is bound and has answered recently.
func (c *Conn) relayAnswered() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.relayAddr.IsValid() && time.Since(c.relayHeard) <= relayDeadTimeout
}

// Observed returns our public address as reported by the relay, if known.
func (c *Conn) Observed() netip.AddrPort {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.observed
}

// SetOverlay tells the socket which address range belongs to the tunnel, so
// it can keep those addresses out of the candidate paths it advertises.
func (c *Conn) SetOverlay(p netip.Prefix) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.overlay = p
}

// LocalEndpoints lists the addresses this node can be reached at on its own
// networks, for peers on the same LAN to try first.
func (c *Conn) LocalEndpoints() []netip.AddrPort {
	c.mu.Lock()
	port := c.port
	overlay := c.overlay
	c.mu.Unlock()
	if port == 0 {
		return nil
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []netip.AddrPort
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			// Link-local v6 needs a zone to be usable and v4 link-local
			// is a sign of a failed DHCP, not a route to anywhere.
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
				continue
			}
			// Never advertise an address inside the overlay. It is the
			// tunnel's own address, so a peer probing it would be trying to
			// reach the tunnel through the tunnel — and a reply that did
			// arrive would report an overlay source, which then looks like
			// this machine's public address. Confusing to read and useless
			// as a path.
			if overlay.IsValid() && overlay.Contains(ip) {
				continue
			}
			out = append(out, netip.AddrPortFrom(ip, port))
		}
	}
	return out
}

// Port returns the bound UDP port.
func (c *Conn) Port() uint16 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.port
}

// Status snapshots every peer's current path.
func (c *Conn) Status() []PeerStatus {
	c.mu.Lock()
	peers := make([]*peer, 0, len(c.peers))
	for _, p := range c.peers {
		peers = append(peers, p)
	}
	relay := c.relayAddr
	c.mu.Unlock()

	out := make([]PeerStatus, 0, len(peers))
	for _, p := range peers {
		st := PeerStatus{WGKey: p.wgKey}
		p.mu.Lock()
		st.NodeID = p.nodeID
		st.LastRx = p.lastRx
		switch {
		case p.best.IsValid() && time.Since(p.lastPong) < directPathTimeout:
			st.Path, st.Addr, st.Latency = "direct", p.best, p.bestRTT
		case relay.IsValid() && !p.lastRx.IsZero() && time.Since(p.lastRx) < relayPathTimeout:
			// "relay" has to mean packets are moving through it now. It used
			// to mean only that some packet had arrived at some point in the
			// past, so a peer that had gone away kept its reassuring "relay"
			// forever — which is precisely the case where the status output
			// most needs to be believed.
			st.Path, st.Addr = "relay", relay
		default:
			st.Path = "connecting"
		}
		p.mu.Unlock()
		out = append(out, st)
	}
	return out
}

// ---------------------------------------------------------- maintenance

// maintain drives relay keepalives and path probing until the socket closes.
func (c *Conn) maintain(done <-chan struct{}) {
	// A short first tick gets probes out while the tunnel is still coming
	// up, so the direct path is often ready by the time traffic starts.
	probe := time.NewTimer(250 * time.Millisecond)
	defer probe.Stop()
	bind := time.NewTicker(relayBindInterval)
	defer bind.Stop()

	c.sendRelayBind()
	for {
		select {
		case <-done:
			return
		case <-bind.C:
			c.sendRelayBind()
		case <-probe.C:
			next := c.probeAll()
			// Until some relay has answered, ask again on every probe tick
			// rather than every twenty seconds. The first bind is often lost
			// — the hub may be restarting alongside this agent, or the
			// network still coming up after a resume — and a node with no
			// relay cannot reach any peer it has no direct path to.
			if !c.relayAnswered() {
				c.sendRelayBind()
			}
			probe.Reset(next)
		}
	}
}

// probeAll sends probes for every peer and reports how long to wait before the
// next round: short while any peer is still searching for a direct path.
func (c *Conn) probeAll() time.Duration {
	c.mu.Lock()
	peers := make([]*peer, 0, len(c.peers))
	for _, p := range c.peers {
		peers = append(peers, p)
	}
	relay := c.relayAddr
	observed := c.observed
	c.mu.Unlock()

	searching := false
	for _, p := range peers {
		if p.disco().IsZero() {
			continue // placeholder for a peer not yet in the netmap
		}
		if addr, ok := p.directPath(); ok {
			c.probePeer(p, []netip.AddrPort{addr}, relay, observed)
			continue
		}
		searching = true
		c.probePeer(p, p.candidates(), relay, observed)
	}
	if searching {
		return probeIntervalSearching
	}
	return probeIntervalEstablished
}

// probePeer sends one sealed ping per candidate address.
//
// Sending to every candidate at once, rather than trying them in turn, is what
// makes hole punching work: both ends are firing at the same moment, and
// whichever pair of addresses happens to have a NAT mapping open wins.
func (c *Conn) probePeer(p *peer, candidates []netip.AddrPort, relay, observed netip.AddrPort) {
	peerDisco := p.disco()
	for _, addr := range candidates {
		if !addr.IsValid() || addr == observed {
			continue // no point probing our own public address
		}
		txid := rand.Uint64()
		ping := &disco.Ping{TxID: txid, WGKey: c.opts.WGKey}
		pkt, err := disco.EncodePing(ping, c.opts.DiscoKey, peerDisco)
		if err != nil {
			continue
		}
		p.startPing(txid, addr)
		_ = c.sendRaw(pkt, addr)
	}

	// Also probe over the relay. This is how two peers that cannot reach
	// each other directly still learn each other's disco keys work, and it
	// keeps the relay path warm so the fallback is instant.
	if relay.IsValid() {
		txid := rand.Uint64()
		ping := &disco.Ping{TxID: txid, WGKey: c.opts.WGKey}
		if pkt, err := disco.EncodePing(ping, c.opts.DiscoKey, peerDisco); err == nil {
			// Recorded with no address: a reply proves the peer is alive
			// but says nothing about direct reachability.
			p.startPing(txid, netip.AddrPort{})
			_ = c.sendRaw(disco.EncodeForward(p.wgKey, c.opts.WGKey, pkt), relay)
		}
	}
	p.expireStalePings()
}

// sendRelayBind refreshes our NAT mapping at the relay and asks it what
// address it sees us from.
//
// While a relay is working, only that one is refreshed. When there is none, or
// the one we had has gone quiet, every candidate is bound at once — the same
// reason probes go to every candidate address at once, and the reason a hub
// that becomes reachable is picked up without anyone restarting anything.
func (c *Conn) sendRelayBind() {
	c.mu.Lock()
	if c.opts.NodeID == "" || len(c.relayCands) == 0 {
		c.mu.Unlock()
		return
	}
	targets := c.relayCands
	if c.relayAddr.IsValid() && time.Since(c.relayHeard) <= relayDeadTimeout {
		targets = []netip.AddrPort{c.relayAddr}
	}
	nonces := make([]uint64, len(targets))
	for i, t := range targets {
		nonces[i] = rand.Uint64()
		c.relayNonces[nonces[i]] = t
	}
	c.expireRelayNoncesLocked()
	c.mu.Unlock()

	for i, target := range targets {
		b := &disco.Bind{NodeID: c.opts.NodeID, WGKey: c.opts.WGKey, Nonce: nonces[i]}
		pkt, err := b.Encode(c.opts.MachineKey)
		if err != nil {
			c.logf("magicsock: encode relay bind: %v", err)
			return
		}
		if err := c.sendRaw(pkt, target); err != nil && !errors.Is(err, net.ErrClosed) {
			c.logf("magicsock: relay bind to %s: %v", target, err)
		}
	}
}

// expireRelayNoncesLocked keeps the outstanding-bind table from growing
// without bound when a candidate never answers. Callers must hold c.mu.
func (c *Conn) expireRelayNoncesLocked() {
	const keep = 4 * maxCandidates
	if len(c.relayNonces) <= keep {
		return
	}
	// Nothing here is worth ordering: an unanswered bind is replaced by a
	// fresh one every interval, so dropping the excess loses only replies we
	// would have ignored anyway.
	for n := range c.relayNonces {
		delete(c.relayNonces, n)
		if len(c.relayNonces) <= keep {
			return
		}
	}
}

func slicesEqual(a, b []netip.AddrPort) bool {
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

func joinAddrs(addrs []netip.AddrPort) string {
	if len(addrs) == 0 {
		return "none"
	}
	parts := make([]string, len(addrs))
	for i, a := range addrs {
		parts[i] = a.String()
	}
	return strings.Join(parts, ", ")
}

// canon normalises an address so that the same peer never occupies two map
// keys. A dual-stack socket reports IPv4 sources as v4-mapped IPv6.
func canon(ap netip.AddrPort) netip.AddrPort {
	if !ap.IsValid() {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port())
}
