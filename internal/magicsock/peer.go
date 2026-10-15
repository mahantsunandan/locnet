package magicsock

import (
	"net/netip"
	"sync"
	"time"

	"github.com/mahantsunandan/locnet/internal/key"
	"golang.zx2c4.com/wireguard/conn"
)

// pingExpiry bounds how long an unanswered probe stays in the inflight table.
// Anything older is a probe to an address that does not work.
const pingExpiry = 30 * time.Second

type inflightPing struct {
	addr netip.AddrPort
	sent time.Time
}

// peer tracks one remote node: what the netmap says about it, and what we have
// learned by probing.
//
// wgKey and ep are set at construction and never change, so they can be read
// without the lock. Everything else moves and is guarded by mu.
type peer struct {
	wgKey key.WGPublic
	ep    *peerEndpoint

	mu       sync.Mutex
	nodeID   string
	discoKey key.DiscoPublic
	cands    []netip.AddrPort
	best     netip.AddrPort
	bestRTT  time.Duration
	lastPong time.Time
	lastRx   time.Time
	inflight map[uint64]inflightPing
}

func newPeer(k key.WGPublic) *peer {
	p := &peer{
		wgKey:    k,
		nodeID:   k.String(),
		inflight: make(map[uint64]inflightPing),
	}
	p.ep = &peerEndpoint{p: p}
	return p
}

func (p *peer) setConfig(cfg PeerConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if cfg.NodeID != "" {
		p.nodeID = cfg.NodeID
	}
	p.discoKey = cfg.DiscoKey
	p.cands = append(p.cands[:0], cfg.Endpoints...)
}

func (p *peer) name() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.nodeID
}

func (p *peer) disco() key.DiscoPublic {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.discoKey
}

func (p *peer) candidates() []netip.AddrPort {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]netip.AddrPort(nil), p.cands...)
}

// directPath returns the current direct address, if one is both known and
// recently confirmed. A path that has stopped answering probes is not
// returned, which is what makes traffic fall back to the relay.
func (p *peer) directPath() (netip.AddrPort, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.best.IsValid() || time.Since(p.lastPong) > directPathTimeout {
		return netip.AddrPort{}, false
	}
	return p.best, true
}

func (p *peer) clearDirect() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.best = netip.AddrPort{}
	p.bestRTT = 0
}

func (p *peer) noteRx() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastRx = time.Now()
}

func (p *peer) startPing(txid uint64, addr netip.AddrPort) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.inflight[txid] = inflightPing{addr: addr, sent: time.Now()}
}

// completePing matches a pong to the probe that caused it and updates the
// chosen path. It returns the address that was proven to work — the address we
// sent to, not the address the reply arrived from. Under a symmetric NAT those
// differ, and only the former is something we can send to again.
//
// switched is true when the reply changed which path the peer uses — a new
// path, a different address, or a path recovered after going quiet. Only those
// are worth a log line; a pong confirming the path already in use arrives
// every few seconds for every peer, and logging each one buried everything
// else in the journal.
func (p *peer) completePing(txid uint64, from netip.AddrPort) (proven netip.AddrPort, rtt time.Duration, switched, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	rec, found := p.inflight[txid]
	if !found {
		return netip.AddrPort{}, 0, false, false
	}
	delete(p.inflight, txid)

	// A probe sent over the relay carries no address, so a reply to it
	// proves liveness but not a direct path.
	if !rec.addr.IsValid() {
		p.lastRx = time.Now()
		return netip.AddrPort{}, 0, false, false
	}

	rtt = time.Since(rec.sent)
	now := time.Now()

	// Whether the chosen path had gone quiet must be judged against the
	// previous pong, not this one. Reading it after lastPong was updated made
	// the answer always "no", so this branch never ran — and a peer that
	// moved to another network kept the address it had before the move. That
	// address still looked current, because a reply on *any* address
	// refreshed the timestamp the freshness check reads, so traffic was sent
	// to somewhere that no longer existed while the status said "direct".
	stale := p.best.IsValid() && now.Sub(p.lastPong) > directPathTimeout

	p.lastPong = now
	p.lastRx = now

	if !p.best.IsValid() || stale || rec.addr == p.best || rtt < p.bestRTT {
		// A path that had lapsed and answers again counts as a switch even
		// at the same address: traffic had gone back to the relay.
		switched = p.best != rec.addr || stale
		p.best = rec.addr
		p.bestRTT = rtt
	}
	return rec.addr, rtt, switched, true
}

func (p *peer) expireStalePings() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for txid, rec := range p.inflight {
		if time.Since(rec.sent) > pingExpiry {
			delete(p.inflight, txid)
		}
	}
}

// ------------------------------------------------------------- endpoints

// peerEndpoint is what WireGuard holds on to for a peer. It carries no
// address: the address is looked up at send time, which is what lets a peer
// roam or switch to the relay without WireGuard being reconfigured.
type peerEndpoint struct{ p *peer }

func (e *peerEndpoint) ClearSrc() {}

func (e *peerEndpoint) SrcToString() string { return "" }

func (e *peerEndpoint) DstToString() string {
	if addr, ok := e.p.directPath(); ok {
		return addr.String()
	}
	return "relay:" + e.p.wgKey.String()
}

// DstToBytes feeds WireGuard's cookie calculation, which needs a stable
// per-peer value rather than a meaningful address.
func (e *peerEndpoint) DstToBytes() []byte {
	k := e.p.wgKey
	return k[:]
}

func (e *peerEndpoint) DstIP() netip.Addr {
	if addr, ok := e.p.directPath(); ok {
		return addr.Addr()
	}
	return netip.Addr{}
}

func (e *peerEndpoint) SrcIP() netip.Addr { return netip.Addr{} }

// bareEndpoint is a plain UDP address, used for traffic from a source we have
// not yet tied to a peer and for hand-written debugging configurations.
type bareEndpoint struct{ addr netip.AddrPort }

func (e *bareEndpoint) ClearSrc()           {}
func (e *bareEndpoint) SrcToString() string { return "" }
func (e *bareEndpoint) DstToString() string { return e.addr.String() }
func (e *bareEndpoint) DstToBytes() []byte  { b, _ := e.addr.MarshalBinary(); return b }
func (e *bareEndpoint) DstIP() netip.Addr   { return e.addr.Addr() }
func (e *bareEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

var (
	_ conn.Endpoint = (*peerEndpoint)(nil)
	_ conn.Endpoint = (*bareEndpoint)(nil)
	_ conn.Bind     = (*Conn)(nil)
)
