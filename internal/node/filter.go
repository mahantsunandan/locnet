package node

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mahantsunandan/locnet/internal/policy"
	"golang.zx2c4.com/wireguard/tun"
)

// filteredTUN wraps the tunnel device and drops inbound packets the policy
// refuses.
//
// It sits on the Write path — the direction in which wireguard-go hands
// already-decrypted packets to the kernel. Filtering here rather than in the
// host firewall means the rule travels with the policy: an operator edits it
// once on the hub and every machine enforces it, with nothing to configure per
// host and nothing to drift.
//
// Machine-level rules are not enforced here at all. Those are enforced by the
// hub leaving a peer out of the network map, so there is no WireGuard peer, no
// shared key, and nothing to decrypt in the first place. This filter exists
// only for the finer question of *which ports* a permitted peer may reach,
// which WireGuard's allowed-IPs cannot express.
//
// The hub sends each node a precomputed port list per peer rather than the
// whole policy. That keeps the data path to one map lookup, and means a node
// is never handed rules about machines it cannot see.
type filteredTUN struct {
	tun.Device

	// rules is swapped wholesale on each netmap update rather than mutated,
	// so the packet path reads one pointer and never takes a lock.
	rules atomic.Pointer[filterRules]

	mu      sync.Mutex
	dropped uint64

	// flows remembers connections this machine opened to restricted peers,
	// so their replies are let back in. See noteOutbound.
	flowMu  sync.Mutex
	flows   map[flowKey]time.Time // → when it expires
	inserts int
}

// flowKey is one connection, seen from this machine.
type flowKey struct {
	proto      uint8
	remote     netip.Addr
	remotePort uint16
	localPort  uint16
}

const (
	// How long a quiet connection stays remembered. TCP's is long so an
	// idle SSH session still gets the far end's output when it comes;
	// UDP has no connection to keep.
	tcpFlowIdle = time.Hour
	udpFlowIdle = 3 * time.Minute
	// maxFlows bounds the table, so a peer cannot grow it without limit.
	maxFlows = 1 << 16
)

// filterRules is an immutable snapshot of what is permitted inbound.
type filterRules struct {
	byAddr map[netip.Addr]peerPorts
}

// peerPorts is what one peer may reach on this machine.
type peerPorts struct {
	all    bool
	ranges []policy.PortRange
}

func (p peerPorts) permits(port uint16) bool {
	if p.all {
		return true
	}
	for _, r := range p.ranges {
		if port >= r.Lo && port <= r.Hi {
			return true
		}
	}
	return false
}

func newFilteredTUN(inner tun.Device) *filteredTUN {
	f := &filteredTUN{Device: inner}
	f.rules.Store(&filterRules{})
	return f
}

// setRules installs a new snapshot. A nil or empty map disables filtering,
// which is what an unrestricted policy should cost: nothing.
func (f *filteredTUN) setRules(byAddr map[netip.Addr]peerPorts) {
	f.rules.Store(&filterRules{byAddr: byAddr})
}

// Dropped reports how many packets the filter has refused.
func (f *filteredTUN) Dropped() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dropped
}

// Read hands wireguard-go what the kernel is sending out, and notes the
// connections it opens to restricted peers on the way.
func (f *filteredTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := f.Device.Read(bufs, sizes, offset)
	r := f.rules.Load()
	if len(r.byAddr) > 0 && n > 0 {
		now := time.Now()
		for i := 0; i < n; i++ {
			if sizes[i] > 0 && len(bufs[i]) >= offset+sizes[i] {
				f.noteOutbound(r, bufs[i][offset:offset+sizes[i]], now)
			}
		}
	}
	return n, err
}

// noteOutbound records a connection this machine is making to a restricted
// peer, so the replies can come back in.
//
// The filter is about who may *start* a conversation. Without this it was
// stateless — it judged each inbound packet by the peer it came from and the
// port it was going to — and a reply goes to whatever ephemeral port the
// connection was opened from. So a one-way rule ("linuxbox may reach
// winpc-01; winpc-01 may reach nothing") either blocked linuxbox's own
// sessions, by dropping winpc-01's answers, or, as the hub used to send it,
// was not enforced at all.
func (f *filteredTUN) noteOutbound(r *filterRules, pkt []byte, now time.Time) {
	fl, ok := parseFlow(pkt)
	if !ok {
		return
	}
	ports, restricted := r.byAddr[fl.dst]
	if !restricted || ports.all {
		return
	}
	idle := tcpFlowIdle
	if fl.proto == 17 {
		idle = udpFlowIdle
	}
	key := flowKey{proto: fl.proto, remote: fl.dst, remotePort: fl.dstPort, localPort: fl.srcPort}

	f.flowMu.Lock()
	defer f.flowMu.Unlock()
	if f.flows == nil {
		f.flows = make(map[flowKey]time.Time)
	}
	if _, known := f.flows[key]; !known {
		f.inserts++
		if f.inserts%4096 == 0 || len(f.flows) >= maxFlows {
			for k, exp := range f.flows {
				if now.After(exp) {
					delete(f.flows, k)
				}
			}
		}
		if len(f.flows) >= maxFlows {
			return // full of live connections; this one's replies will be refused
		}
	}
	f.flows[key] = now.Add(idle)
}

// isReply reports whether an inbound packet answers a connection this
// machine opened.
func (f *filteredTUN) isReply(pkt []byte, now time.Time) bool {
	fl, ok := parseFlow(pkt)
	if !ok {
		return false
	}
	key := flowKey{proto: fl.proto, remote: fl.src, remotePort: fl.srcPort, localPort: fl.dstPort}
	f.flowMu.Lock()
	defer f.flowMu.Unlock()
	exp, known := f.flows[key]
	return known && now.Before(exp)
}

// Write delivers permitted packets and silently drops the rest.
//
// Dropping rather than rejecting is deliberate: an ICMP unreachable would tell
// the sender that something is there and refusing, which is exactly the
// information a policy exists to withhold.
func (f *filteredTUN) Write(bufs [][]byte, offset int) (int, error) {
	r := f.rules.Load()
	if len(r.byAddr) == 0 {
		return f.Device.Write(bufs, offset)
	}

	kept := bufs[:0]
	var dropped int
	now := time.Now()
	for _, b := range bufs {
		if len(b) <= offset || permitted(r, b[offset:]) || f.isReply(b[offset:], now) {
			kept = append(kept, b)
			continue
		}
		dropped++
	}
	if dropped > 0 {
		f.mu.Lock()
		f.dropped += uint64(dropped)
		f.mu.Unlock()
	}
	if len(kept) == 0 {
		// Report every packet as written. They were handled — by being
		// discarded — and a short count would make wireguard-go treat a
		// working filter as a device error.
		return len(bufs), nil
	}
	if n, err := f.Device.Write(kept, offset); err != nil {
		return n, err
	}
	return len(bufs), nil
}

// permitted parses just enough of an IPv4 packet to apply the rules.
func permitted(r *filterRules, pkt []byte) bool {
	src, port, ok := parseIPv4(pkt)
	if !ok {
		// Not something this filter understands — IPv6, a fragment, ICMP.
		// Machine-level policy already permitted this peer to exist, so let
		// it through rather than break ping.
		return true
	}
	ports, known := r.byAddr[src]
	if !known {
		// From an address not in our map. It decrypted under some peer's
		// key so it is authentic, but we cannot attribute it to a name.
		return true
	}
	return ports.permits(port)
}

// flow is the addressing of one TCP or UDP packet.
type flow struct {
	proto            uint8
	src, dst         netip.Addr
	srcPort, dstPort uint16
}

// parseFlow reads both ends of a TCP or UDP packet. Anything else, and any
// fragment after the first, is not a flow.
func parseFlow(pkt []byte) (flow, bool) {
	src, dstPort, ok := parseIPv4(pkt)
	if !ok {
		return flow{}, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	return flow{
		proto:   pkt[9],
		src:     src,
		dst:     netip.AddrFrom4([4]byte(pkt[16:20])),
		srcPort: binary.BigEndian.Uint16(pkt[ihl : ihl+2]),
		dstPort: dstPort,
	}, true
}

// parseIPv4 extracts the source address and destination port.
//
// Only TCP and UDP carry ports. ICMP has none, and a policy that blocked ping
// while permitting SSH would be a miserable thing to debug, so it passes and
// is governed by the machine-level rule alone.
func parseIPv4(pkt []byte) (src netip.Addr, dstPort uint16, ok bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return src, 0, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return src, 0, false
	}
	// A non-zero fragment offset means the transport header is in an earlier
	// packet. Passing fragments is the safe choice: dropping them would break
	// large permitted transfers.
	if binary.BigEndian.Uint16(pkt[6:8])&0x1fff != 0 {
		return src, 0, false
	}

	src = netip.AddrFrom4([4]byte(pkt[12:16]))
	switch pkt[9] { // protocol
	case 6, 17: // TCP, UDP
		if len(pkt) < ihl+4 {
			return src, 0, false
		}
		return src, binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4]), true
	}
	return src, 0, false
}
