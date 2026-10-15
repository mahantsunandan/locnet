package node

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/mahantsunandan/locnet/internal/policy"
)

// ipv4 builds a minimal IPv4 packet for the filter to inspect.
func ipv4(proto byte, src netip.Addr, dstPort uint16) []byte {
	pkt := make([]byte, 28)
	pkt[0] = 0x45 // version 4, 5-word header
	pkt[9] = proto
	copy(pkt[12:16], src.AsSlice())
	copy(pkt[16:20], []byte{100, 100, 0, 1})
	binary.BigEndian.PutUint16(pkt[22:24], dstPort) // TCP/UDP dst port
	return pkt
}

func addr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}

func TestFilterAllowsGrantedPorts(t *testing.T) {
	rules := &filterRules{byAddr: map[netip.Addr]peerPorts{
		addr("100.100.0.2"): {ranges: []policy.PortRange{{Lo: 8421, Hi: 8421}}},
	}}

	if !permitted(rules, ipv4(6, addr("100.100.0.2"), 8421)) {
		t.Error("the granted port was dropped")
	}
	for _, port := range []uint16{22, 80, 3389, 8420, 8422} {
		if permitted(rules, ipv4(6, addr("100.100.0.2"), port)) {
			t.Errorf("port %d passed but was never granted", port)
		}
	}
}

func TestFilterAllowsUnrestrictedAndUnknownPeers(t *testing.T) {
	rules := &filterRules{byAddr: map[netip.Addr]peerPorts{
		addr("100.100.0.2"): {ranges: []policy.PortRange{{Lo: 22, Hi: 22}}},
	}}

	// A peer with no entry is unrestricted — the hub only sends entries for
	// peers the policy actually limits.
	if !permitted(rules, ipv4(6, addr("100.100.0.9"), 3389)) {
		t.Error("a peer with no rule entry was filtered")
	}
	// An explicit all=true entry passes everything.
	rules.byAddr[addr("100.100.0.3")] = peerPorts{all: true}
	if !permitted(rules, ipv4(6, addr("100.100.0.3"), 12345)) {
		t.Error("an unrestricted peer was filtered")
	}
}

// TestFilterPassesICMP covers the deliberate exemption: blocking ping while
// permitting SSH would be a miserable thing to debug.
func TestFilterPassesICMP(t *testing.T) {
	rules := &filterRules{byAddr: map[netip.Addr]peerPorts{
		addr("100.100.0.2"): {ranges: []policy.PortRange{{Lo: 8421, Hi: 8421}}},
	}}
	if !permitted(rules, ipv4(1, addr("100.100.0.2"), 0)) {
		t.Error("ICMP was dropped by a port rule")
	}
}

func TestFilterHandlesMalformedPackets(t *testing.T) {
	rules := &filterRules{byAddr: map[netip.Addr]peerPorts{
		addr("100.100.0.2"): {ranges: []policy.PortRange{{Lo: 22, Hi: 22}}},
	}}
	// Anything unparseable must pass rather than panic — the machine-level
	// policy already vouched for the peer.
	cases := [][]byte{
		{},
		{0x45},
		make([]byte, 19),
		{0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // IPv6
		{0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // IHL 0
	}
	for i, pkt := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("case %d panicked: %v", i, r)
				}
			}()
			if !permitted(rules, pkt) {
				t.Errorf("case %d was dropped; unparseable packets should pass", i)
			}
		}()
	}
}

// TestFilterPassesFragments checks that a later fragment, which has no
// transport header to read, is not silently dropped and does not break a
// permitted transfer.
func TestFilterPassesFragments(t *testing.T) {
	rules := &filterRules{byAddr: map[netip.Addr]peerPorts{
		addr("100.100.0.2"): {ranges: []policy.PortRange{{Lo: 22, Hi: 22}}},
	}}
	pkt := ipv4(6, addr("100.100.0.2"), 3389)
	binary.BigEndian.PutUint16(pkt[6:8], 185) // non-zero fragment offset
	if !permitted(rules, pkt) {
		t.Error("a non-first fragment was dropped")
	}
}

func TestParseIPv4(t *testing.T) {
	src := addr("100.100.0.7")
	for _, proto := range []byte{6, 17} {
		got, port, ok := parseIPv4(ipv4(proto, src, 4242))
		if !ok {
			t.Fatalf("proto %d did not parse", proto)
		}
		if got != src || port != 4242 {
			t.Errorf("parsed %s:%d, want %s:4242", got, port, src)
		}
	}
	if _, _, ok := parseIPv4(ipv4(1, src, 0)); ok {
		t.Error("ICMP reported a port")
	}
}

// TestWriteCountsEveryPacket checks the contract with wireguard-go: a short
// return would be read as a device error rather than a policy decision.
func TestWriteCountsEveryPacket(t *testing.T) {
	inner := &countingTUN{}
	f := newFilteredTUN(inner)
	f.setRules(map[netip.Addr]peerPorts{
		addr("100.100.0.2"): {ranges: []policy.PortRange{{Lo: 22, Hi: 22}}},
	})

	bufs := [][]byte{
		ipv4(6, addr("100.100.0.2"), 22),   // allowed
		ipv4(6, addr("100.100.0.2"), 3389), // dropped
		ipv4(6, addr("100.100.0.2"), 22),   // allowed
	}
	n, err := f.Write(bufs, 0)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(bufs) {
		t.Errorf("Write returned %d, want %d — a short count reads as a device error", n, len(bufs))
	}
	if inner.written != 2 {
		t.Errorf("%d packets reached the kernel, want 2", inner.written)
	}
	if f.Dropped() != 1 {
		t.Errorf("Dropped() = %d, want 1", f.Dropped())
	}

	// Everything dropped: still must not look like an error.
	inner.written = 0
	n, err = f.Write([][]byte{ipv4(6, addr("100.100.0.2"), 3389)}, 0)
	if err != nil || n != 1 {
		t.Errorf("all-dropped Write returned (%d, %v), want (1, nil)", n, err)
	}
	if inner.written != 0 {
		t.Error("a dropped packet reached the kernel")
	}
}

// tcpPacket builds an IPv4 TCP or UDP packet with both ends filled in.
func tcpPacket(proto byte, src netip.Addr, srcPort uint16, dst netip.Addr, dstPort uint16) []byte {
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	pkt[9] = proto
	copy(pkt[12:16], src.AsSlice())
	copy(pkt[16:20], dst.AsSlice())
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	return pkt
}

// outboundTUN plays the kernel: Read returns the packets queued in out.
type outboundTUN struct {
	countingTUN
	out [][]byte
}

func (o *outboundTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n := 0
	for ; n < len(o.out) && n < len(bufs); n++ {
		sizes[n] = copy(bufs[n][offset:], o.out[n])
	}
	o.out = o.out[n:]
	return n, nil
}

// TestOneWayPolicyLetsRepliesBackIn is the shape of "linuxbox may reach
// winpc-01; winpc-01 may reach nothing on linuxbox". The hub sends winpc-01
// to linuxbox with no ports. linuxbox's own connections must still work, and
// winpc-01 must not be able to start one.
func TestOneWayPolicyLetsRepliesBackIn(t *testing.T) {
	self, peer := addr("100.100.0.1"), addr("100.100.0.2")
	inner := &outboundTUN{}
	f := newFilteredTUN(inner)
	f.setRules(map[netip.Addr]peerPorts{peer: {ranges: []policy.PortRange{policy.NoPorts}}})

	// This machine opens SSH and a UDP exchange to the peer.
	inner.out = [][]byte{
		tcpPacket(6, self, 50000, peer, 22),
		tcpPacket(17, self, 50001, peer, 53),
	}
	bufs := [][]byte{make([]byte, 64), make([]byte, 64)}
	if n, err := f.Read(bufs, make([]int, 2), 0); err != nil || n != 2 {
		t.Fatalf("Read = %d, %v", n, err)
	}

	cases := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"reply to our SSH connection", tcpPacket(6, peer, 22, self, 50000), true},
		{"reply to our UDP exchange", tcpPacket(17, peer, 53, self, 50001), true},
		{"the peer opening SSH to us", tcpPacket(6, peer, 50000, self, 22), false},
		{"the peer opening VNC to us", tcpPacket(6, peer, 40000, self, 5900), false},
		{"right ports, wrong protocol", tcpPacket(17, peer, 22, self, 50000), false},
		{"a different local port", tcpPacket(6, peer, 22, self, 50002), false},
	}
	for _, c := range cases {
		inner.written = 0
		f.Write([][]byte{c.pkt}, 0)
		if got := inner.written == 1; got != c.want {
			t.Errorf("%s: delivered=%v, want %v", c.name, got, c.want)
		}
	}
}

// Unrestricted peers need no memory: nothing is recorded for them.
func TestNoFlowsKeptForUnrestrictedPeers(t *testing.T) {
	self, open, limited := addr("100.100.0.1"), addr("100.100.0.3"), addr("100.100.0.2")
	inner := &outboundTUN{out: [][]byte{tcpPacket(6, self, 50000, open, 22)}}
	f := newFilteredTUN(inner)
	f.setRules(map[netip.Addr]peerPorts{limited: {ranges: []policy.PortRange{policy.NoPorts}}})
	f.Read([][]byte{make([]byte, 64)}, make([]int, 1), 0)
	if len(f.flows) != 0 {
		t.Errorf("%d flows recorded for a peer the policy does not restrict", len(f.flows))
	}
}

// Under a one-way policy the first peer in the list is often one that may
// not connect here at all. It must not be the one asked to check this
// machine's ports, or every port reads as firewalled.
func TestProbersSkipPeersThePolicyKeepsOut(t *testing.T) {
	none := []policy.PortRange{policy.NoPorts}
	peers := []PeerStatus{
		{Name: "winpc-01", IP: addr("10.99.0.3"), Online: true, InboundPorts: none},
		{Name: "ssh-only", IP: addr("10.99.0.5"), Online: true, InboundPorts: []policy.PortRange{{Lo: 22, Hi: 22}}},
		{Name: "offline", IP: addr("10.99.0.4"), Online: false},
		{Name: "hubpc", IP: addr("10.99.0.1"), Online: true},
	}
	got := Probers(peers, []uint16{22, 8421})
	var names []string
	for _, p := range got {
		names = append(names, p.Name)
	}
	if len(names) != 2 || names[0] != "hubpc" || names[1] != "ssh-only" {
		t.Errorf("Probers = %v, want [hubpc ssh-only]: unrestricted first, kept-out and offline peers dropped", names)
	}
	if peers[0].MayReach(22) {
		t.Error("a peer sent NoPorts may reach port 22")
	}
	if !peers[3].MayReach(5900) || !peers[1].MayReach(22) || peers[1].MayReach(8421) {
		t.Error("MayReach disagrees with the port lists")
	}
}
