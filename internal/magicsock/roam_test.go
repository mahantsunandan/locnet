package magicsock

import (
	"net/netip"
	"testing"
	"time"

	"github.com/mahantsunandan/locnet/internal/key"
)

// key0 is a fixed public key; these tests care about path selection, not
// cryptography.
func key0() key.WGPublic {
	var k key.WGPublic
	k[0] = 1
	return k
}

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

// pong drives one probe/response cycle against addr and returns what the peer
// decided.
func pong(p *peer, txid uint64, addr netip.AddrPort) {
	p.startPing(txid, addr)
	p.completePing(txid, addr)
}

// TestPeerAdoptsTheNewAddressAfterRoaming is the case that broke a laptop
// moving from Wi-Fi to a phone hotspot.
//
// The old address stops answering. The path times out and traffic falls to the
// relay, which is correct. Then a probe succeeds on the *new* address — and at
// that moment the peer must switch to it. Keeping the old one leaves the
// status saying "direct" while packets go to an address that no longer exists,
// which looks exactly like a network that is up but silently drops everything.
func TestPeerAdoptsTheNewAddressAfterRoaming(t *testing.T) {
	old, fresh := ap("192.168.1.50:41820"), ap("172.20.10.4:41820")

	p := newPeer(key0())
	pong(p, 1, old)
	if got, ok := p.directPath(); !ok || got != old {
		t.Fatalf("first path = %v (ok=%v), want %v", got, ok, old)
	}

	// The machine moves. Nothing answers for longer than the timeout.
	p.mu.Lock()
	p.lastPong = time.Now().Add(-2 * directPathTimeout)
	p.mu.Unlock()
	if _, ok := p.directPath(); ok {
		t.Fatal("a path that stopped answering should not still be offered")
	}

	// A probe succeeds on the new address. It is slower than the old one was
	// — a hotspot usually is — so a rule that only ever accepts a faster
	// address would reject it.
	p.startPing(2, fresh)
	time.Sleep(2 * time.Millisecond)
	p.completePing(2, fresh)

	got, ok := p.directPath()
	if !ok {
		t.Fatal("no direct path after the new address answered")
	}
	if got != fresh {
		t.Errorf("path = %v, want %v — the peer kept an address that no longer works", got, fresh)
	}
}

// TestSlowerAddressDoesNotStealAWorkingPath is the other half: while the
// chosen path is healthy, a slower candidate answering must not displace it,
// or the path would flap between every address that replies.
func TestSlowerAddressDoesNotStealAWorkingPath(t *testing.T) {
	quick, slow := ap("192.168.1.50:41820"), ap("10.8.0.9:41820")

	p := newPeer(key0())
	p.startPing(1, quick)
	p.completePing(1, quick)

	p.startPing(2, slow)
	time.Sleep(5 * time.Millisecond) // make it measurably slower
	p.completePing(2, slow)

	if got, _ := p.directPath(); got != quick {
		t.Errorf("path = %v, want %v — a slower address displaced a healthy one", got, quick)
	}
}

// TestRelayPongProvesLivenessNotAPath guards the distinction the whole design
// rests on: a reply that came back through the relay says the peer is alive,
// not that we can reach it directly.
func TestRelayPongProvesLivenessNotAPath(t *testing.T) {
	p := newPeer(key0())

	p.startPing(1, netip.AddrPort{}) // no address = sent via the relay
	addr, _, _, ok := p.completePing(1, ap("1.2.3.4:41820"))
	if ok || addr.IsValid() {
		t.Errorf("a relayed pong was treated as proof of a direct path (%v)", addr)
	}
	if _, ok := p.directPath(); ok {
		t.Error("a relayed pong created a direct path")
	}
}

// TestRepeatedPongsOnTheSameAddressKeepItFresh: the steady state. A path that
// keeps answering must never expire, whatever its RTT does.
func TestRepeatedPongsOnTheSameAddressKeepItFresh(t *testing.T) {
	addr := ap("192.168.1.50:41820")
	p := newPeer(key0())

	for i := uint64(1); i <= 5; i++ {
		p.startPing(i, addr)
		time.Sleep(time.Millisecond) // each one slower than the last
		p.completePing(i, addr)
		if got, ok := p.directPath(); !ok || got != addr {
			t.Fatalf("probe %d: path = %v (ok=%v), want %v", i, got, ok, addr)
		}
	}
}
