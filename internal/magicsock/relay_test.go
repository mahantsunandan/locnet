package magicsock

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/mahantsunandan/locnet/internal/disco"
	"github.com/mahantsunandan/locnet/internal/key"
	"golang.zx2c4.com/wireguard/conn"
)

// fakeRelay is a UDP socket that answers binds the way a hub's relay does,
// without any of the hub behind it.
type fakeRelay struct {
	pc       *net.UDPConn
	addr     netip.AddrPort
	binds    chan netip.AddrPort
	forwards chan []byte // bodies of TypeForward frames, as received
}

// startFakeRelay answers every bind it receives. startBlackHole listens but
// never answers, which is what an advertised address that cannot be reached
// looks like from the outside: not a refusal, just silence.
func startFakeRelay(t *testing.T, answer bool) *fakeRelay {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	r := &fakeRelay{
		pc:       pc,
		addr:     canon(netip.MustParseAddrPort(pc.LocalAddr().String())),
		binds:    make(chan netip.AddrPort, 16),
		forwards: make(chan []byte, 16),
	}
	t.Cleanup(func() { pc.Close() })

	go func() {
		buf := make([]byte, disco.MaxPacketSize)
		for {
			n, src, err := pc.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			typ, body, err := disco.Type(buf[:n])
			if err != nil {
				continue
			}
			if typ == disco.TypeForward {
				select {
				case r.forwards <- append([]byte(nil), body...):
				default:
				}
				continue
			}
			if typ != disco.TypeBind {
				continue
			}
			select {
			case r.binds <- canon(src):
			default:
			}
			if !answer {
				continue
			}
			// The nonce is the last 8 bytes before the signature, and the
			// signature is the trailing 64. Parsing it properly would need
			// the store; this test only has to echo it back.
			if len(body) < 8+64 {
				continue
			}
			nonce := binary.BigEndian.Uint64(body[len(body)-64-8 : len(body)-64])
			reply := (&disco.BindReply{Nonce: nonce, Observed: canon(src)}).Encode()
			pc.WriteToUDPAddrPort(reply, src)
		}
	}()
	return r
}

func relayTestConn(t *testing.T) *Conn {
	t.Helper()
	machine, _, err := key.NewMachine()
	if err != nil {
		t.Fatal(err)
	}
	discoPriv, _, err := key.NewDisco()
	if err != nil {
		t.Fatal(err)
	}
	c := New(Options{
		NodeID:     "n-test",
		MachineKey: machine,
		DiscoKey:   discoPriv,
		Logf:       t.Logf,
	})
	if _, _, err := c.Open(0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })

	// magicsock processes replies inside the receive path, which WireGuard
	// normally drives. Without this pump a bind is sent and its answer never
	// read, and every relay test would time out for the wrong reason.
	go func() {
		bufs := [][]byte{make([]byte, disco.MaxPacketSize)}
		sizes := make([]int, 1)
		eps := make([]conn.Endpoint, 1)
		for {
			if _, err := c.receive(bufs, sizes, eps); err != nil {
				return
			}
		}
	}()
	return c
}

// TestRelayFailsOverToAWorkingCandidate is the bug that left this network with
// no fallback path at all.
//
// The hub advertises its public address first, because that is the right
// answer for machines elsewhere. From inside the hub's own LAN that address
// only works if the router hairpins, and many do not. Taking the first address
// on faith meant the relay was never reachable, while `locnet status` went on
// reporting peers as "relay".
func TestRelayFailsOverToAWorkingCandidate(t *testing.T) {
	dead := startFakeRelay(t, false)
	live := startFakeRelay(t, true)

	c := relayTestConn(t)
	c.SetRelays([]netip.AddrPort{dead.addr, live.addr})

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if c.Relay() == live.addr {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("relay = %v, want the candidate that answers (%v)", c.Relay(), live.addr)
}

// TestRelayIgnoresAnUnsolicitedReply covers the other half: adopting a relay
// because something answered, rather than because the thing we asked
// answered, would let anything on the path nominate itself.
func TestRelayIgnoresAnUnsolicitedReply(t *testing.T) {
	live := startFakeRelay(t, true)
	c := relayTestConn(t)
	c.SetRelays([]netip.AddrPort{live.addr})

	forged := &disco.BindReply{Nonce: 0xdeadbeef, Observed: ap("203.0.113.9:1234")}
	c.noteBindReply(forged, ap("198.51.100.1:8420"))

	if got := c.Relay(); got == ap("198.51.100.1:8420") {
		t.Fatal("a reply nobody asked for was accepted as the relay")
	}
}

// TestBareEndpointFallsBackToTheRelay is the bug behind "shows Relay on
// locnet peers but I cannot ping or ssh".
//
// WireGuard pins a peer to the endpoint its last inbound packet carried. A
// packet from an address magicsock had not yet tied to a peer arrives as a
// bare address, and that pin then bypasses path selection entirely: when the
// machine moves to another network the address goes dead, no fallback is ever
// consulted, and the status output goes on claiming a relay it is not using.
func TestBareEndpointFallsBackToTheRelay(t *testing.T) {
	live := startFakeRelay(t, true)

	// Somewhere nothing is listening — the peer's old address after it moved.
	stale := ap("127.0.0.1:9")

	c := relayTestConn(t)
	c.SetRelays([]netip.AddrPort{live.addr})
	waitForRelay(t, c, live.addr)

	// The peer exists and its address is known, but no probe has succeeded,
	// so there is no direct path.
	c.SetPeers([]PeerConfig{{NodeID: "beta", WGKey: key0()}})
	c.noteAddrForPeer(stale, key0())

	ep, err := c.ParseEndpoint(stale.String())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ep.(*bareEndpoint); !ok {
		t.Fatalf("ParseEndpoint(%q) gave %T, want the bare-address endpoint this test is about", stale, ep)
	}

	payload := append([]byte{0x01, 0x00, 0x00, 0x00}, []byte("transport")...)
	if err := c.Send([][]byte{payload}, ep); err != nil {
		t.Fatalf("send: %v", err)
	}

	// It must have gone to the relay, wrapped for delivery to the peer —
	// not to the address WireGuard had pinned.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case pkt := <-live.forwards:
			dst, _, inner, err := disco.ParseForward(pkt)
			if err != nil {
				continue
			}
			if dst != key0() {
				t.Fatalf("relayed to %v, want the peer's key", dst)
			}
			if string(inner) != string(payload) {
				t.Fatalf("relayed payload = %q, want %q", inner, payload)
			}
			return
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
	t.Fatal("the packet went to the pinned address instead of the relay")
}

func waitForRelay(t *testing.T, c *Conn, want netip.AddrPort) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if c.Relay() == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("relay never became %v", want)
}

// TestRelayIsNotReportedUntilItAnswers covers the status line. A relay that
// has been configured but has never replied is not a fallback path, and
// saying it is has cost real debugging time.
func TestRelayIsNotReportedUntilItAnswers(t *testing.T) {
	dead := startFakeRelay(t, false)
	c := relayTestConn(t)
	c.SetRelays([]netip.AddrPort{dead.addr})

	// Give the bind long enough to have been answered, had anything been
	// going to answer it.
	select {
	case <-dead.binds:
	case <-time.After(5 * time.Second):
		t.Fatal("no bind was ever sent to the candidate")
	}
	time.Sleep(200 * time.Millisecond)

	if got := c.Relay(); got.IsValid() {
		t.Fatalf("Relay() = %v, want none: nothing has ever answered", got)
	}
}
