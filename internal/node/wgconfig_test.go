package node

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/mahantsunandan/locnet/internal/key"
	"github.com/mahantsunandan/locnet/internal/netmap"
	"github.com/mahantsunandan/locnet/internal/resource"
)

func wgKey(b byte) key.WGPublic {
	var k key.WGPublic
	k[0] = b
	return k
}

func mapWith(peers ...netmap.Node) *netmap.NetMap {
	return &netmap.NetMap{Peers: peers}
}

func peerNode(name string, k key.WGPublic, ip string) netmap.Node {
	return netmap.Node{Name: name, WGKey: k, IP: netip.MustParseAddr(ip)}
}

// TestNetMapChurnDoesNotReconfigureWireGuard is the fix for a tunnel that
// looked up and refused to carry traffic.
//
// The netmap version bumps every time any machine reports its load, so on a
// three-machine network a new map arrives every few seconds. Re-sending the
// whole WireGuard configuration for each one is quietly destructive:
// `replace_peers=true` makes wireguard-go discard every peer's session keys
// and queued packets, and `listen_port=` makes it close and reopen the UDP
// socket. The tunnel spent its life re-handshaking.
func TestNetMapChurnDoesNotReconfigureWireGuard(t *testing.T) {
	k := wgKey(1)
	before := mapWith(peerNode("beta", k, "10.99.0.3"))

	// The same peer, one report later: new stats, new last-seen, new
	// endpoints, new advertised shares. None of it means anything to
	// WireGuard.
	after := mapWith(netmap.Node{
		Name:      "beta",
		WGKey:     k,
		IP:        netip.MustParseAddr("10.99.0.3"),
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.7:41820")},
		LastSeen:  time.Now(),
		Online:    true,
		Stats:     resource.Stats{CPUs: 8, LoadPercent: 91},
		Shares:    []resource.Advert{{Name: "data"}},
	})

	if got := wgUpdate(wgPeers(before), wgPeers(after)); got != "" {
		t.Fatalf("a netmap that changed nothing WireGuard cares about produced:\n%s", got)
	}
}

func TestWGUpdateAddsRemovesAndReaddresses(t *testing.T) {
	a, b, c := wgKey(1), wgKey(2), wgKey(3)

	prev := wgPeers(mapWith(
		peerNode("alpha", a, "10.99.0.2"),
		peerNode("beta", b, "10.99.0.3"),
	))
	next := wgPeers(mapWith(
		peerNode("alpha", a, "10.99.0.2"), // unchanged
		peerNode("beta", b, "10.99.0.9"),  // readdressed
		peerNode("gamma", c, "10.99.0.4"), // new
	))

	got := wgUpdate(prev, next)
	if got == "" {
		t.Fatal("a changed peer set produced no configuration")
	}
	if strings.Contains(got, "replace_peers") {
		t.Error("an incremental update must never drop every peer")
	}
	if strings.Contains(got, "listen_port") {
		t.Error("an incremental update must never rebind the socket")
	}
	if strings.Contains(got, "private_key") {
		t.Error("an incremental update must not resend the private key")
	}
	if strings.Contains(got, a.Hex()) {
		t.Error("an unchanged peer was reconfigured, which costs it a handshake")
	}
	if !strings.Contains(got, "allowed_ip=10.99.0.9/32") {
		t.Error("the readdressed peer did not get its new address")
	}
	if !strings.Contains(got, "allowed_ip=10.99.0.4/32") {
		t.Error("the new peer was not added")
	}

	// And a peer that leaves the network is removed rather than left behind.
	gone := wgUpdate(next, wgPeers(mapWith(peerNode("alpha", a, "10.99.0.2"))))
	for _, k := range []key.WGPublic{b, c} {
		if !strings.Contains(gone, "public_key="+k.Hex()+"\nremove=true\n") {
			t.Errorf("peer %s was not removed:\n%s", k.Hex(), gone)
		}
	}
}

// TestWGConfigIsWholeOnlyAtStartup: the full form still has to be complete,
// because it is what the device is built from.
func TestWGConfigIsWholeOnlyAtStartup(t *testing.T) {
	priv, _, err := key.NewWG()
	if err != nil {
		t.Fatal(err)
	}
	st := &State{WGKey: priv, ListenPort: DefaultListenPort}
	cfg := wgConfig(st, mapWith(peerNode("beta", wgKey(1), "10.99.0.3")))

	for _, want := range []string{
		"private_key=" + priv.Hex(),
		"listen_port=41820",
		"replace_peers=true",
		"allowed_ip=10.99.0.3/32",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("the initial configuration is missing %q:\n%s", want, cfg)
		}
	}
}

// TestWGPeersIgnoresUnusableEntries: a peer with no key or no address cannot
// be configured, and must not silently become one that can.
func TestWGPeersIgnoresUnusableEntries(t *testing.T) {
	got := wgPeers(mapWith(
		netmap.Node{Name: "nokey", IP: netip.MustParseAddr("10.99.0.5")},
		netmap.Node{Name: "noaddr", WGKey: wgKey(7)},
		peerNode("good", wgKey(8), "10.99.0.6"),
	))
	if len(got) != 1 {
		t.Fatalf("wgPeers returned %d entries, want just the usable one: %v", len(got), got)
	}
}
