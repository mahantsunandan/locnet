package wake

import (
	"net/netip"
	"testing"

	"github.com/mahantsunandan/locnet/internal/resource"
)

func TestMagicPacket(t *testing.T) {
	pkt, err := MagicPacket("01:23:45:67:89:ab")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkt) != 102 {
		t.Fatalf("packet is %d bytes, wanted 102", len(pkt))
	}
	for i := 0; i < 6; i++ {
		if pkt[i] != 0xff {
			t.Fatalf("byte %d of the header is %#x, wanted 0xff", i, pkt[i])
		}
	}
	want := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab}
	for rep := 0; rep < 16; rep++ {
		for i, b := range want {
			if got := pkt[6+rep*6+i]; got != b {
				t.Fatalf("repetition %d byte %d is %#x, wanted %#x", rep, i, got, b)
			}
		}
	}

	if _, err := MagicPacket("not a mac"); err == nil {
		t.Error("a nonsense address was accepted")
	}
}

func TestBroadcastFor(t *testing.T) {
	cases := map[string]string{
		"192.168.1.5/24": "192.168.1.255",
		"10.0.0.7/8":     "10.255.255.255",
		"172.16.4.9/20":  "172.16.15.255",
		"192.168.1.5/32": "192.168.1.5",
	}
	for in, want := range cases {
		p := netip.MustParsePrefix(in)
		if got := broadcastFor(p); got.String() != want {
			t.Errorf("broadcastFor(%s) = %s, wanted %s", in, got, want)
		}
	}
}

func TestChoosePrefersThisMachine(t *testing.T) {
	target := []resource.LANIface{{MAC: "aa:bb:cc:dd:ee:ff",
		Nets: []netip.Prefix{netip.MustParsePrefix("192.168.1.50/24")}}}

	self := []resource.LANIface{{Nets: []netip.Prefix{netip.MustParsePrefix("192.168.1.9/24")}}}
	peers := map[string][]resource.LANIface{
		"lab-1": {{Nets: []netip.Prefix{netip.MustParsePrefix("192.168.1.20/24")}}},
	}

	w, ok := Choose(target, self, peers)
	if !ok {
		t.Fatal("nobody was chosen although this machine is on the same subnet")
	}
	if w.Name != "" {
		t.Errorf("chose %q; this machine is on the subnet and should send it itself", w.Name)
	}
}

func TestChooseFindsAPeerOnTheRightSubnet(t *testing.T) {
	target := []resource.LANIface{{MAC: "aa:bb:cc:dd:ee:ff",
		Nets: []netip.Prefix{netip.MustParsePrefix("10.4.0.50/24")}}}

	// This machine is somewhere else entirely — a broadcast from here would
	// never cross the router.
	self := []resource.LANIface{{Nets: []netip.Prefix{netip.MustParsePrefix("192.168.1.9/24")}}}
	peers := map[string][]resource.LANIface{
		"far":  {{Nets: []netip.Prefix{netip.MustParsePrefix("172.16.0.5/24")}}},
		"near": {{Nets: []netip.Prefix{netip.MustParsePrefix("10.4.0.11/24")}}},
	}

	w, ok := Choose(target, self, peers)
	if !ok {
		t.Fatal("no peer was chosen although one is on the target's subnet")
	}
	if w.Name != "near" {
		t.Errorf("chose %q, wanted near", w.Name)
	}
}

func TestChooseGivesUpWhenNobodyCanReachIt(t *testing.T) {
	target := []resource.LANIface{{MAC: "aa:bb:cc:dd:ee:ff",
		Nets: []netip.Prefix{netip.MustParsePrefix("10.4.0.50/24")}}}
	self := []resource.LANIface{{Nets: []netip.Prefix{netip.MustParsePrefix("192.168.1.9/24")}}}
	peers := map[string][]resource.LANIface{
		"far": {{Nets: []netip.Prefix{netip.MustParsePrefix("172.16.0.5/24")}}},
	}
	if _, ok := Choose(target, self, peers); ok {
		t.Error("a machine on another network was chosen; its packet would go nowhere")
	}
}
