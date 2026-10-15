package node

import (
	"net/netip"
	"testing"

	"github.com/mahantsunandan/locnet/internal/resource"
)

// A machine that may open no connections can never get its services
// confirmed by asking a peer, so the peers that connect to it confirm them
// themselves — without touching the netmap's slice, which other readers share.
func TestMarkReachedConfirmsWhatThisMachineConnectedTo(t *testing.T) {
	ip := netip.MustParseAddr("10.99.0.3")
	services := []resource.Service{{Name: "ssh", Port: 22}, {Name: "rdp", Port: 3389}}
	reached := map[netip.AddrPort]bool{netip.AddrPortFrom(ip, 22): true}

	got := markReached(ip, services, reached)
	if !got[0].Verified || got[1].Verified {
		t.Errorf("got %+v, want ssh confirmed and rdp not", got)
	}
	if services[0].Verified {
		t.Error("the netmap's own slice was modified")
	}

	other := netip.MustParseAddr("10.99.0.4")
	if out := markReached(other, services, reached); out[0].Verified {
		t.Error("a port reached on one machine confirmed it on another")
	}
}
