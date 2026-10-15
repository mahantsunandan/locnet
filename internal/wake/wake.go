// Package wake sends Wake-on-LAN magic packets.
//
// A machine that is switched off is the one machine a mesh cannot help with,
// because there is nothing there to run an agent. But a machine on the same
// piece of Ethernet can still shout at its network card, which stays powered
// exactly for this. So LocNet does not wake a machine itself — it asks a peer
// that is on the right subnet to do it, and it knows which peer that is
// because every node reports the subnets it sits on.
//
// The packet is trivially forgeable and carries no authentication; that is the
// standard, not a shortcut here. The gate is on the asking: only a member of
// the network can ask a peer to send one, and the worst a member can do with
// that is turn a computer on.
package wake

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/mahantsunandan/locnet/internal/resource"
)

// Port is where magic packets are conventionally sent. Nothing listens: the
// network card matches the pattern in the frame, not the port.
const Port = 9

// MagicPacket builds the 102-byte frame for one hardware address: six 0xff
// bytes, then the address sixteen times.
func MagicPacket(mac string) ([]byte, error) {
	hw, err := net.ParseMAC(strings.TrimSpace(mac))
	if err != nil {
		return nil, fmt.Errorf("%q is not a hardware address: %w", mac, err)
	}
	if len(hw) != 6 {
		return nil, fmt.Errorf("%q is not a six-byte hardware address", mac)
	}
	pkt := make([]byte, 0, 102)
	for i := 0; i < 6; i++ {
		pkt = append(pkt, 0xff)
	}
	for i := 0; i < 16; i++ {
		pkt = append(pkt, hw...)
	}
	return pkt, nil
}

// Send broadcasts a magic packet for each address in macs.
//
// It sends to every local subnet's broadcast address as well as to the
// all-ones address, because which one gets through depends on the switch, the
// operating system and whether anything is doing directed-broadcast filtering.
// They are cheap, and one arriving is all that is needed.
func Send(macs []string, ifaces []resource.LANIface) (sent int, err error) {
	targets := broadcastAddrs(ifaces)
	if len(targets) == 0 {
		return 0, fmt.Errorf("this machine is not on any local network, so it cannot wake anything")
	}

	var firstErr error
	for _, mac := range macs {
		pkt, err := MagicPacket(mac)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, dst := range targets {
			conn, err := net.DialTimeout("udp4",
				netip.AddrPortFrom(dst, Port).String(), 2*time.Second)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			_, werr := conn.Write(pkt)
			conn.Close()
			if werr != nil {
				if firstErr == nil {
					firstErr = werr
				}
				continue
			}
			sent++
		}
	}
	if sent == 0 && firstErr != nil {
		return 0, firstErr
	}
	return sent, nil
}

// broadcastAddrs returns every address worth sending to.
func broadcastAddrs(ifaces []resource.LANIface) []netip.Addr {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	add := func(a netip.Addr) {
		if a.IsValid() && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	for _, li := range ifaces {
		for _, n := range li.Nets {
			add(broadcastFor(n))
		}
	}
	add(netip.AddrFrom4([4]byte{255, 255, 255, 255}))
	return out
}

// broadcastFor is the all-hosts address of a subnet: the network address with
// every host bit set.
func broadcastFor(p netip.Prefix) netip.Addr {
	if !p.Addr().Is4() {
		return netip.Addr{}
	}
	base := p.Masked().Addr().As4()
	bits := p.Bits()
	if bits < 0 || bits > 32 {
		return netip.Addr{}
	}
	host := uint32(0xffffffff) >> uint(bits)
	v := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	v |= host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// Waker describes a machine that could deliver the packet.
type Waker struct {
	// Name is the peer that will send it, empty for this machine.
	Name string
	// Reason says why it was chosen, for the line printed to the user.
	Reason string
}

// Choose picks who should send the packet.
//
// The rule is simply "someone on the same subnet as the machine was when it
// was last awake". A machine on a different subnet can send all the magic
// packets it likes and none of them will cross the router.
func Choose(target []resource.LANIface, self []resource.LANIface,
	peers map[string][]resource.LANIface) (Waker, bool) {

	addrs := resource.Addrs(target)
	for _, a := range addrs {
		if resource.SameSubnet(self, a) {
			return Waker{Reason: fmt.Sprintf("this machine is on %s too", a)}, true
		}
	}
	for name, ifaces := range peers {
		for _, a := range addrs {
			if resource.SameSubnet(ifaces, a) {
				return Waker{Name: name, Reason: fmt.Sprintf("%s is on %s too", name, a)}, true
			}
		}
	}
	return Waker{}, false
}
