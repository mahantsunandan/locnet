package resource

import (
	"net"
	"net/netip"
	"strings"
)

// LANIface is one of a machine's real network interfaces: its hardware
// address and the subnets it sits on.
//
// This is here for one reason — waking a machine that is switched off. A magic
// packet has to carry the target's MAC address and has to be broadcast onto
// the target's own subnet, so both facts must be known before the machine goes
// to sleep, by something that is still awake. The mesh already collects a
// report from every machine on a timer; this is two more fields on it.
type LANIface struct {
	Name string `json:"name"`
	MAC  string `json:"mac"`
	// Nets are the IPv4 subnets this interface is on, in CIDR form.
	Nets []netip.Prefix `json:"nets,omitempty"`
}

// LocalInterfaces describes this machine's physical network interfaces.
//
// Loopback, the tunnel itself and the virtual bridges that container runtimes
// leave lying around are all skipped: none of them is a place a magic packet
// could arrive from, and listing them would only make the choice of where to
// send one harder.
func LocalInterfaces() []LANIface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []LANIface
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagLoopback != 0 || ifi.Flags&net.FlagUp == 0 {
			continue
		}
		if len(ifi.HardwareAddr) != 6 || isVirtualIface(ifi.Name) {
			continue
		}
		li := LANIface{Name: ifi.Name, MAC: ifi.HardwareAddr.String()}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipNet.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if !ip.Is4() || ip.IsLinkLocalUnicast() {
				continue
			}
			ones, _ := ipNet.Mask.Size()
			// Kept unmasked: the host bits are this machine's own address,
			// which is what tells you whether it shares a subnet with the
			// machine you are trying to wake. Contains works either way.
			li.Nets = append(li.Nets, netip.PrefixFrom(ip, ones))
		}
		if len(li.Nets) == 0 {
			continue
		}
		out = append(out, li)
	}
	return out
}

// virtualPrefixes are interface names that belong to something other than a
// cable or a radio.
var virtualPrefixes = []string{
	"locnet", "docker", "br-", "veth", "virbr", "vmnet", "tun", "tap",
	"cni", "flannel", "kube", "zt", "tailscale", "wg",
}

func isVirtualIface(name string) bool {
	lower := strings.ToLower(name)
	for _, p := range virtualPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// SameSubnet reports whether any of these interfaces is on a subnet that
// contains addr — that is, whether this machine could put a broadcast in front
// of a machine at that address.
func SameSubnet(ifaces []LANIface, addr netip.Addr) bool {
	for _, li := range ifaces {
		for _, n := range li.Nets {
			if n.Contains(addr) {
				return true
			}
		}
	}
	return false
}

// Addrs returns every address on these interfaces.
func Addrs(ifaces []LANIface) []netip.Addr {
	var out []netip.Addr
	for _, li := range ifaces {
		for _, n := range li.Nets {
			out = append(out, n.Addr())
		}
	}
	return out
}

// MACs returns every hardware address, which is what a magic packet needs.
func MACs(ifaces []LANIface) []string {
	var out []string
	for _, li := range ifaces {
		if li.MAC != "" {
			out = append(out, li.MAC)
		}
	}
	return out
}
