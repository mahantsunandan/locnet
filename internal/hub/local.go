package hub

import (
	"net"
	"net/http"
	"net/netip"
)

// isLocalAddr reports whether ip belongs to this machine.
//
// It answers one question: is the node that just registered running on the hub
// machine itself? That machine is special in a way worth showing — everything
// else depends on it to find each other, so it is the one you think twice
// about rebooting — and nothing else in the protocol reveals it. The hub does
// not know its own node ID, because a node's identity is a key it generates
// locally and the hub only ever sees the public half.
//
// Asking where the registration came from settles it without adding
// configuration for the operator to get wrong. A node on the hub machine
// reaches the hub over loopback or over one of the machine's own interface
// addresses; no other node can.
func isLocalAddr(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	ip = ip.Unmap()

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		local, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		if local.Unmap() == ip {
			return true
		}
	}
	return false
}

// isLocalRequest reports whether r came from this machine.
//
// The first test needs nothing but the connection itself: a client on this
// machine that dials one of its own addresses arrives *from* that same address,
// so the two ends of the connection match. That matters because the
// interface-list fallback below needs a netlink socket on Linux, and the hub's
// systemd unit allows only AF_INET and AF_INET6 — so under systemd the list
// always came back empty, and no machine was ever marked as the hub.
func isLocalRequest(r *http.Request) bool {
	remote := remoteIP(r.RemoteAddr)
	if !remote.IsValid() {
		return false
	}
	if la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		if local := remoteIP(la.String()); local.IsValid() && local.Unmap() == remote.Unmap() {
			return true
		}
	}
	return isLocalAddr(remote)
}

// remoteIP extracts the address a request came from.
func remoteIP(remoteAddr string) netip.Addr {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return ip
}
