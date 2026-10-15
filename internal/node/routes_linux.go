package node

import (
	"net/netip"
	"os/exec"
	"strings"
)

// systemRoutes lists the IPv4 destinations in the routing table.
//
// Parsing `ip route` rather than opening a netlink socket: this runs once at
// startup to produce a warning, and a netlink dependency would be a lot of
// machinery for a diagnostic. If `ip` is missing the check simply finds
// nothing, which degrades to the interface-address check above it.
func systemRoutes(ownIface string) []netip.Prefix {
	out, err := exec.Command("ip", "-4", "route", "show").Output()
	if err != nil {
		return nil
	}

	var routes []netip.Prefix
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		dst := fields[0]
		if dst == "default" || dst == "broadcast" || dst == "local" {
			continue
		}
		// A bare address in the routing table means a host route.
		if !strings.Contains(dst, "/") {
			dst += "/32"
		}
		p, err := netip.ParsePrefix(dst)
		if err != nil || !p.Addr().Is4() {
			continue
		}
		// Ignore the routes for our own tunnel and anything link-local.
		if isOurRouteDevice(fields, ownIface) || p.Addr().IsLinkLocalUnicast() {
			continue
		}
		routes = append(routes, p)
	}
	return routes
}

func isOurRouteDevice(fields []string, ownIface string) bool {
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) && isOurInterface(fields[i+1], ownIface) {
			return true
		}
	}
	return false
}
