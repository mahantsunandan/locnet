package node

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
)

// tailscaleRange is the carrier-grade NAT block Tailscale assigns from. Any
// LocNet prefix inside it is a coin flip away from a clash on a machine that
// runs both.
var tailscaleRange = netip.MustParsePrefix("100.64.0.0/10")

// CheckPrefixConflicts looks for anything already on this machine that would
// fight with the overlay range.
//
// This exists because the failure it catches is miserable to debug from the
// symptom. An overlapping route does not produce an error; it produces traffic
// that silently goes to the wrong interface, and the two networks involved
// both look healthy from their own side.
//
// Everything here is best-effort and read-only. It never changes a route.
// ownIface is this machine's own tunnel interface, which must never be
// reported as a conflict with itself. Passing it in rather than guessing
// matters on macOS: the device there is named utunN, chosen by the kernel, and
// no name pattern can tell LocNet's utun from anyone else's.
func CheckPrefixConflicts(prefix netip.Prefix, ownIface string) []string {
	if !prefix.IsValid() {
		return nil
	}
	var warnings []string

	// 1. Another interface holding an address inside our range.
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, ifc := range ifaces {
			if ifc.Flags&net.FlagUp == 0 || isOurInterface(ifc.Name, ownIface) {
				continue
			}
			addrs, err := ifc.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				ipn, ok := a.(*net.IPNet)
				if !ok {
					continue
				}
				ip, ok := netip.AddrFromSlice(ipn.IP)
				if !ok {
					continue
				}
				if prefix.Contains(ip.Unmap()) {
					warnings = append(warnings, fmt.Sprintf(
						"interface %s already holds %s, which is inside the LocNet range %s",
						ifc.Name, ip.Unmap(), prefix))
				}
			}
		}
	}

	// 2. A route that covers our range. This is the Tailscale case: its
	//    interface address is a single /32, but it installs a route for the
	//    whole /10, so an address check alone would miss it.
	for _, r := range systemRoutes(ownIface) {
		if r.Overlaps(prefix) {
			warnings = append(warnings, fmt.Sprintf(
				"the routing table already sends %s somewhere else, and it overlaps the LocNet range %s",
				r, prefix))
		}
	}

	// 3. The specific, likely case, called out by name.
	if prefix.Overlaps(tailscaleRange) && hasTailscale() {
		warnings = append(warnings, fmt.Sprintf(
			"Tailscale is running on this machine and claims %s, which overlaps %s.\n"+
				"    Give LocNet a range outside it — the hub's -prefix flag, on first run only.",
			tailscaleRange, prefix))
	}
	return dedupe(warnings)
}

// isOurInterface reports whether a name is one LocNet created, so the check
// does not warn about the tunnel it just brought up.
func isOurInterface(name, ownIface string) bool {
	// The name we were actually given wins. The prefix match is a fallback
	// for callers that do not know it yet — and on macOS it never matches,
	// which is exactly why ownIface exists.
	if ownIface != "" && name == ownIface {
		return true
	}
	return strings.HasPrefix(name, "locnet") || name == "LocNet"
}

func hasTailscale() bool {
	if ifaces, err := net.Interfaces(); err == nil {
		for _, ifc := range ifaces {
			if strings.HasPrefix(ifc.Name, "tailscale") {
				return true
			}
		}
	}
	// macOS names its utun devices generically, so fall back to the binary.
	_, err := exec.LookPath("tailscale")
	return err == nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
