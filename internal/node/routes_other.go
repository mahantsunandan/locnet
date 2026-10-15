//go:build !linux

package node

import "net/netip"

// systemRoutes returns nothing on macOS and Windows.
//
// Both have a routing table worth reading, and both need a different parser
// (`netstat -rn` and `route print`, each with its own locale-dependent
// output). Rather than ship two fragile parsers for a diagnostic, the conflict
// check falls back to comparing interface addresses, which catches the common
// cases. The explicit Tailscale check covers the one that matters most.
func systemRoutes(ownIface string) []netip.Prefix { return nil }
