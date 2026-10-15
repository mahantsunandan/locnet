//go:build !windows

package node

import "net/netip"

// trustOverlay has nothing to do outside Windows: neither Linux nor macOS
// firewalls a new interface by default.
func trustOverlay(ifName string, prefix netip.Prefix, logf func(string, ...any)) {}
