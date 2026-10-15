package node

import (
	"net/netip"
	"testing"
)

// TestOurOwnInterfaceIsNeverAConflict is the macOS case.
//
// On Linux the tunnel is called locnet0 and the name pattern catches it. On
// macOS the kernel picks the name — utun5, utun7, whatever is free — and no
// pattern can distinguish LocNet's utun from Tailscale's or a VPN client's.
// Without the name being passed in, LocNet reported its own address as
// something conflicting with itself, which sends people looking for a clash
// that does not exist.
func TestOurOwnInterfaceIsNeverAConflict(t *testing.T) {
	cases := []struct {
		name, ifName, own string
		want              bool
	}{
		{"macOS tunnel, named", "utun5", "utun5", true},
		{"macOS tunnel, a different utun", "utun5", "utun7", false},
		{"linux tunnel by pattern", "locnet0", "", true},
		{"windows tunnel by name", "LocNet", "", true},
		{"someone else's tunnel", "utun3", "", false},
		{"an ordinary interface", "en0", "utun5", false},
	}
	for _, c := range cases {
		if got := isOurInterface(c.ifName, c.own); got != c.want {
			t.Errorf("%s: isOurInterface(%q, %q) = %v, want %v",
				c.name, c.ifName, c.own, got, c.want)
		}
	}
}

// TestConflictCheckIsSafeWithoutAnInterfaceName: the checker also runs before
// the tunnel exists, and must not fall over when there is no name to exclude.
func TestConflictCheckIsSafeWithoutAnInterfaceName(t *testing.T) {
	prefix := netip.MustParsePrefix("10.99.0.0/16")
	// Running it is the test — it reads real interfaces and must not panic
	// whether or not this machine happens to have a conflict.
	_ = CheckPrefixConflicts(prefix, "")
	_ = CheckPrefixConflicts(prefix, "utun5")
}

func TestInvalidPrefixReportsNothing(t *testing.T) {
	if got := CheckPrefixConflicts(netip.Prefix{}, "utun5"); got != nil {
		t.Errorf("an invalid prefix should produce no warnings, got %v", got)
	}
}
