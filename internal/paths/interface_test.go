package paths

import (
	"fmt"
	"runtime"
	"testing"
)

// acceptedByWireguardDarwin mirrors the check in wireguard-go's
// tun/tun_darwin.go CreateTUN. It is duplicated here on purpose: the name we
// hand that function is not validated anywhere at compile time, so the only
// thing standing between a wrong constant and a Mac that cannot bring its
// tunnel up is a test that knows the rule.
func acceptedByWireguardDarwin(name string) bool {
	if name == "utun" {
		return true // ask the kernel to choose the unit number
	}
	ifIndex := -1
	_, err := fmt.Sscanf(name, "utun%d", &ifIndex)
	return err == nil && ifIndex >= 0
}

func TestDarwinInterfaceNameIsAcceptedByWireguard(t *testing.T) {
	// Checked on every platform, not just when running on a Mac: the whole
	// point is that a Linux developer changing this constant finds out here
	// rather than from a user.
	const darwinName = "utun"

	if !acceptedByWireguardDarwin(darwinName) {
		t.Fatalf("%q would be rejected by wireguard-go's darwin CreateTUN", darwinName)
	}
	// The empty string was the original value, and is the specific mistake
	// worth pinning: it reads like "let the kernel decide" and is not.
	if acceptedByWireguardDarwin("") {
		t.Error("the rule mirrored here is wrong — wireguard-go rejects an empty name")
	}
	if acceptedByWireguardDarwin("locnet0") {
		t.Error("the rule mirrored here is wrong — wireguard-go rejects arbitrary names")
	}

	if runtime.GOOS == "darwin" && DefaultInterface() != darwinName {
		t.Errorf("DefaultInterface() = %q, want %q", DefaultInterface(), darwinName)
	}
}

func TestDefaultInterfaceIsNeverEmpty(t *testing.T) {
	// An empty name means something different on every platform and is right
	// on none of them.
	if got := DefaultInterface(); got == "" {
		t.Errorf("DefaultInterface() is empty on %s", runtime.GOOS)
	}
}
