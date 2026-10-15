package node

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// configureInterface gives the tunnel an address and a route on Windows.
//
// Unlike Linux and macOS, the address is set with the overlay's real mask.
// Windows creates the on-link route for the prefix from that automatically,
// and adding a second explicit route on top produces a duplicate that the
// stack complains about on every restart.
func configureInterface(ifName string, ip netip.Addr, prefix netip.Prefix, mtu int) error {
	mask := net.CIDRMask(prefix.Bits(), 32)
	maskStr := fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])

	// Duplicate address detection has nothing to detect on a point-to-point
	// tunnel, and while it runs (about three seconds) the address is
	// "Tentative" and cannot be bound. The share server binds it straight
	// after this returns, so with DAD on it failed on every start and the
	// machine never served a share. wireguard-windows turns it off for the
	// same reason. Failure here is not fatal: the wait below covers it.
	run("netsh", "interface", "ipv4", "set", "interface", ifName, "dadtransmits=0")

	if err := run("netsh", "interface", "ipv4", "set", "address",
		"name="+ifName, "source=static", "addr="+ip.String(), "mask="+maskStr); err != nil {
		return err
	}
	if err := run("netsh", "interface", "ipv4", "set", "subinterface",
		ifName, "mtu="+strconv.Itoa(mtu), "store=persistent"); err != nil {
		// An MTU that will not stick is a performance problem, not a
		// connectivity one. Report it and carry on.
		return fmt.Errorf("set mtu on %s: %w", ifName, err)
	}
	return waitForAddress(ip, 15*time.Second)
}

// waitForAddress returns once ip can be bound, which is the thing every caller
// after this actually needs. Asking the stack whether the address is
// "Preferred" would mean parsing localised netsh output; trying a bind cannot
// be misread.
func waitForAddress(ip netip.Addr, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		c, err := net.ListenPacket("udp4", netip.AddrPortFrom(ip, 0).String())
		if err == nil {
			c.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s was set but is still not usable after %s: %w", ip, timeout, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), msg)
	}
	return nil
}
