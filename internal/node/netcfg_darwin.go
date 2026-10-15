package node

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
)

// configureInterface gives the tunnel an address and a route on macOS.
//
// Each step runs on its own rather than as one long ifconfig line. That is not
// tidiness: if this fails the tunnel never comes up, the hub poll loop never
// starts, and every other machine quietly shows this one as offline while
// `locnet peers` still answers from the map cached at join. One combined
// command that fails tells you only that "ifconfig failed"; these say which
// part, which is the difference between a fix and a guess.
func configureInterface(ifName string, ip netip.Addr, prefix netip.Prefix, mtu int) error {
	// utun devices are point-to-point, so ifconfig wants the address twice:
	// once as the local address and once as the peer. Passing the node's own
	// address for both is the usual idiom for an interface whose real peers
	// are reached through a route rather than through the link.
	if err := run("ifconfig", ifName, "inet", ip.String(), ip.String(),
		"netmask", "255.255.255.255"); err != nil {
		return fmt.Errorf("assign %s to %s: %w", ip, ifName, err)
	}

	// MTU is best-effort. The device already has a workable MTU from the
	// moment it was created, and some macOS releases refuse SIOCSIFMTU on
	// utun even for a legal value. Failing the whole bring-up over a number
	// that is already close enough would trade a working tunnel for a tidy
	// one.
	if mtu > 0 {
		if err := run("ifconfig", ifName, "mtu", strconv.Itoa(mtu)); err != nil {
			fmt.Printf("locnetd: could not set MTU %d on %s (%v); "+
				"keeping the device default\n", mtu, ifName, err)
		}
	}

	if err := run("ifconfig", ifName, "up"); err != nil {
		return fmt.Errorf("bring %s up: %w", ifName, err)
	}

	// `route add` fails if the route already exists, which it does after a
	// restart that did not clean up. Change it in that case rather than
	// treating a working route as an error.
	if err := run("route", "-q", "-n", "add", "-inet", prefix.String(), "-interface", ifName); err != nil {
		if err2 := run("route", "-q", "-n", "change", "-inet", prefix.String(), "-interface", ifName); err2 != nil {
			return fmt.Errorf("route %s via %s: %v (and change failed: %v)", prefix, ifName, err, err2)
		}
	}
	return nil
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
