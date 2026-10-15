package node

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
)

// configureInterface gives the tunnel an address and a route on Linux.
//
// The address is added as a /32 and the overlay prefix as an explicit route,
// rather than adding the address as a /16 and letting the kernel infer the
// subnet route. The difference matters: a /16 on the interface would make the
// kernel treat every address in the overlay as directly attached, including
// ones no peer has claimed, and traffic to those would vanish into the tunnel
// instead of being refused.
func configureInterface(ifName string, ip netip.Addr, prefix netip.Prefix, mtu int) error {
	steps := [][]string{
		{"ip", "link", "set", "dev", ifName, "mtu", strconv.Itoa(mtu)},
		{"ip", "address", "replace", ip.String() + "/32", "dev", ifName},
		{"ip", "link", "set", "dev", ifName, "up"},
		{"ip", "route", "replace", prefix.String(), "dev", ifName},
	}
	for _, step := range steps {
		if err := run(step[0], step[1:]...); err != nil {
			return err
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
