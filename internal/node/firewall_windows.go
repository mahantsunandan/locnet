package node

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
)

// adapterGUID is the tunnel adapter's identity, the same on every start.
//
// Without it wintun picks a random GUID each time the service starts, and
// Windows' network location service treats every one as a network it has never
// seen: a new "Unidentified network", filed under the Public firewall profile.
// Anything set on the previous one — its category, a rule scoped to it — is
// gone after a restart. A fixed GUID makes it one network that Windows
// remembers. Every machine can share it; it only has to be stable per machine.
var adapterGUID = windows.GUID{
	Data1: 0x56f23679, Data2: 0xdb7f, Data3: 0x4a93,
	Data4: [8]byte{0x8a, 0xdd, 0x2b, 0xd7, 0xd3, 0xb4, 0x79, 0x0a},
}

func init() { tun.WintunStaticRequestedGUID = &adapterGUID }

// firewallRuleName is the one inbound rule locnetd keeps for itself.
const firewallRuleName = "LocNet-locnetd"

// trustOverlay makes the Windows firewall let peers in, the way it already
// does on Linux and macOS.
//
// Found on the first Windows machine joined from outside the house: every peer
// could reach RDP and nothing else. Windows had filed the tunnel under the
// Public profile, where the OpenSSH rule (Private only) does not apply, and
// locnetd's own share port had no rule at all — a service is not offered the
// "allow this app" prompt, it is silently blocked. So `locnet join` reported
// port 22 and 8421 as "listening here but blocked" on a machine where both
// were running.
//
// Two changes, both scoped to the overlay:
//
//   - The adapter is marked Private, which is what Tailscale does with its own.
//     Windows then applies the same rules to peers as to the home LAN, and
//     LocNet's port policy (filter.go) stays the real gate in front of them.
//   - locnetd gets an inbound rule for traffic from the overlay prefix only,
//     covering the share server and every port share it binds.
//
// Neither is fatal. A failure here leaves the tunnel working and some ports
// unreachable, which the reachability check at join reports by name.
func trustOverlay(ifName string, prefix netip.Prefix, logf func(string, ...any)) {
	if exe, err := os.Executable(); err != nil {
		logf("firewall: cannot find locnetd's own path: %v", err)
	} else if err := runPS(fmt.Sprintf(
		`Remove-NetFirewallRule -Name %s -ErrorAction SilentlyContinue; `+
			`New-NetFirewallRule -Name %s -DisplayName 'LocNet (locnetd)' `+
			`-Description 'Lets LocNet peers reach this machine''s shares. Recreated by locnetd at every start.' `+
			`-Direction Inbound -Action Allow -Profile Any -Program %s -RemoteAddress %s | Out-Null`,
		psQuote(firewallRuleName), psQuote(firewallRuleName), psQuote(exe), psQuote(prefix.String()))); err != nil {
		logf("firewall: could not allow peers in to locnetd: %v", err)
	}

	// The network location service needs a moment to file a new adapter
	// under any profile at all, and until it has, there is nothing to change.
	script := fmt.Sprintf(
		`$p = Get-NetConnectionProfile -InterfaceAlias %[1]s -ErrorAction Stop; `+
			`if ($p.NetworkCategory -eq 'Public') { `+
			`Set-NetConnectionProfile -InterfaceAlias %[1]s -NetworkCategory Private -ErrorAction Stop }`,
		psQuote(ifName))
	var err error
	for i := 0; i < 10; i++ {
		if err = runPS(script); err == nil {
			return
		}
		time.Sleep(3 * time.Second)
	}
	logf("firewall: could not mark %s as a private network, so rules for the Private profile will not apply to peers: %v", ifName, err)
}

func runPS(script string) error {
	return run("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
}

// psQuote makes a PowerShell single-quoted string literal.
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
