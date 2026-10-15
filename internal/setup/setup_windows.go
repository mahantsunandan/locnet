package setup

import (
	"fmt"
	"strings"
)

type distro struct{ id, name string }

func detectDistro() distro { return distro{id: "windows", name: "Windows"} }

// sshPort is the port a peer connects to for a shell. The firewall rule names
// below are the two that can legitimately be admitting it: the one this code
// creates, and the one the OpenSSH capability is documented to create and
// sometimes does.
const (
	sshPort        = 22
	sshRuleOurs    = "sshd"
	sshRuleBuiltin = "OpenSSH-Server-In-TCP"
	rdpRuleBuiltin = "RemoteDesktop-UserMode-In-TCP"
)

func planFor() ([]Step, error) {
	return []Step{
		// OpenSSH Server ships as an optional capability from Windows 10 1809
		// onwards. DISM is the scriptable way in; PowerShell's
		// Add-WindowsCapability does the same thing.
		//
		// The firewall command is the reason this step exists in its current
		// shape. The capability install is documented to create an inbound
		// rule for port 22 and frequently does not, which leaves a machine
		// with sshd installed, automatic, running — and unreachable. Microsoft
		// says to check for the rule and create it by hand; this does that.
		{
			Name:   "OpenSSH server",
			Why:    "so `locnet ssh <this machine>` works from a peer",
			Done:   serviceRunning("sshd") && firewallRuleEnabled(sshRuleOurs, sshRuleBuiltin),
			Detail: "installed, running, allowed through the firewall",
			Commands: [][]string{
				{"dism", "/online", "/Add-Capability", "/CapabilityName:OpenSSH.Server~~~~0.0.1.0"},
				{"sc", "config", "sshd", "start=", "auto"},
				{"net", "start", "sshd"},
				powershell(fmt.Sprintf(
					`if (-not (Get-NetFirewallRule -Name sshd -ErrorAction SilentlyContinue)) { `+
						`New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' `+
						`-Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort %d | Out-Null }`,
					sshPort)),
			},
		},
		// Remote Desktop is Windows's screen server, and it is already
		// present on Pro and above — it just needs switching on. Two registry
		// values and a firewall rule is the documented way, and it is what
		// the Settings app does. There is no VNC server in the box, so this
		// is the screen-sharing half of the setup here.
		{
			Name:   "Remote Desktop",
			Why:    "so a peer's RDP client can show this machine's screen",
			Done:   rdpEnabled() && firewallRuleEnabled(rdpRuleBuiltin),
			Detail: "enabled, allowed through the firewall",
			Commands: [][]string{
				{"reg", "add", `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`,
					"/v", "fDenyTSConnections", "/t", "REG_DWORD", "/d", "0", "/f"},
				{"netsh", "advfirewall", "firewall", "set", "rule",
					"group=remote desktop", "new", "enable=Yes"},
			},
			Manual: "Home editions of Windows have no Remote Desktop server. Install\n" +
				"a VNC server there instead — TightVNC and TigerVNC both work.",
		},
		tightVNCStep(),
	}, nil
}

// TightVNC's service settings, and the values LocNet needs in them.
const (
	tightVNCKey     = `HKLM\SOFTWARE\TightVNC\Server`
	tightVNCService = "tvnserver"
)

// tightVNCStep puts an installed TightVNC behind LocNet, the way the Linux VNC
// server already is: listening on loopback only, with no VNC password, and
// published to peers by a port share (see publishScreenShare). The share is
// the gate — it checks the peer's WireGuard identity against its allow list
// before connecting anything — so a VNC password adds nothing but one more
// secret to lose. That is not hypothetical: the first Windows machine joined
// had TightVNC asking every viewer for a password nobody remembered setting.
//
// Loopback-only is what makes dropping the password safe. Without it TightVNC
// listens on every interface, and its installer opens the firewall on every
// profile, so a password-free server would be open to the whole café Wi-Fi.
//
// The port moves to 5901 so the share can own 5900 on the overlay address
// without the two ever contending for it.
func tightVNCStep() Step {
	s := Step{
		Name:   "Screen sharing (VNC)",
		Why:    "so `locnet vnc <this machine>` shows this screen, gated by LocNet instead of a VNC password",
		Detail: fmt.Sprintf("TightVNC on 127.0.0.1:%d, no password, published to peers on port 5900", VNCPort()),
	}
	if !serviceExists(tightVNCService) {
		s.Manual = "No VNC server is installed. Install TightVNC (https://www.tightvnc.com, or\n" +
			"`winget install -e --id GlavSoft.TightVNC`), then run `locnet setup -install` again."
		return s
	}
	s.Done = tightVNCReady()
	set := func(name string, v int) []string {
		return []string{"reg", "add", tightVNCKey, "/v", name, "/t", "REG_DWORD", "/d", fmt.Sprint(v), "/f"}
	}
	s.Commands = [][]string{
		set("RfbPort", VNCPort()),
		set("LoopbackOnly", 1),
		set("AllowLoopback", 1),
		set("UseVncAuthentication", 0),
		// A restart, then proof: the settings on disk are not the server.
		powershell(fmt.Sprintf(
			`Restart-Service -Name %s -Force; `+
				`for ($i = 0; $i -lt 40; $i++) { `+
				`if (Get-NetTCPConnection -LocalPort %d -State Listen -ErrorAction SilentlyContinue) { exit 0 }; `+
				`Start-Sleep -Milliseconds 500 }; `+
				`Write-Error 'TightVNC restarted but is not listening on port %d'; exit 1`,
			tightVNCService, VNCPort(), VNCPort())),
	}
	return s
}

// tightVNCReady checks the running server, not just its settings: the
// registry can say all the right things while the service still runs with
// what it read at its last start. So it asks what is actually listening —
// something on our port, on loopback and nowhere else.
func tightVNCReady() bool {
	return psOK(fmt.Sprintf(
		`$v = Get-ItemProperty -Path 'Registry::%s' -ErrorAction Stop; `+
			`if ($v.UseVncAuthentication -ne 0 -or $v.LoopbackOnly -ne 1 -or $v.AllowLoopback -ne 1 -or $v.RfbPort -ne %d) { exit 1 }; `+
			`if ((Get-Service -Name %s).Status -ne 'Running') { exit 1 }; `+
			`$l = @(Get-NetTCPConnection -LocalPort %d -State Listen -ErrorAction SilentlyContinue); `+
			`if ($l.Count -eq 0) { exit 1 }; `+
			`if ($l | Where-Object { $_.LocalAddress -notin '127.0.0.1', '::1' }) { exit 1 }; exit 0`,
		tightVNCKey, VNCPort(), tightVNCService, VNCPort()))
}

// serviceExists reports whether a Windows service is registered at all.
func serviceExists(name string) bool {
	return psOK(fmt.Sprintf(`exit [int](-not (Get-Service -Name '%s' -ErrorAction SilentlyContinue))`, name))
}

// powershell wraps a script as a command line for Step.Commands. The script is
// also what gets shown to the operator before it runs, so it is written to be
// readable rather than golfed.
func powershell(script string) []string {
	return []string{"powershell", "-NoProfile", "-NonInteractive", "-Command", script}
}

// psOK runs a PowerShell snippet and reports whether it exited zero.
//
// Exit codes rather than output matching, throughout. `sc query` prints
// "RUNNING" only on an English Windows, and `netsh ... show rule` prints "No
// rules match the specified criteria." only on an English Windows; a check
// built on those strings reports "not installed" forever on a German or
// Japanese machine and reinstalls on every run. Comparing a .NET enum in
// PowerShell is locale-independent.
func psOK(script string) bool {
	cmd := powershell(script)
	return runQuiet(cmd[0], cmd[1:]...)
}

// serviceRunning reports whether a Windows service exists and is running.
//
// The previous check was `sc query <name>` succeeding, which is true the moment
// a service is *registered* — including when it is stopped, disabled, or
// firewalled off. That made a re-run of `locnet setup -install` skip the step
// and report success on a machine that no peer could reach.
func serviceRunning(name string) bool {
	return psOK(fmt.Sprintf(
		`exit [int]((Get-Service -Name '%s' -ErrorAction SilentlyContinue).Status -ne 'Running')`, name))
}

// firewallRuleEnabled reports whether any of the named inbound rules exists and
// is enabled.
//
// It looks rules up by name rather than asking the more natural question — "is
// TCP 22 allowed from anywhere?" — purely for speed. The general form,
//
//	Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow |
//	    Get-NetFirewallPortFilter | Where-Object { ... }
//
// is correct and took **43 seconds** on a stock Windows 11: the pipeline
// materialises every rule on the machine and joins it against every port
// filter. Plan() runs this per step, so setup would have sat silent for a
// minute and a half before printing anything. A lookup by name is ~0.3s.
//
// Passing several names is what makes that trade acceptable here. The rule may
// be the one this code creates ("sshd") or the one the OpenSSH capability
// installs ("OpenSSH-Server-In-TCP") — on the machine this was measured on,
// both existed, and only hours earlier neither did.
//
// The cost of the shortcut is a rule allowing the port under some other name,
// which this reports as absent. That errs toward re-running an idempotent
// command, which is the harmless direction; reporting a blocked port as open is
// the failure that wastes an afternoon.
//
// Note what this does and does not establish. It reads the rule set, which is
// enough to catch the case that started all this — a service installed, running
// and firewalled off. It is not proof of reachability: a machine cannot obtain
// that about itself, because Windows exempts traffic it sends to its own
// addresses from firewall evaluation entirely. Only a peer can prove it.
//
// A rule also has to cover the profile peers arrive under. locnetd marks the
// tunnel Private, so a rule counts if it applies to Private (or to every
// profile). "Enabled" alone was not enough: the OpenSSH capability's rule is
// Private-only, and while the tunnel was still filed as Public this reported
// SSH as done on a machine no peer could reach.
func firewallRuleEnabled(names ...string) bool {
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = "'" + n + "'"
	}
	// Profile is a flags enum: Any is 0, Private is 2.
	return psOK(fmt.Sprintf(
		`$hit = @(%s) | ForEach-Object { Get-NetFirewallRule -Name $_ -ErrorAction SilentlyContinue } |`+
			` Where-Object { $_.Enabled -eq 'True' -and ([int]$_.Profile -eq 0 -or ([int]$_.Profile -band 2)) };`+
			` exit [int](-not [bool]$hit)`,
		strings.Join(quoted, ",")))
}

func rdpEnabled() bool {
	out, ok := runOutput("reg", "query",
		`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`, "/v", "fDenyTSConnections")
	return ok && containsFold(out, "0x0")
}

// vncDisplay is fixed here. Choosing a free X display is a Linux problem; on
// Windows it only places TightVNC on port 5901, behind the share on 5900.
func vncDisplay() int { return 1 }
