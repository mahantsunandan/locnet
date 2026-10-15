package setup

import (
	"fmt"
	"os"
	"strings"

	"github.com/mahantsunandan/locnet/internal/paths"
)

// distro is enough of a Linux distribution to pick a package manager.
type distro struct {
	id      string // "ubuntu", "fedora", "arch", …
	name    string // pretty name for display
	install []string
	// sshServer and friends are the package names, which differ enough
	// between distributions that guessing is not an option.
	sshServer string
	vncServer string
	// windowManager is what runs inside the virtual desktop on a machine
	// that has no X session of its own. A window manager, not a desktop
	// environment and not a terminal emulator: enough for a VNC session to
	// be usable, and nothing a machine would otherwise never open.
	windowManager string
	// sshService is the systemd unit, which is "ssh" on Debian and "sshd"
	// almost everywhere else — a difference that has cost many people an
	// afternoon.
	sshService string
}

func detectDistro() distro {
	raw, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return distro{}
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		fields[k] = strings.Trim(v, `"`)
	}
	id := fields["ID"]
	like := fields["ID_LIKE"]
	name := fields["PRETTY_NAME"]
	if name == "" {
		name = id
	}

	switch {
	case id == "ubuntu" || id == "debian" || id == "linuxmint" || id == "pop" ||
		strings.Contains(like, "debian") || strings.Contains(like, "ubuntu"):
		return distro{
			id: "debian", name: name,
			install:   []string{"apt-get", "install", "-y"},
			sshServer: "openssh-server", sshService: "ssh",
			vncServer: "tigervnc-standalone-server", windowManager: "openbox",
		}
	case id == "fedora" || id == "rhel" || id == "centos" || id == "rocky" || id == "almalinux" ||
		strings.Contains(like, "fedora") || strings.Contains(like, "rhel"):
		return distro{
			id: "fedora", name: name,
			install:   []string{"dnf", "install", "-y"},
			sshServer: "openssh-server", sshService: "sshd",
			vncServer: "tigervnc-server", windowManager: "openbox",
		}
	case id == "arch" || id == "manjaro" || strings.Contains(like, "arch"):
		return distro{
			id: "arch", name: name,
			install:   []string{"pacman", "-S", "--noconfirm"},
			sshServer: "openssh", sshService: "sshd",
			vncServer: "tigervnc", windowManager: "openbox",
		}
	case id == "opensuse-tumbleweed" || id == "opensuse-leap" || strings.Contains(like, "suse"):
		return distro{
			id: "suse", name: name,
			install:   []string{"zypper", "--non-interactive", "install"},
			sshServer: "openssh", sshService: "sshd",
			vncServer: "tigervnc", windowManager: "openbox",
		}
	}
	return distro{id: id, name: name}
}

func planFor() ([]Step, error) {
	d := detectDistro()
	if len(d.install) == 0 {
		return nil, fmt.Errorf("LocNet does not know the package names for %q.\n"+
			"Install these by hand: an SSH server and a VNC server", d.name)
	}

	return []Step{
		{
			Name:   "SSH server",
			Why:    "so `locnet ssh <this machine>` works from a peer",
			Done:   isServiceActive(d.sshService),
			Detail: "already running",
			Commands: [][]string{
				append(append([]string{}, d.install...), d.sshServer),
				{"systemctl", "enable", "--now", d.sshService},
			},
		},
		vncStep(d),
		firewallStep(),
	}, nil
}

// firewallStep opens the LocNet interface on whichever host firewall is running.
//
// This exists because installing and starting a server is not the same as being
// reachable, and the gap is silent from the inside: Fedora and RHEL enable
// firewalld by default, a freshly created tunnel interface lands in the default
// zone, and the screen server's port is dropped there. Every local check passes
// and every peer times out.
//
// It trusts the whole interface rather than listing ports, which is both
// simpler and better founded: everything arriving on locnet0 has already proved
// its identity with a WireGuard key. Enumerating ports would also need updating
// every time the catalog grows, and a missed entry fails silently in the
// direction that is hardest to notice.
func firewallStep() Step {
	iface := paths.DefaultInterface()

	// "Cannot tell" is its own answer here, and saying so is the point.
	//
	// Both `ufw status` and `firewall-cmd --query-interface` need root, and the
	// preview — `locnet setup` with no -install — deliberately runs without it.
	// Treating the resulting failure as "not allowed" told a correctly
	// configured machine that its firewall needed fixing, which is the same
	// species of confident wrong answer as advertising an SSH server nobody can
	// reach. The commands are idempotent, so an honest "unknown" costs a
	// redundant re-run and nothing else.
	unknown := func(why string) Step {
		return Step{
			Name:     "Firewall",
			Why:      why,
			Commands: firewallCommands(iface),
		}
	}

	switch {
	case isServiceActive("firewalld"):
		out, ok := runOutput("firewall-cmd", "--zone=trusted", "--query-interface="+iface)
		switch {
		case ok && containsFold(out, "yes"):
			return Step{Name: "Firewall", Done: true, Detail: iface + " is in the trusted zone"}
		case ok:
			return Step{
				Name:     "Firewall",
				Why:      "so peers can reach this machine's servers over " + iface,
				Commands: firewallCommands(iface),
			}
		default:
			return unknown("reading firewalld needs root, so this could not be checked — the commands below change nothing if " + iface + " is already trusted")
		}

	case isServiceActive("ufw"):
		out, ok := runOutput("ufw", "status")
		switch {
		case ok && containsFold(out, iface):
			return Step{Name: "Firewall", Done: true, Detail: iface + " is already allowed"}
		case ok:
			return Step{
				Name:     "Firewall",
				Why:      "so peers can reach this machine's servers over " + iface,
				Commands: firewallCommands(iface),
			}
		default:
			return unknown("reading ufw needs root, so this could not be checked — the command below changes nothing if " + iface + " is already allowed")
		}
	}

	// Nothing to do, but worth saying out loud rather than omitting: a reader
	// working out why a peer cannot connect should be able to rule this out.
	return Step{
		Name:   "Firewall",
		Done:   true,
		Detail: "no host firewall is active",
	}
}

// firewallCommands opens the LocNet interface on whichever firewall is present.
func firewallCommands(iface string) [][]string {
	if isServiceActive("firewalld") {
		return [][]string{
			{"firewall-cmd", "--permanent", "--zone=trusted", "--add-interface=" + iface},
			{"firewall-cmd", "--reload"},
		}
	}
	return [][]string{{"ufw", "allow", "in", "on", iface}}
}

// isServiceActive asks systemd. A machine without systemd reports false, which
// makes the step appear pending — harmless, since the install command is
// idempotent and the operator sees exactly what will run.
func isServiceActive(unit string) bool {
	if unit == "" || !have("systemctl") {
		return false
	}
	return runQuiet("systemctl", "is-active", "--quiet", unit)
}
