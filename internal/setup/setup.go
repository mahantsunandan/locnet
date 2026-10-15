// Package setup installs and enables the two servers LocNet hands off to: an
// SSH server and a screen-sharing server.
//
// That is the whole list, and the shortness of it is the point. LocNet does not
// implement remote desktop or shell access; it makes machines reachable. What a
// machine needs for that is to *answer* — so setup installs the answering half
// and stops. Which client you connect with is your business: Remmina, a VNC
// viewer, your terminal, whatever you already like. An earlier version also
// installed viewers and a terminal emulator on every machine, which meant every
// field unit acquired a small pile of desktop software it would never open.
//
// Every step is shown as the literal commands that will run, nothing happens
// without consent, and anything already in place is skipped. An operator who
// would rather run the commands by hand can read the plan and do exactly that.
package setup

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// VNCDisplay is the X display number LocNet gives the shared desktop, and
// VNCPort the RFB port that follows from it. They are here rather than beside
// the Linux implementation because the command layer publishes the port on the
// overlay, and that code compiles everywhere.
//
// They are functions rather than constants because :1 is not always free. A
// machine with somebody logged in already owns a display, and on the machine
// this was found on that was :1 — so setup wrote a configuration for a server
// that could never start, and `vncserver` refused with "A VNC server is
// already running as :1" while systemd reported success. Picking a display
// that is actually free is the difference between screen sharing that works
// and screen sharing that reports it works.
func VNCDisplay() int { return vncDisplay() }

// VNCPort is the RFB port for VNCDisplay.
func VNCPort() int { return 5900 + VNCDisplay() }

// Step is one thing to install or enable.
type Step struct {
	// Name is short, e.g. "SSH server".
	Name string
	// Why explains what LocNet uses it for.
	Why string
	// Commands run in order. Empty means there is nothing to automate and
	// Manual explains what to do instead.
	Commands [][]string
	// Apply is the part of a step that is not a command line — writing a
	// configuration file, editing a list of users. It runs after Commands.
	//
	// This exists because "install the package" was never the whole job for
	// screen sharing, and pretending otherwise is what left machines with a
	// VNC server installed and nothing listening. Explain must describe
	// whatever it touches, so the consent prompt is still the truth.
	Apply func(logf func(string, ...any)) error
	// Explain describes Apply for a human, one line per thing changed.
	Explain []string
	// Manual is instructions for a step that cannot be scripted safely.
	Manual string
	// Done is true when the check found it already in place.
	Done bool
	// Detail is what the check found.
	Detail string
}

// automated reports whether this step would actually change anything.
func (s Step) automated() bool { return len(s.Commands) > 0 || s.Apply != nil }

// Plan works out what this machine still needs.
func Plan() ([]Step, error) { return planFor() }

// Describe renders a plan for a human to approve.
func Describe(steps []Step) string {
	var b strings.Builder
	var pending int

	for _, s := range steps {
		if s.Done {
			fmt.Fprintf(&b, "  ✓ %-22s %s\n", s.Name, s.Detail)
			continue
		}
		pending++
		fmt.Fprintf(&b, "  · %-22s %s\n", s.Name, s.Why)
		for _, cmd := range s.Commands {
			fmt.Fprintf(&b, "      $ %s\n", strings.Join(cmd, " "))
		}
		for _, line := range s.Explain {
			fmt.Fprintf(&b, "      + %s\n", line)
		}
		if s.Manual != "" {
			for _, line := range strings.Split(strings.TrimSpace(s.Manual), "\n") {
				fmt.Fprintf(&b, "      %s\n", line)
			}
		}
	}
	if pending == 0 {
		b.WriteString("\n  Nothing to do — this machine already has everything.\n")
	}
	return b.String()
}

// Pending returns the steps that would actually run.
func Pending(steps []Step) []Step {
	var out []Step
	for _, s := range steps {
		if !s.Done && s.automated() {
			out = append(out, s)
		}
	}
	return out
}

// Run executes a step's commands, reporting each one as it goes.
func Run(s Step, logf func(string, ...any)) error {
	for _, cmd := range s.Commands {
		logf("    $ %s", strings.Join(cmd, " "))
		out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput()
		if err != nil {
			trimmed := strings.TrimSpace(string(out))
			if trimmed == "" {
				trimmed = err.Error()
			}
			return fmt.Errorf("%s: %s", strings.Join(cmd, " "), lastLines(trimmed, 4))
		}
	}
	if s.Apply != nil {
		return s.Apply(logf)
	}
	return nil
}

// lastLines keeps an error message short. Package managers are verbose and the
// useful part is almost always at the end.
func lastLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) <= n {
		return s
	}
	return "…\n" + strings.Join(lines[len(lines)-n:], "\n")
}

// have reports whether a program is on PATH.
func have(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

// Platform names this machine for display.
func Platform() string {
	switch runtime.GOOS {
	case "linux":
		if d := detectDistro(); d.name != "" {
			return d.name
		}
		return "Linux"
	case "darwin":
		return "macOS"
	case "windows":
		return "Windows"
	}
	return runtime.GOOS
}
