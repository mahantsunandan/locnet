// Package launch starts the local program that connects to a peer.
//
// LocNet does not implement remote desktop, file browsing or a shell. It makes
// the peer reachable and then hands off to whatever the operating system
// already has — mstsc, xfreerdp, Screen Sharing, ssh, the browser. That is a
// deliberate limit: a purpose-built screen codec would take months and be
// worse than RDP, and the hard problem LocNet actually solves is that the peer
// was unreachable in the first place.
package launch

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// startupGrace is how long a graphical client is watched before it is assumed
// to have opened a window. Long enough for a failing client to print its
// reason and quit; short enough that nobody notices the wait.
const startupGrace = 1500 * time.Millisecond

// firstLines trims a client's output to something worth putting in front of a
// person. Clients are chatty about certificates and codecs; the reason it
// failed is near the top.
func firstLines(s string, n int) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "It exited immediately and said nothing about why."
	}
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = append(lines[:n], "…")
	}
	return strings.Join(lines, "\n")
}

// candidate is one program that might be installed, and how to call it.
type candidate struct {
	bin  string
	args func(target string) []string
	// guiAuth is true when the client asks for a password in a window of its
	// own. Clients without it prompt on the terminal, which is fatal when
	// there is no terminal: xfreerdp started from the web console reaches the
	// server, tries to read a domain from stdin, gets "Inappropriate ioctl
	// for device", and cancels the connection. The user sees nothing at all.
	guiAuth bool
	// where lists full paths to try when bin is not on PATH — the usual state
	// of an installed Windows program.
	where []string
	// remembers is true when the client can save the password in the system's
	// own credential store, so it is asked for once rather than every time.
	//
	// LocNet deliberately has no password store of its own. SSH does not need
	// one — a key replaces the password outright — but remote desktop has no
	// equivalent, and the choice is then between a keyring the desktop already
	// maintains and a plaintext file LocNet would have to invent. Preferring
	// the client that uses the keyring is the whole of LocNet's answer.
	remembers bool
}

// Kind is a sort of client program.
type Kind string

const (
	KindSSH     Kind = "ssh"
	KindRDP     Kind = "rdp"
	KindVNC     Kind = "vnc"
	KindBrowser Kind = "browser"
	KindSMB     Kind = "smb"
)

// Attached reports whether this kind of client takes over the terminal. SSH
// does; a remote-desktop window does not, and waiting for one would wedge the
// shell until the user closed it.
func (k Kind) Attached() bool { return k == KindSSH }

// NeedsCredentials reports whether this kind of client is likely to have to ask
// for a password before it can show anything.
//
// Remote desktop does: RDP with network-level authentication and VNC with a
// password both authenticate before the first pixel. LocNet cannot supply
// those — they belong to the far machine's own screen server, not to the mesh
// — so the client has to ask somebody, and it needs a terminal or a window to
// ask in.
func (k Kind) NeedsCredentials() bool { return k == KindRDP || k == KindVNC }

// hasTerminal reports whether standard input is a terminal a client could
// prompt on.
//
// It asks the kernel rather than looking at the file mode. The mode says only
// "character device", which /dev/null also is — so `locnet rdp peer </dev/null`
// would be handed a client that waits forever for an answer from nowhere.
func hasTerminal() bool { return isTerminal(os.Stdin.Fd()) }

// clients maps a kind to the programs to try, in order of preference.
// clientsFor is clients() with the login name folded into the arguments where
// a client supports it.
func clientsFor(k Kind, login string) []candidate {
	list := clients(k)
	if login == "" || k != KindRDP {
		return list
	}
	out := make([]candidate, 0, len(list))
	for _, c := range list {
		c := c
		inner := c.args
		switch c.bin {
		case "xfreerdp", "xfreerdp3":
			c.args = func(t string) []string { return append(inner(t), "/u:"+login) }
		case "rdesktop":
			c.args = func(t string) []string { return append([]string{"-u", login}, inner(t)...) }
		case "remmina":
			// Remmina takes the account in the URL rather than a flag.
			c.args = func(t string) []string { return []string{"-c", "rdp://" + login + "@" + t} }
		case "open":
			// macOS: the rdp:// scheme carries a username parameter.
			c.args = func(t string) []string {
				return []string{"rdp://full%20address=s:" + t + "&username=s:" + login}
			}
		}
		out = append(out, c)
	}
	return out
}

func clients(k Kind) []candidate {
	switch k {
	case KindSSH:
		return []candidate{{bin: "ssh", args: func(t string) []string { return []string{t} }}}

	case KindRDP:
		switch runtime.GOOS {
		case "windows":
			return []candidate{{bin: "mstsc.exe", args: func(t string) []string { return []string{"/v:" + t} }, guiAuth: true}}
		case "darwin":
			// Microsoft Remote Desktop registers the rdp:// scheme.
			return []candidate{{bin: "open", args: func(t string) []string {
				return []string{"rdp://full%20address=s:" + t}
			}}}
		default:
			return []candidate{
				{bin: "xfreerdp3", args: freerdpArgs},
				{bin: "xfreerdp", args: freerdpArgs},
				{bin: "remmina", args: func(t string) []string { return []string{"-c", "rdp://" + t} }, guiAuth: true, remembers: true},
				{bin: "rdesktop", args: func(t string) []string { return []string{t} }},
			}
		}

	case KindVNC:
		switch runtime.GOOS {
		case "darwin":
			return []candidate{{bin: "open", args: func(t string) []string { return []string{"vnc://" + t} }, guiAuth: true}}
		case "windows":
			// Windows installers rarely put a viewer on PATH, so each is also
			// looked for where its installer puts it.
			viewer := func(t string) []string { return []string{vncHostPort(t)} }
			return []candidate{
				{bin: "vncviewer.exe", args: viewer, where: programFiles(
					`TigerVNC\vncviewer.exe`, `RealVNC\VNC Viewer\vncviewer.exe`, `uvnc bvba\UltraVNC\vncviewer.exe`)},
				{bin: "tvnviewer.exe", args: viewer, where: programFiles(`TightVNC\tvnviewer.exe`)},
			}
		default:
			return []candidate{
				{bin: "remmina", args: func(t string) []string { return []string{"-c", "vnc://" + t} }, guiAuth: true, remembers: true},
				{bin: "vncviewer", args: func(t string) []string { return []string{vncHostPort(t)} }},
				{bin: "xtightvncviewer", args: func(t string) []string { return []string{vncHostPort(t)} }},
				{bin: "vinagre", args: func(t string) []string { return []string{"vnc://" + t} }, guiAuth: true},
			}
		}

	case KindBrowser, KindSMB:
		switch runtime.GOOS {
		case "darwin":
			return []candidate{{bin: "open", args: func(t string) []string { return []string{t} }}}
		case "windows":
			return []candidate{{bin: "rundll32", args: func(t string) []string {
				return []string{"url.dll,FileProtocolHandler", t}
			}}}
		default:
			return []candidate{
				{bin: "xdg-open", args: func(t string) []string { return []string{t} }},
				{bin: "gio", args: func(t string) []string { return []string{"open", t} }},
			}
		}
	}
	return nil
}

func freerdpArgs(t string) []string {
	// /cert:ignore because a machine on your own mesh will have a
	// self-signed certificate, and refusing to connect over that is not a
	// meaningful protection when the transport is already a WireGuard tunnel.
	return []string{"/v:" + t, "/cert:ignore", "/dynamic-resolution"}
}

// Run starts the best available client for kind, pointed at target.
//
// target is a host, "host:port", or a URL, depending on the kind.
func Run(kind Kind, target string) error { return RunAs(kind, target, "") }

// RunDetached is RunAs for a caller with no terminal behind it — the web
// console. It prefers clients that can ask for a password in their own window,
// and denies the others a terminal to prompt on so they fail loudly instead of
// hanging on a prompt nobody can answer.
func RunDetached(kind Kind, target, login string) error {
	return run(kind, target, login, true)
}

// RunAs is Run with a login name for the clients that accept one.
//
// SSH takes it in the target itself, so the caller has already applied it.
// Remote desktop clients take a flag, and supplying it saves typing the
// username into a login box on every connection.
func RunAs(kind Kind, target, login string) error {
	return run(kind, target, login, false)
}

func run(kind Kind, target, login string, headless bool) error {
	list := clientsFor(kind, login)
	if headless {
		list = guiFirst(list)
	}
	if len(list) == 0 {
		return fmt.Errorf("no %s client is known for %s", kind, runtime.GOOS)
	}

	// A client that has to ask for a password needs somewhere to ask. When
	// there is no terminal, prefer the clients that can ask in a window of
	// their own; when there is one, hand it over.
	//
	// Getting this wrong is not a subtle failure. A remote desktop server
	// using network-level authentication — which is what GNOME's does —
	// demands credentials before it will show anything, so xfreerdp prompts
	// immediately; with stdin closed it aborts with "tcgetattr() failed with
	// Inappropriate ioctl for device" and the connection looks refused.
	interactive := !headless && hasTerminal()
	if kind.NeedsCredentials() {
		list = rememberingFirst(list)
	}
	if !interactive {
		list = guiFirst(list)
	}

	var tried []string
	for _, c := range list {
		path, ok := locate(c)
		if !ok {
			tried = append(tried, c.bin)
			continue
		}
		cmd := exec.Command(path, c.args(target)...)
		deescalate(cmd)
		// Only a client that prompts on the terminal needs the terminal. One
		// with a window of its own is released, so the shell comes straight
		// back the way it always did for a graphical client.
		if interactive && (kind.Attached() || (kind.NeedsCredentials() && !c.guiAuth)) {
			// Waiting rather than releasing, because the prompt is only
			// answerable while this process still owns the terminal. Released
			// to the background it would be stopped by SIGTTIN the moment it
			// tried to read.
			cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
			return cmd.Run()
		}
		// A GUI client outlives the CLI that started it. Releasing it means
		// `locnet rdp foo` returns straight away instead of blocking until
		// the window is closed.
		//
		// But releasing it blind is how you get a button that reports success
		// and does nothing: if there is no RDP server on the far machine,
		// xfreerdp prints the reason and exits in well under a second, and
		// nobody ever sees it. So the first moment is watched.
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("could not start %s: %w", c.bin, err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()

		select {
		case err := <-done:
			if err == nil {
				// Some launchers — xdg-open, remmina's -c, macOS open —
				// hand off to another process and exit cleanly. That is
				// success, not a client that vanished.
				return nil
			}
			return fmt.Errorf("%s could not connect to %s.\n%s", c.bin, target,
				firstLines(out.String(), 6))
		case <-time.After(startupGrace):
			// Still running after the grace period: it is a window, not an
			// error message. Leave it alone.
			return nil
		}
	}

	return fmt.Errorf("no %s client found. Tried: %s.\n%s",
		kind, strings.Join(tried, ", "), installHint(kind))
}

// locate finds a client: on PATH, or failing that at one of the places its
// installer is known to put it.
func locate(c candidate) (string, bool) {
	if p, err := exec.LookPath(c.bin); err == nil {
		return p, true
	}
	for _, p := range c.where {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, true
		}
	}
	return "", false
}

// programFiles expands paths relative to both Windows program folders.
func programFiles(rel ...string) []string {
	var out []string
	for _, root := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)")} {
		if root == "" {
			continue
		}
		for _, r := range rel {
			out = append(out, root+`\`+r)
		}
	}
	return out
}

// vncHostPort writes host:port the way the classic VNC viewers read it.
//
// To TigerVNC, TightVNC, RealVNC and UltraVNC a single colon introduces a
// *display number*, which they add to 5900 — and only some of them treat a
// number of 100 or more as a port instead. "host:5900" therefore means port
// 5900 to one viewer and port 11800 to another. Two colons always mean a port.
func vncHostPort(t string) string {
	i := strings.LastIndex(t, ":")
	if i < 0 || strings.Contains(t, "::") {
		return t
	}
	return t[:i] + "::" + t[i+1:]
}

// guiFirst puts the clients that have their own password dialog in front,
// keeping the relative order of each group. A terminal-prompting client is
// still tried, because one that cannot ask for a password is better than no
// client at all — a machine with no password set connects fine.
func guiFirst(in []candidate) []candidate {
	out := make([]candidate, 0, len(in))
	for _, c := range in {
		if c.guiAuth {
			out = append(out, c)
		}
	}
	for _, c := range in {
		if !c.guiAuth {
			out = append(out, c)
		}
	}
	return out
}

// installHint says what to install, because "command not found" is not a
// useful thing to tell someone who just wants to see a desktop.
func installHint(kind Kind) string {
	switch kind {
	case KindRDP:
		switch runtime.GOOS {
		case "linux":
			return "Install one:  sudo apt install freerdp3-x11   |   sudo dnf install freerdp"
		case "darwin":
			return "Install Microsoft Remote Desktop from the App Store."
		}
	case KindVNC:
		switch runtime.GOOS {
		case "linux":
			return "Install one:  sudo apt install remmina   |   sudo dnf install remmina"
		case "windows":
			return "Install TigerVNC or RealVNC Viewer."
		}
	case KindSSH:
		if runtime.GOOS == "windows" {
			return "Enable the OpenSSH client: Settings → Apps → Optional Features → OpenSSH Client."
		}
	}
	return ""
}

// KindForService maps a discovered service to the client that opens it.
func KindForService(name string) (Kind, bool) {
	switch name {
	case "ssh":
		return KindSSH, true
	case "rdp":
		return KindRDP, true
	case "vnc", "vnc-1", "vnc-2", "vnc-3", "vnc-4":
		return KindVNC, true
	case "http", "https", "http-alt":
		return KindBrowser, true
	case "smb":
		return KindSMB, true
	}
	return "", false
}

// TargetFor builds the argument a client of this kind expects.
func TargetFor(kind Kind, host string, port uint16) string {
	switch kind {
	case KindSSH:
		return host
	case KindBrowser:
		scheme := "http"
		if port == 443 {
			scheme = "https"
		}
		if port == 80 || port == 443 {
			return fmt.Sprintf("%s://%s", scheme, host)
		}
		return fmt.Sprintf("%s://%s:%d", scheme, host, port)
	case KindSMB:
		if runtime.GOOS == "windows" {
			return `\\` + host
		}
		return "smb://" + host
	default:
		return fmt.Sprintf("%s:%d", host, port)
	}
}

// Deescalate makes cmd run as the person who typed the command rather than as
// root. Exported for packages that start their own client programs — SSH in
// particular, where running as root means logging in as root@peer and reading
// root's keys instead of yours.
func Deescalate(cmd *exec.Cmd) { deescalate(cmd) }

// rememberingFirst puts the clients that can save a password ahead of those
// that cannot, without dropping any: if the preferred one is not installed the
// others still get their turn.
func rememberingFirst(list []candidate) []candidate {
	out := make([]candidate, 0, len(list))
	for _, c := range list {
		if c.remembers {
			out = append(out, c)
		}
	}
	for _, c := range list {
		if !c.remembers {
			out = append(out, c)
		}
	}
	return out
}
