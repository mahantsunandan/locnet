package setup

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Screen sharing on Linux is the one part of setup that installing a package
// does not finish, and for years this code pretended otherwise: it put a VNC
// server on disk, said "already installed" on every subsequent run, and left
// nothing listening. From a peer that looks exactly like a machine with no VNC
// at all, which is a miserable thing to debug from the other end of a network.
//
// So the step now configures and starts a server, and the shape of what it
// starts follows from a fact about modern Linux desktops: they are Wayland,
// and a Wayland session cannot be handed to a VNC server. GNOME removed its
// VNC backend entirely in GNOME 46; wayvnc only speaks to wlroots compositors.
// There is no arrangement of packages that shows the physical screen of an
// Ubuntu GNOME machine over VNC.
//
// What does work everywhere, on X11 and Wayland alike, is a *virtual* desktop:
// Xvnc hosting a display of its own, with a session running inside it. That is
// a second desktop rather than the one someone is sitting in front of, and the
// plan says so rather than letting the difference be a surprise. In exchange it
// is reliable, it survives logout, and it needs no graphical session to already
// exist — which is precisely what a field unit wants.

// vncDisplay is the display number the virtual desktop runs on.
//
// Not a constant. The obvious choice is :1 — :0 is where a real session lives
// on the machines that still have one — but "the machines that still have one"
// turned out to include machines whose session had *already taken :1*. GNOME on
// Wayland runs Xwayland on the next free display, and on a freshly booted
// desktop that is :1 as often as not. Configuring a VNC server there produces a
// unit that starts, dies with status 255, and is reported as started.
//
// The answer is sticky rather than merely free: once a display has been mapped
// to somebody in the TigerVNC user file, that is the one to keep using, or a
// second run of setup would wander to a new number and leave the first server
// running on the old one.
func vncDisplay() int {
	vncDisplayOnce.Do(func() {
		if vncDisplayNum != 0 {
			return // pinned, which is how the tests get a predictable number
		}
		if n, ok := configuredDisplay(); ok && displayUsable(n) {
			vncDisplayNum = n
			return
		}
		vncDisplayNum = firstFreeDisplay()
	})
	return vncDisplayNum
}

// displayUsable reports whether a display we have already configured can still
// be used: either our own server is running on it, or nothing else has taken
// it since.
//
// Stickiness has to yield here. The machine this was written on had :1 mapped
// from an earlier attempt *and* :1 occupied by the desktop session, so keeping
// the mapping out of loyalty to it would reconfigure the same broken display
// forever.
func displayUsable(n int) bool {
	if unit := vncUnitName(); unit != "" && isServiceActive(fmt.Sprintf("%s@:%d", unit, n)) {
		return true
	}
	return displayFree(n)
}

var (
	vncDisplayOnce sync.Once
	vncDisplayNum  int
)

// configuredDisplay returns the display LocNet has already mapped for the
// person whose desktop this is.
func configuredDisplay() (int, bool) {
	raw, err := os.ReadFile(vncUsersFile)
	if err != nil {
		return 0, false
	}
	want := ""
	if u, err := desktopUser(); err == nil {
		want = u.Username
	}

	var only int
	var count int
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		disp, user, ok := strings.Cut(line, "=")
		if !ok || !strings.HasPrefix(disp, ":") {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(disp, ":"))
		if err != nil {
			continue
		}
		if want != "" && user == want {
			return n, true
		}
		only, count = n, count+1
	}
	// No match by name — which is the normal case when setup is run without
	// sudo and cannot tell whose desktop this is. A single mapping is
	// unambiguous enough to reuse; several are not.
	if want == "" && count == 1 {
		return only, true
	}
	return 0, false
}

// firstFreeDisplay finds a display number nothing has claimed.
//
// The three checks are the ones the X server and TigerVNC make themselves: the
// lock file, the socket, and the RFB port. Checking fewer would pick a number
// that looks free and is not, which is the whole bug this exists to avoid.
func firstFreeDisplay() int {
	for n := 1; n <= 32; n++ {
		if displayFree(n) {
			return n
		}
	}
	// Nothing free in a range that large means something is very wrong.
	// Returning :1 lets the caller fail with TigerVNC's own message rather
	// than inventing a different one here.
	return 1
}

func displayFree(n int) bool {
	for _, path := range []string{
		fmt.Sprintf("/tmp/.X%d-lock", n),
		fmt.Sprintf("/tmp/.X11-unix/X%d", n),
	} {
		if _, err := os.Stat(path); err == nil {
			return false
		}
	}
	// The port has to be free on every address: TigerVNC's own check binds
	// the wildcard, so a listener on one address is enough to stop it.
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", 5900+n))
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

// vncUsersFile maps display numbers to the account whose desktop runs there.
// TigerVNC reads it on every distribution that ships a systemd unit for it.
// A variable rather than a constant so the test can edit a copy instead of
// the real one.
var vncUsersFile = "/etc/tigervnc/vncserver.users"

// vncStep builds the screen-sharing step for a distribution.
func vncStep(d distro) Step {
	s := Step{
		Name: "Screen sharing",
		Why:  fmt.Sprintf("so peers can watch this machine (VNC on :%d)", vncDisplay()),
	}

	unit := vncUnitName()
	if unit != "" && isServiceActive(fmt.Sprintf("%s@:%d", unit, vncDisplay())) {
		// Running is not the same as correctly configured. When LocNet learns
		// that a setting is required — as it did about the blacklist, which
		// locks every peer out at once because they all arrive from the
		// forwarder's address — a server that is already up still needs it.
		// Both halves matter, and for different reasons. The file can be out
		// of date because LocNet learned about a setting after this server was
		// configured. The *process* can be out of date even when the file is
		// right, because it has been running since before the file changed —
		// which is exactly what happened here, and which no amount of reading
		// the file would ever have revealed.
		missing := staleVNCSettings()
		missing = append(missing, settingsMissingFromProcess(vncDisplay())...)
		if len(missing) > 0 {
			s.Detail = fmt.Sprintf("running on :%d, but not with the settings LocNet needs", vncDisplay())
			s.Explain = []string{
				"update the VNC configuration: " + strings.Join(dedupe(missing), ", "),
				fmt.Sprintf("restart the tigervnc service for :%d so the running server picks them up", vncDisplay()),
			}
			s.Apply = applyVNC
			return s
		}
		s.Done = true
		s.Detail = fmt.Sprintf("running on :%d", vncDisplay())
		return s
	}

	// The package first. Everything after it needs files the package owns, so
	// the checks that follow are deliberately deferred to Apply.
	if !have("Xvnc") && !have("Xtigervnc") {
		s.Commands = append(s.Commands,
			append(append([]string{}, d.install...), d.vncServer))
	}

	// A virtual display with nothing running in it is a grey rectangle. If the
	// machine has no X session installed — which is now the normal state of a
	// Wayland-only desktop — one has to come from somewhere, and the plan says
	// which package before anyone consents to it.
	//
	// One package: a window manager. This used to install a terminal emulator
	// alongside it, on the theory that a bare window manager gives you nowhere
	// to type. It does not need to: a shell on the far machine is what SSH is
	// for, and a terminal emulator installed on every machine in the fleet is
	// software nobody asked for.
	if !haveXSession() && !have("openbox-session") {
		s.Commands = append(s.Commands,
			append(append([]string{}, d.install...), d.windowManager))
		s.Manual = "This machine has no X session installed, so the virtual desktop\n" +
			"gets a window manager (openbox) and nothing else — a viewer will\n" +
			"show grey until something is started on it. For a desktop with a\n" +
			"menu and a file manager already on it, install a full session\n" +
			"(xfce4, or @xfce-desktop on Fedora) first and run this again."
	}

	s.Explain = []string{
		fmt.Sprintf("map display :%d to your account in %s", vncDisplay(), vncUsersFile),
		fmt.Sprintf("write ~/.vnc/config and ~/.config/tigervnc/config — bound to localhost, %s", vncSessionNote()),
		fmt.Sprintf("enable and start the tigervnc service for :%d", vncDisplay()),
	}
	s.Apply = applyVNC
	return s
}

// requiredVNCSettings are the options LocNet depends on, and which it will
// rewrite an existing configuration to add.
var requiredVNCSettings = []string{"localhost", "securitytypes=none", "useblacklist=0"}

// staleVNCSettings names the required options a running server's configuration
// is missing.
//
// It finds whose configuration to read from the user map rather than from
// SUDO_USER, so the answer is the same whether or not setup was run with sudo
// — the plan a person approves has to match what actually runs.
func staleVNCSettings() []string {
	owner, ok := displayOwner(vncDisplay())
	if !ok {
		return nil
	}
	u, err := user.Lookup(owner)
	if err != nil {
		return nil
	}

	// Whichever config the installed version reads is the one that matters, so
	// a setting present in either is enough.
	seen := map[string]bool{}
	for _, dir := range vncConfigDirs(u) {
		raw, err := os.ReadFile(filepath.Join(dir, "config"))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			seen[strings.ToLower(strings.TrimSpace(line))] = true
		}
	}
	if len(seen) == 0 {
		return nil // nothing we wrote; not ours to correct
	}

	var missing []string
	for _, want := range requiredVNCSettings {
		if !seen[want] {
			missing = append(missing, want)
		}
	}

	// A better session installed since last time is worth picking up. The
	// plan's own advice is "install xfce4 and run this again", and that advice
	// was a lie while an already-running server counted as finished.
	if want := xSessionName(); want != "" && !seen["session="+want] {
		missing = append(missing, "session="+want)
	}
	return missing
}

// displayOwner reports which account a display is mapped to.
func displayOwner(n int) (string, bool) {
	raw, err := os.ReadFile(vncUsersFile)
	if err != nil {
		return "", false
	}
	prefix := fmt.Sprintf(":%d=", n)
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if name, ok := strings.CutPrefix(line, prefix); ok && name != "" {
			return name, true
		}
	}
	return "", false
}

// vncSessionNote describes what will run inside the virtual display.
func vncSessionNote() string {
	if name := xSessionName(); name != "" {
		return "running the " + name + " session"
	}
	return "running " + windowManagerCmd()
}

// applyVNC does the configuration the package leaves undone.
func applyVNC(logf func(string, ...any)) error {
	u, err := desktopUser()
	if err != nil {
		return err
	}

	unit := vncUnitName()
	if unit == "" {
		return fmt.Errorf("this build of TigerVNC ships no systemd unit, so LocNet cannot start it for you.\n" +
			"Start a server by hand and LocNet will find it: vncserver -localhost yes :1")
	}

	if err := mapVNCUser(u.Username, logf); err != nil {
		return err
	}
	if err := writeVNCConfig(u, logf); err != nil {
		return err
	}

	service := fmt.Sprintf("%s@:%d", unit, vncDisplay())

	// Stop, wait, start — rather than restart.
	//
	// `enable --now` was worse than useless: it starts a stopped unit and does
	// nothing at all to a running one, so every configuration change LocNet
	// made to a server that was already up was written to disk and never read.
	// But plain `restart` is not enough either. TigerVNC refuses to start a
	// display that looks occupied, and for a moment after the old server is
	// signalled its lock file and socket are still there — so the replacement
	// dies with "A VNC server is already running as :N" and the unit reports
	// success. Waiting for the display to actually come free is the only
	// version of this that is not a race.
	for _, cmd := range [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "stop", service},
	} {
		logf("    $ %s", strings.Join(cmd, " "))
		if out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %s", strings.Join(cmd, " "),
				lastLines(strings.TrimSpace(string(out)), 4))
		}
	}
	if err := waitForDisplayFree(vncDisplay(), 20*time.Second); err != nil {
		return err
	}
	for _, cmd := range [][]string{
		{"systemctl", "enable", service},
		{"systemctl", "start", service},
	} {
		logf("    $ %s", strings.Join(cmd, " "))
		if out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %s", strings.Join(cmd, " "),
				lastLines(strings.TrimSpace(string(out)), 4))
		}
	}

	// systemctl exiting zero means the unit was started, not that the server
	// is up. TigerVNC's session helper forks, returns success, and the actual
	// server can then die a moment later — which is exactly what happened on
	// the machine this was written for: `systemctl enable --now` succeeded,
	// setup printed a tick, and nothing was ever listening. The only honest
	// check is the port.
	if err := waitForRFB(vncDisplay(), 15*time.Second); err != nil {
		return fmt.Errorf("%s started but no VNC server is listening on :%d.\n%s\n\nWhat the service said:\n%s",
			service, vncDisplay(), err, lastLines(unitJournal(service), 8))
	}

	// And confirm the settings reached the process, not merely the file. The
	// two disagreed for a whole afternoon once, and nothing in the behaviour
	// said so — a client could connect either way, right up until the moment
	// the missing setting mattered.
	if missing := settingsMissingFromProcess(vncDisplay()); len(missing) > 0 {
		return fmt.Errorf("the VNC server on :%d is running without %s.\n"+
			"The configuration on disk asks for it, so this build of TigerVNC is\n"+
			"ignoring the setting. Screen sharing will work until several clients\n"+
			"fail to connect in a row, and then refuse everyone with \"too many\n"+
			"security failures\".",
			vncDisplay(), strings.Join(missing, " and "))
	}

	logf("    screen sharing is up on :%d for %s", vncDisplay(), u.Username)

	// Say what will actually be on it. A virtual desktop running nothing but a
	// window manager is a plain grey rectangle, and a viewer that connects
	// successfully and shows grey is indistinguishable from a broken one until
	// somebody tells you which it is. This is that somebody.
	if xSessionName() == "openbox" || !haveXSession() {
		logf("")
		logf("    This is a second, empty desktop — not the screen anyone is sitting")
		logf("    in front of. It starts with a window manager and nothing else, so")
		logf("    a viewer will show grey until something runs on it:")
		logf("")
		logf("        right-click on the grey for openbox's menu, or from a shell here")
		logf("        DISPLAY=:%d <some-program> &", vncDisplay())
		logf("")
		logf("    For a desktop with a menu, files and a terminal already on it,")
		logf("    install a full session (dnf install @xfce-desktop, apt install")
		logf("    xfce4) and run setup again — an installed session is preferred.")
	}
	return nil
}

// settingsMissingFromProcess names required options that are absent from the
// running server's own command line.
//
// TigerVNC's wrapper turns each line of the config file into an argument, so
// the argument list is the honest record of what the server was actually told.
// Reading the config file back would only prove that the file says what we
// wrote in it.
func settingsMissingFromProcess(display int) []string {
	argv, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", vncPID(display)))
	if err != nil {
		return nil // cannot tell; do not invent a failure
	}
	args := strings.ToLower(strings.ReplaceAll(string(argv), "\x00", " "))

	var missing []string
	// Only the settings whose absence is silently harmful are checked. A
	// missing geometry is cosmetic; a missing blacklist setting locks the
	// whole network out of the screen.
	if !strings.Contains(args, "-useblacklist") {
		missing = append(missing, "useblacklist=0")
	}
	return missing
}

// vncPID finds the Xvnc serving a display.
func vncPID(display int) int {
	out, ok := runOutput("pgrep", "-f", fmt.Sprintf("Xvnc :%d", display))
	if !ok {
		return 0
	}
	for _, line := range strings.Fields(out) {
		if n, err := strconv.Atoi(line); err == nil {
			return n
		}
	}
	return 0
}

// waitForRFB waits for something to answer on the display's RFB port.
//
// It connects rather than looking for a process, because "a process exists"
// and "a client can reach it" are different claims and only the second one is
// what a peer needs.
func waitForRFB(display int, within time.Duration) error {
	addr := fmt.Sprintf("127.0.0.1:%d", 5900+display)
	deadline := time.Now().Add(within)
	for {
		c, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			c.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("nothing answered on %s within %s", addr, within)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// unitJournal fetches a unit's recent log, so a failure explains itself
// instead of asking the operator to go and look.
func unitJournal(service string) string {
	out, err := exec.Command("journalctl", "-u", service, "-n", "20", "--no-pager").CombinedOutput()
	if err != nil {
		return "(could not read the journal: " + err.Error() + ")"
	}
	return strings.TrimSpace(string(out))
}

// mapVNCUser adds ":1=user" to the TigerVNC user map, leaving any other
// display's mapping alone.
func mapVNCUser(name string, logf func(string, ...any)) error {
	want := fmt.Sprintf(":%d=%s", vncDisplay(), name)

	raw, err := os.ReadFile(vncUsersFile)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("reading %s: %w", vncUsersFile, err)
	}

	var out []string
	replaced := false
	// Splitting "" yields one empty field, which would prepend a blank line
	// on a machine whose package shipped no user map at all.
	var lines []string
	if len(raw) > 0 {
		lines = strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, fmt.Sprintf(":%d=", vncDisplay())) {
			// Somebody else's mapping for this display. Ours wins, because
			// the operator just asked for it — but only this line changes.
			if trimmed != want {
				logf("    replacing %q in %s", trimmed, vncUsersFile)
			}
			out = append(out, want)
			replaced = true
			continue
		}
		// This user's mapping for some *other* display, left behind when a
		// previous run had to move — usually because the display it chose
		// turned out to be the desktop session's. One person, one display:
		// leaving the old line would keep a mapping to a display that is not
		// theirs and never will be.
		if disp, u, ok := strings.Cut(trimmed, "="); ok && u == name && !strings.HasPrefix(trimmed, "#") {
			logf("    dropping this account's old mapping %q", disp+"="+u)
			continue
		}
		out = append(out, line)
	}
	if !replaced {
		out = append(out, want)
	}

	if err := os.MkdirAll(filepath.Dir(vncUsersFile), 0o755); err != nil {
		return err
	}
	body := strings.TrimRight(strings.Join(out, "\n"), "\n") + "\n"
	if err := os.WriteFile(vncUsersFile, []byte(body), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", vncUsersFile, err)
	}
	logf("    %s: %s", vncUsersFile, want)
	return nil
}

// writeVNCConfig writes the per-user server options.
//
// Two of them carry the whole security argument. `localhost` means the server
// answers only connections from this machine, so it is invisible to the LAN
// however the firewall is set. `SecurityTypes=None` is then not the reckless
// setting it looks like: the only thing that can reach the port is locnetd on
// this same machine, and locnetd checks the share's access list — a WireGuard
// allowed-IP check against the peer's key — before forwarding a single byte.
// Putting a second password in front of that would be one more thing to lose,
// guarding a door that is already locked.
// It is written to both of TigerVNC's config locations. ~/.vnc is where every
// version up to 1.12 looked; 1.13 moved to ~/.config/tigervnc and 1.16 prints
// "~/.vnc is deprecated" and reads the new one. Writing only the old path is
// how you configure a server that quietly ignores the configuration, so both
// get the same bytes and whichever the installed version prefers is correct.
func writeVNCConfig(u *user.User, logf func(string, ...any)) error {
	var b strings.Builder
	b.WriteString("# Written by `locnet setup -install`. Edit freely; it is not\n")
	b.WriteString("# rewritten unless you run setup again.\n")
	b.WriteString("geometry=1600x900\n")
	b.WriteString("depth=24\n")
	b.WriteString("localhost\n")
	b.WriteString("alwaysshared\n")
	b.WriteString("securitytypes=none\n")
	// TigerVNC blacklists a *source address* that fails to authenticate
	// repeatedly. Behind LocNet's port share every client arrives from
	// 127.0.0.1 — the forwarder — so the blacklist cannot tell them apart and
	// one client's stumbles lock out everybody with "too many security
	// failures", including the health probe, which then makes it worse. It is
	// protecting a door that only LocNet can reach, and the peer's identity
	// has already been checked against the share's access list by then.
	b.WriteString("useblacklist=0\n")
	if name := xSessionName(); name != "" {
		b.WriteString("session=" + name + "\n")
	}

	// Without an xstartup TigerVNC starts a bare X server, so one is written
	// when the machine has no session of its own to name in `session=`.
	var startup string
	if xSessionName() == "" {
		startup = generatedXstartup()
	}

	for _, dir := range vncConfigDirs(u) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		// The files belong to the person whose desktop this is, not to the
		// root shell that created them. The session helper drops privileges
		// before it reads them and would fail on files it cannot open.
		if err := chownTo(dir, u); err != nil {
			return err
		}

		path := filepath.Join(dir, "config")
		if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
			return err
		}
		if err := chownTo(path, u); err != nil {
			return err
		}
		if startup != "" {
			sp := filepath.Join(dir, "xstartup")
			switch existing, mine := readXstartup(sp); {
			case existing != "" && !mine:
				// Somebody tuned this by hand. Overwriting it is how a working
				// virtual desktop silently becomes a grey rectangle on the next
				// unrelated run of setup, so it is left exactly as it is — but
				// not silently, and not without checking it for the one mistake
				// that breaks the machine's *real* desktop.
				logf("    %s left alone — not written by LocNet", sp)
				if bad := singleInstanceApps(existing); len(bad) > 0 {
					logf("    warning: %s starts %s on the virtual display.", sp, strings.Join(bad, " and "))
					logf("      These are single-instance apps: the copy started here claims the")
					logf("      name on the session bus, and launching one on your real desktop")
					logf("      then opens its window on display :%d, where you cannot see it.", vncDisplay())
					logf("      Remove that line if your terminal has stopped opening.")
				}
			default:
				if err := os.WriteFile(sp, []byte(startup), 0o755); err != nil {
					return err
				}
				if err := chownTo(sp, u); err != nil {
					return err
				}
			}
		}
		logf("    %s written for %s", path, u.Username)
	}
	return nil
}

// xstartupMarker identifies an xstartup that LocNet generated, and so may
// safely replace. Its absence means a person wrote the file — see
// readXstartup. Never change this string: an older marker that no longer
// matches turns every upgrade into the clobbering this exists to prevent.
const xstartupMarker = "# locnet-generated-xstartup"

// generatedXstartup is the session LocNet runs on the virtual display when the
// machine has no X session of its own to name in `session=`.
//
// It deliberately starts a window manager and nothing else. A terminal
// emulator must never be added here: the ones a desktop actually ships are
// single-instance, so a copy started on this display claims its name on the
// session bus and every later launch — including from the dock on the real
// screen — is handed to the copy nobody can see. That failure is silent, and
// it looks exactly like the terminal being broken.
func generatedXstartup() string {
	return "#!/bin/sh\n" +
		xstartupMarker + "\n" +
		"# Minimal session for the LocNet virtual desktop. Delete this marker\n" +
		"# line to adopt the file and setup will stop rewriting it.\n" +
		"#\n" +
		"# Do not start a terminal emulator here. Ptyxis, gnome-terminal and kgx\n" +
		"# are single-instance: the copy started on this display would capture\n" +
		"# every launch made on the real desktop.\n" +
		"exec " + windowManagerCmd() + "\n"
}

// windowManagerCmd is the window manager to run inside the virtual display,
// chosen from what is installed rather than assumed.
//
// openbox is what the plan offers to install, so it is preferred and is what
// runs on a machine that accepted the plan. mutter is the fallback that makes
// a Wayland-only GNOME machine work when the openbox install was declined or
// failed — it is already present there. `--x11` matters: mutter defaults to
// its Wayland backend, and `--replace` (the obvious guess) exits immediately
// on a bare Xvnc display because there is no running WM to replace.
func windowManagerCmd() string {
	for _, c := range []struct{ bin, cmd string }{
		{"openbox-session", "openbox-session"},
		{"mutter", "mutter --x11"},
		{"i3", "i3"},
		{"xfwm4", "xfwm4"},
	} {
		if have(c.bin) {
			return c.cmd
		}
	}
	// Nothing installed. A no-op session still beats no xstartup at all: it
	// keeps the display up and grey rather than letting TigerVNC start
	// whatever default it would otherwise pick.
	return "tail -f /dev/null"
}

// readXstartup returns an existing xstartup and whether LocNet wrote it.
//
// A missing or unreadable file reports empty, which the caller treats as safe
// to write. Only a file carrying the marker is ours to replace.
func readXstartup(path string) (content string, mine bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return string(raw), strings.Contains(string(raw), xstartupMarker)
}

// singleInstanceApps names the terminal emulators an xstartup starts that
// would capture launches made on the real desktop. See generatedXstartup.
func singleInstanceApps(script string) []string {
	var found []string
	for _, bin := range []string{"ptyxis", "gnome-terminal", "kgx", "gnome-console"} {
		for _, line := range strings.Split(script, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// A bare mention in a test like `[ -x /usr/bin/ptyxis ]` is not a
			// launch on its own, but it is always paired with one, and the
			// warning is advisory — a false positive costs a line of output.
			if strings.Contains(line, bin) {
				found = append(found, bin)
				break
			}
		}
	}
	return found
}

// vncConfigDirs are the places TigerVNC has looked for per-user options, old
// first. Both are written; see writeVNCConfig.
func vncConfigDirs(u *user.User) []string {
	return []string{
		filepath.Join(u.HomeDir, ".vnc"),
		filepath.Join(u.HomeDir, ".config", "tigervnc"),
	}
}

func chownTo(path string, u *user.User) error {
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return nil // a non-numeric id means a directory service; leave it be
	}
	return os.Chown(path, uid, gid)
}

// vncUnitName finds the systemd template TigerVNC installed, which is
// "tigervncserver@" on Debian and "vncserver@" almost everywhere else. Probing
// for the file is more durable than a table of distribution names.
func vncUnitName() string {
	for _, name := range []string{"tigervncserver", "vncserver"} {
		for _, dir := range []string{"/usr/lib/systemd/system", "/lib/systemd/system", "/etc/systemd/system"} {
			if _, err := os.Stat(filepath.Join(dir, name+"@.service")); err == nil {
				return name
			}
		}
	}
	return ""
}

// xSessionName is the name of an installed X session, without the .desktop
// suffix — what TigerVNC's `session=` option wants. Empty when the machine has
// only Wayland sessions, which is now common.
func xSessionName() string {
	entries, err := os.ReadDir("/usr/share/xsessions")
	if err != nil {
		return ""
	}
	// Prefer a plain session over a vendor variant when both are present:
	// "gnome" starts faster and breaks less inside Xvnc than "ubuntu" does.
	var names []string
	for _, e := range entries {
		if name, ok := strings.CutSuffix(e.Name(), ".desktop"); ok {
			names = append(names, name)
		}
	}
	for _, want := range []string{"xfce", "openbox", "mate", "gnome", "plasma"} {
		for _, n := range names {
			if n == want {
				return n
			}
		}
	}
	if len(names) > 0 {
		return names[0]
	}
	return ""
}

func haveXSession() bool { return xSessionName() != "" }

// desktopUser is the account the virtual desktop should belong to: the person
// who ran sudo, never root. A desktop owned by root is both a bad idea and,
// for tigervncsession, a refused one.
func desktopUser() (*user.User, error) {
	name := os.Getenv("SUDO_USER")
	if name == "" || name == "root" {
		return nil, fmt.Errorf("cannot tell whose desktop to share — run this with sudo from your own account,\n" +
			"not as a root login, so LocNet knows which user the screen belongs to")
	}
	u, err := user.Lookup(name)
	if err != nil {
		return nil, fmt.Errorf("looking up %q: %w", name, err)
	}
	if u.Uid == "0" {
		return nil, fmt.Errorf("the virtual desktop cannot belong to root")
	}
	return u, nil
}

// dedupe keeps a list of missing settings readable when the file and the
// process are both short of the same one.
func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// waitForDisplayFree blocks until nothing holds the display any more.
//
// The lock file and the socket outlive the process that made them by a short
// margin, and TigerVNC checks both before it will start.
func waitForDisplayFree(display int, within time.Duration) error {
	deadline := time.Now().Add(within)
	for {
		if displayFree(display) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("display :%d is still held after %s — something else is using it.\n"+
				"Check with:  ls -la /tmp/.X%d-lock /tmp/.X11-unix/X%d", display, within, display, display)
		}
		time.Sleep(300 * time.Millisecond)
	}
}
