package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/mahantsunandan/locnet/internal/ipc"
	"github.com/mahantsunandan/locnet/internal/resource"
)

// setupRDP gets this machine's own RDP server to the point where somebody can
// log in to it.
//
// On a GNOME desktop that server is GNOME Remote Desktop, and it has a trap:
// switching RDP on in Settings — or anything that enables it without a login —
// leaves it listening on 3389 and hanging up on every client, because it has no
// username and password to check anyone against. Nothing on the screen says so;
// the client just fails. This sets the login, using grdctl's own prompts so the
// password goes from the keyboard to GNOME and nowhere else, turns remote
// control on, and then checks the server answers the way a working one does.
//
// It runs as the person who logs in at this machine, not as root: the RDP login
// lives in their desktop settings and their keyring.
func setupRDP(replace bool) error {
	switch runtime.GOOS {
	case "windows":
		fmt.Println("Windows has its own RDP server: Settings → System → Remote Desktop → On.")
		fmt.Println("Then, from another machine:  locnet rdp <this machine>   and log in with your Windows account.")
		return nil
	case "darwin":
		fmt.Println("macOS has no RDP server. Use its VNC server instead: System Settings →")
		fmt.Println("General → Sharing → Screen Sharing. Then:  locnet vnc <this machine>")
		return nil
	}

	if os.Geteuid() == 0 {
		return errors.New("run this without sudo, as the person who logs in at this machine's desktop.\n" +
			"GNOME keeps the RDP login in that person's own settings, not root's")
	}
	if _, err := exec.LookPath("grdctl"); err != nil {
		return errors.New("this desktop has no GNOME Remote Desktop (no grdctl).\n" +
			"On GNOME: install gnome-remote-desktop.  On other desktops, xrdp is the usual RDP\n" +
			"server — install it with your package manager, then: sudo systemctl enable --now xrdp")
	}
	ensureSessionBus()

	me := currentUser()
	fmt.Println()
	fmt.Println("This sets up GNOME's own remote desktop server, which shows this machine's real")
	fmt.Println("screen to an RDP client — whatever is on the monitor, lock screen included.")
	fmt.Println()

	// GNOME keeps the RDP login in the user's keyring, and reads it from there
	// every time a client connects. A machine that logs in automatically never
	// unlocks that keyring — nobody typed a password for PAM to hand it — so
	// GNOME can neither store a login nor find one, and refuses everyone with
	// "Credentials are not set" whatever is configured. That has to be undone
	// first, and again after every reboot on such a machine.
	if locked, known := keyringLocked(); known && locked {
		if err := unlockKeyring(me); err != nil {
			return err
		}
	}

	status, err := grdctl("status")
	if err != nil {
		return fmt.Errorf("could not ask GNOME Remote Desktop how it is set up (%v).\n"+
			"Run this from your desktop session, or over SSH while you are logged in at the desktop", err)
	}
	port := rdpPort(status)

	if hasRDPLogin(status) && !replace {
		fmt.Println("It already has an RDP login, which is kept. (To choose a new one:  locnet setup rdp -new)")
		fmt.Println()
	} else {
		fmt.Printf("Choose the username and password an RDP client will log in with. Using your own\n"+
			"account name, %s, keeps it simple; the password can be anything. GNOME keeps it\n"+
			"in your keyring — LocNet never sees it.\n\n", me)
		set := exec.Command("grdctl", "rdp", "set-credentials")
		set.Stdin, set.Stdout, set.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := set.Run(); err != nil {
			return fmt.Errorf("grdctl rdp set-credentials: %w", err)
		}
		fmt.Println()
	}

	for _, args := range [][]string{
		{"rdp", "disable-view-only"}, // let the person connecting use the mouse and keyboard
		{"rdp", "enable"},
	} {
		if out, err := grdctl(args...); err != nil {
			return fmt.Errorf("grdctl %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	// The daemon runs in the desktop session. It is normally there already;
	// if it is not, start it, and at every login from now on.
	if exec.Command("systemctl", "--user", "is-active", "--quiet", "gnome-remote-desktop.service").Run() != nil {
		_ = exec.Command("systemctl", "--user", "enable", "--now", "gnome-remote-desktop.service").Run()
	}

	// Check the way a client would. GNOME picks the settings up within a
	// moment, so give it a few tries before calling it a failure.
	target := net.JoinHostPort("127.0.0.1", port)
	var problem string
	for i := 0; i < 8; i++ {
		time.Sleep(time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		problem = resource.CheckProtocol(ctx, "rdp", target)
		cancel()
		if problem == "" {
			break
		}
	}
	if problem != "" {
		return fmt.Errorf("the login is set, but the RDP server still does not answer properly: %s\n"+
			"Check: journalctl --user -u gnome-remote-desktop -n 20", problem)
	}

	// Have the agent look again now, so peers stop being warned off a server
	// that works, rather than in up to five minutes. Not being allowed to ask
	// it is fine: the next scan gets there anyway.
	if c, err := ipc.Dial(); err == nil {
		_ = c.Post("/rescan", struct{}{}, nil)
	}

	host, _ := os.Hostname()
	fmt.Println("✓ RDP is ready, and accepts logins.")
	fmt.Println()
	fmt.Printf("From another machine:  locnet rdp %s   — or Screen (RDP) in locnet console.\n", shortHost(host))
	fmt.Println("Log in with the username and password you just chose. Remmina offers to")
	fmt.Println("remember the password, so you type it once.")
	return nil
}

// keyringLocked asks the Secret Service whether the login keyring is locked.
// known is false when that cannot be asked, and the caller carries on.
func keyringLocked() (locked, known bool) {
	out, err := exec.Command("busctl", "--user", "get-property", "org.freedesktop.secrets",
		"/org/freedesktop/secrets/collection/login", "org.freedesktop.Secret.Collection", "Locked").Output()
	if err != nil {
		return false, false
	}
	v := strings.TrimSpace(string(out))
	return v == "b true", v == "b true" || v == "b false"
}

// unlockKeyring unlocks the login keyring with the account password, typed
// here without echo and handed straight to gnome-keyring on its standard input.
// It is not kept, logged, or put on any command line.
func unlockKeyring(who string) error {
	fmt.Println("Your keyring is locked — usual on a machine that logs in automatically, since")
	fmt.Println("nobody typed a password to unlock it. GNOME keeps the RDP login in it, so it")
	fmt.Println("must be unlocked first. On a machine that logs in by itself this is needed")
	fmt.Println("again after every restart: run  locnet setup rdp  then too.")
	fmt.Println()
	for attempt := 0; attempt < 3; attempt++ {
		fmt.Printf("Password for %s on this machine: ", who)
		pw, err := readSecret()
		if err != nil {
			return fmt.Errorf("reading the password: %w", err)
		}
		cmd := exec.Command("gnome-keyring-daemon", "--unlock")
		cmd.Stdin = strings.NewReader(pw)
		pw = ""
		if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" && os.Getenv("GNOME_KEYRING_CONTROL") == "" {
			cmd.Env = append(os.Environ(), "GNOME_KEYRING_CONTROL="+filepath.Join(dir, "keyring"))
		}
		_ = cmd.Run() // its output is environment variables; success is judged below
		if locked, _ := keyringLocked(); !locked {
			fmt.Println("✓ keyring unlocked")
			fmt.Println()
			return nil
		}
		fmt.Println("That did not unlock it. (If you changed your password, the keyring may still")
		fmt.Println("use the old one.)")
	}
	return errors.New("the keyring is still locked, so GNOME cannot keep an RDP login")
}

// grdctl runs one grdctl command and returns its output.
func grdctl(args ...string) (string, error) {
	out, err := exec.Command("grdctl", args...).CombinedOutput()
	return string(out), err
}

// ensureSessionBus points GLib at the desktop session's bus when this runs in
// an SSH session, which has none of its own. grdctl keeps its settings and the
// login in that session — without the bus it fails, or worse, writes to a
// throwaway one.
func ensureSessionBus() {
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") != "" {
		return
	}
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		runtimeDir = fmt.Sprintf("/run/user/%d", os.Getuid())
		os.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	}
	bus := filepath.Join(runtimeDir, "bus")
	if _, err := os.Stat(bus); err == nil {
		os.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+bus)
	}
}

var (
	reRDPSection = regexp.MustCompile(`(?s)RDP:\s*\n(.*?)(?:\n\S|\z)`)
	rePort       = regexp.MustCompile(`(?m)^\s*Port:\s*(\d+)`)
	reUser       = regexp.MustCompile(`(?m)^\s*Username:\s*(.+)$`)
)

// rdpSection is the RDP part of `grdctl status`, which also has a VNC part
// with fields of the same names.
func rdpSection(status string) string {
	if m := reRDPSection.FindStringSubmatch(status); m != nil {
		return m[1]
	}
	return ""
}

func rdpPort(status string) string {
	if m := rePort.FindStringSubmatch(rdpSection(status)); m != nil {
		return m[1]
	}
	return "3389"
}

// hasRDPLogin reports whether a username is set. `grdctl status` prints
// "(hidden)" for one that is set — this deliberately never asks for
// --show-credentials, which would put the password in this process.
func hasRDPLogin(status string) bool {
	m := reUser.FindStringSubmatch(rdpSection(status))
	if m == nil {
		return false
	}
	u := strings.TrimSpace(m[1])
	return u != "" && u != "(null)" && u != "(empty)"
}

func currentUser() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return os.Getenv("USER")
}

func shortHost(h string) string {
	if i := strings.IndexByte(h, '.'); i > 0 {
		return h[:i]
	}
	if h == "" {
		return "<this machine>"
	}
	return h
}

// rdpNote is the line `locnet setup` adds when this machine's RDP server is
// listening but would refuse everyone. setup itself runs as root and cannot
// fix it — the login belongs to the desktop user — so it says who should run
// what.
func rdpNote() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	c, err := net.DialTimeout("tcp", "127.0.0.1:3389", time.Second)
	if err != nil {
		return ""
	}
	c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	problem := resource.CheckProtocol(ctx, "rdp", "127.0.0.1:3389")
	if problem == "" {
		return ""
	}
	return "\n  Remote desktop (RDP): " + problem + " (without sudo)\n"
}
