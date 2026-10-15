package setup

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The user map is a system file that may already describe other people's
// desktops. Rewriting it wholesale would silently switch off a colleague's
// display, so these check that exactly one line ever changes.

func TestMapVNCUserAddsToAnEmptyFile(t *testing.T) {
	path := tempUsersFile(t, "")
	if err := mapVNCUser("ada", t.Logf); err != nil {
		t.Fatalf("mapVNCUser: %v", err)
	}
	if got := read(t, path); got != ":1=ada\n" {
		t.Errorf("got %q, want %q", got, ":1=ada\n")
	}
}

func TestMapVNCUserKeepsCommentsAndOtherDisplays(t *testing.T) {
	path := tempUsersFile(t, "# TigerVNC user assignment\n#\n# :2=andrew\n:3=lisa\n")
	if err := mapVNCUser("ada", t.Logf); err != nil {
		t.Fatalf("mapVNCUser: %v", err)
	}
	got := read(t, path)
	for _, want := range []string{"# TigerVNC user assignment", "# :2=andrew", ":3=lisa", ":1=ada"} {
		if !strings.Contains(got, want) {
			t.Errorf("result lost %q:\n%s", want, got)
		}
	}
}

// Running setup twice must not leave two mappings for one display: TigerVNC
// reads the file top to bottom and the duplicate would be the one that wins.
func TestMapVNCUserIsIdempotent(t *testing.T) {
	path := tempUsersFile(t, "")
	for i := 0; i < 3; i++ {
		if err := mapVNCUser("ada", t.Logf); err != nil {
			t.Fatalf("mapVNCUser: %v", err)
		}
	}
	if n := strings.Count(read(t, path), ":1="); n != 1 {
		t.Errorf("found %d mappings for display :1, want 1:\n%s", n, read(t, path))
	}
}

func TestMapVNCUserReplacesTheDisplaysOwner(t *testing.T) {
	path := tempUsersFile(t, ":1=grace\n:3=lisa\n")
	if err := mapVNCUser("ada", t.Logf); err != nil {
		t.Fatalf("mapVNCUser: %v", err)
	}
	got := read(t, path)
	if strings.Contains(got, "grace") {
		t.Errorf("the previous owner of :1 survived:\n%s", got)
	}
	if !strings.Contains(got, ":3=lisa") {
		t.Errorf("an unrelated display was lost:\n%s", got)
	}
}

// A step with an Apply must describe it, or the consent prompt is a lie.
func TestVNCStepExplainsWhatItWillDo(t *testing.T) {
	s := vncStep(distro{id: "debian", install: []string{"apt-get", "install", "-y"},
		vncServer: "tigervnc-standalone-server"})
	if s.Done {
		return // already running on this machine; nothing is planned
	}
	if s.Apply == nil {
		t.Fatal("the step does no configuration")
	}
	if len(s.Explain) == 0 {
		t.Error("the step configures things it does not disclose")
	}
}

// pinDisplay fixes the display number so these tests do not depend on which
// displays happen to be free on the machine running them.
func pinDisplay(t *testing.T, n int) {
	t.Helper()
	vncDisplayOnce = sync.Once{}
	vncDisplayNum = n
	t.Cleanup(func() {
		vncDisplayOnce = sync.Once{}
		vncDisplayNum = 0
	})
}

func tempUsersFile(t *testing.T, body string) string {
	t.Helper()
	pinDisplay(t, 1)
	path := filepath.Join(t.TempDir(), "vncserver.users")
	if body != "" {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	old := vncUsersFile
	vncUsersFile = path
	t.Cleanup(func() { vncUsersFile = old })
	return path
}

func read(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestDisplayInUseIsNotOffered is the bug that made screen sharing unusable on
// a machine with somebody logged in: GNOME's Xwayland had already taken :1, so
// the VNC server configured there died on every start with "A VNC server is
// already running as :1" — while systemd reported success and setup printed a
// tick.
func TestDisplayInUseIsNotOffered(t *testing.T) {
	// Occupy a display the way a running X server does.
	dir := t.TempDir()
	lock := filepath.Join(dir, ".X99-lock")
	if err := os.WriteFile(lock, []byte("      1234\n"), 0o444); err != nil {
		t.Fatal(err)
	}

	// A port that is genuinely taken must also count as taken.
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Skip("cannot bind a port here")
	}
	defer ln.Close()
	busy := ln.Addr().(*net.TCPAddr).Port
	if busy > 5900 && busy < 5932 {
		if displayFree(busy - 5900) {
			t.Errorf("display :%d was offered while its RFB port is bound", busy-5900)
		}
	}

	// And the display the *test process itself* can bind must be free.
	free := firstFreeDisplay()
	if free < 1 || free > 32 {
		t.Fatalf("firstFreeDisplay returned :%d, outside the range it searches", free)
	}
	if !displayFree(free) {
		t.Errorf("firstFreeDisplay chose :%d, which displayFree calls taken", free)
	}
}

// TestConfiguredDisplayIsSticky: once setup has mapped a display, a second run
// must reuse it rather than wander to a new number and leave the first server
// running on the old one.
func TestConfiguredDisplayIsSticky(t *testing.T) {
	tempUsersFile(t, ":7=ada\n")
	vncDisplayOnce = sync.Once{}
	vncDisplayNum = 0
	t.Cleanup(func() { vncDisplayOnce = sync.Once{}; vncDisplayNum = 0 })

	if got := vncDisplay(); got != 7 {
		t.Errorf("vncDisplay() = :%d, want the :7 already in the user map", got)
	}
}

// Two mappings and no way to tell whose desktop this is, is genuinely
// ambiguous — picking one at random would hand somebody else's display to this
// machine's screen share.
func TestAmbiguousUserMapIsNotGuessed(t *testing.T) {
	tempUsersFile(t, ":4=ada\n:5=grace\n")
	if _, ok := configuredDisplay(); ok {
		t.Error("configuredDisplay guessed between two mappings it cannot choose between")
	}
}

// TestStickinessYieldsToAnOccupiedDisplay: reusing the display already in the
// user map is right, but not when something else has taken it since. The
// machine this came from had :1 both mapped from a failed attempt and occupied
// by the desktop session, so loyalty to the mapping meant reconfiguring the
// same dead display on every run.
func TestStickinessYieldsToAnOccupiedDisplay(t *testing.T) {
	tempUsersFile(t, ":1=ada\n")

	// Occupy :1's RFB port the way an X server would.
	ln, err := net.Listen("tcp", ":5901")
	if err != nil {
		t.Skip("port 5901 is already in use here, which is the case this tests")
	}
	defer ln.Close()

	if displayUsable(1) {
		t.Error("a display whose RFB port is bound by something else was called usable")
	}
}

// A user who had to move displays must not be left mapped to both.
func TestMovingDisplaysDropsTheOldMapping(t *testing.T) {
	path := tempUsersFile(t, ":1=ada\n:3=grace\n")
	pinDisplay(t, 5)

	if err := mapVNCUser("ada", t.Logf); err != nil {
		t.Fatal(err)
	}
	got := read(t, path)
	if strings.Contains(got, ":1=ada") {
		t.Errorf("ada is still mapped to the display she moved off:\n%s", got)
	}
	if !strings.Contains(got, ":5=ada") {
		t.Errorf("ada was not mapped to her new display:\n%s", got)
	}
	if !strings.Contains(got, ":3=grace") {
		t.Errorf("somebody else's mapping was lost:\n%s", got)
	}
}

// An xstartup somebody tuned by hand is not LocNet's to rewrite. Clobbering it
// is how a working virtual desktop becomes a grey rectangle on the next
// unrelated run of setup.

func TestGeneratedXstartupIsRecognisedAsOurs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xstartup")
	if err := os.WriteFile(path, []byte(generatedXstartup()), 0o755); err != nil {
		t.Fatal(err)
	}
	content, mine := readXstartup(path)
	if !mine {
		t.Errorf("generated xstartup not recognised as ours:\n%s", content)
	}
}

func TestHandWrittenXstartupIsNotOurs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xstartup")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexec startxfce4\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, mine := readXstartup(path); mine {
		t.Error("a hand-written xstartup was reported as LocNet's, so setup would overwrite it")
	}
}

func TestMissingXstartupIsSafeToWrite(t *testing.T) {
	if content, mine := readXstartup(filepath.Join(t.TempDir(), "absent")); content != "" || mine {
		t.Errorf("absent file: got (%q, %v), want (%q, false)", content, mine, "")
	}
}

// The generated session must never start a terminal emulator; that is the bug
// that makes the real desktop's terminal stop opening.

func TestGeneratedXstartupStartsNoTerminal(t *testing.T) {
	if bad := singleInstanceApps(generatedXstartup()); len(bad) > 0 {
		t.Errorf("generated xstartup starts %v on the virtual display", bad)
	}
}

func TestSingleInstanceAppsFindsTheTerminalTrap(t *testing.T) {
	script := "#!/bin/sh\nmutter --x11 &\nif [ -x /usr/bin/ptyxis ]; then\n  ptyxis &\nfi\nexec tail -f /dev/null\n"
	got := singleInstanceApps(script)
	if len(got) != 1 || got[0] != "ptyxis" {
		t.Errorf("got %v, want [ptyxis]", got)
	}
}

func TestSingleInstanceAppsIgnoresComments(t *testing.T) {
	script := "#!/bin/sh\n# Do not start ptyxis here: it would capture every launch.\nexec openbox-session\n"
	if got := singleInstanceApps(script); len(got) > 0 {
		t.Errorf("got %v, want none — a comment naming ptyxis is not a launch", got)
	}
}

func TestWindowManagerCmdIsSomethingInstalled(t *testing.T) {
	cmd := windowManagerCmd()
	if cmd == "" {
		t.Fatal("no window manager command at all")
	}
	// mutter's Wayland default is wrong inside Xvnc, and --replace exits at
	// once when there is no running WM to replace.
	if strings.HasPrefix(cmd, "mutter") && !strings.Contains(cmd, "--x11") {
		t.Errorf("mutter must run with --x11 inside Xvnc, got %q", cmd)
	}
	if strings.Contains(cmd, "--replace") {
		t.Errorf("--replace exits immediately on a bare display, got %q", cmd)
	}
}
