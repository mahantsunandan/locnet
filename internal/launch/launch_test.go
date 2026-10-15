package launch

import (
	"os"
	"strings"
	"testing"
)

// TestRemoteDesktopKindsNeedSomewhereToAsk is the bug behind `locnet rdp`
// failing with "tcgetattr() failed with Inappropriate ioctl for device".
//
// GNOME's remote desktop server uses network-level authentication: it demands
// credentials before it will show a single pixel, so the client prompts the
// instant it connects. Started with no stdin and no window of its own, it has
// nobody to ask, aborts, and the failure reads as a refused connection.
func TestRemoteDesktopKindsNeedSomewhereToAsk(t *testing.T) {
	for _, k := range []Kind{KindRDP, KindVNC} {
		if !k.NeedsCredentials() {
			t.Errorf("%s does not declare that it may need credentials", k)
		}
	}
	for _, k := range []Kind{KindBrowser, KindSMB} {
		if k.NeedsCredentials() {
			t.Errorf("%s should not be treated as needing a password prompt", k)
		}
	}
}

// Without a terminal, the clients that can ask in their own window must come
// first — otherwise the console launches one that tries to prompt on a
// terminal that is not there.
func TestWithoutATerminalGuiClientsComeFirst(t *testing.T) {
	list := guiFirst(clients(KindRDP))
	if len(list) == 0 {
		t.Skip("no RDP clients are known for this platform")
	}
	var sawPlain bool
	for _, c := range list {
		if !c.guiAuth {
			sawPlain = true
			continue
		}
		if sawPlain {
			t.Errorf("%s can ask for a password in its own window but is ordered after one that cannot", c.bin)
		}
	}
}

// hasTerminal must say no when standard input is a pipe or a file, which is
// what it is under the web console and under `go test`.
func TestHasTerminalIsFalseWithoutOne(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	old := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = old }()

	if hasTerminal() {
		t.Error("a pipe was mistaken for a terminal a client could prompt on")
	}
}

// The login name has to reach the RDP client, or every connection starts by
// asking for something LocNet already knows.
func TestLoginIsPassedToRDPClients(t *testing.T) {
	list := clientsFor(KindRDP, "ada")
	if len(list) == 0 {
		t.Skip("no RDP clients are known for this platform")
	}
	for _, c := range list {
		args := strings.Join(c.args("10.99.0.1:3389"), " ")
		if !strings.Contains(args, "ada") {
			t.Errorf("%s is invoked without the login name: %s", c.bin, args)
		}
	}
}

// TestCredentialKindsPreferAClientThatRemembers is the answer to "it asks for
// the password every time".
//
// SSH never asks because a key replaced the password; remote desktop has no
// equivalent, so somebody has to keep it. LocNet's answer is not to invent a
// password store of its own but to reach for the client that already uses the
// desktop's keyring.
func TestCredentialKindsPreferAClientThatRemembers(t *testing.T) {
	for _, k := range []Kind{KindRDP, KindVNC} {
		list := rememberingFirst(clients(k))
		if len(list) == 0 {
			continue
		}
		var anyRemembers bool
		for _, c := range list {
			if c.remembers {
				anyRemembers = true
			}
		}
		if !anyRemembers {
			continue // no such client on this platform; nothing to order
		}
		if !list[0].remembers {
			t.Errorf("%s: %s is tried first, but it cannot save the password", k, list[0].bin)
		}
		// And nothing may be dropped: the preferred client is often absent.
		if len(list) != len(clients(k)) {
			t.Errorf("%s: reordering lost a client (%d -> %d)", k, len(clients(k)), len(list))
		}
	}
}

func TestVNCViewersAreGivenAPortNotADisplay(t *testing.T) {
	for in, want := range map[string]string{
		"10.99.0.1:5900":  "10.99.0.1::5900",
		"10.99.0.1::5901": "10.99.0.1::5901",
		"10.99.0.1":       "10.99.0.1",
	} {
		if got := vncHostPort(in); got != want {
			t.Errorf("vncHostPort(%q) = %q, want %q", in, got, want)
		}
	}
}
