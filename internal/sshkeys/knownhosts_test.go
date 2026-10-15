package sshkeys

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const handWritten = "github.com ssh-ed25519 AAAAGITHUB"

func khPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), ".ssh", "known_hosts")
}

func TestSyncKnownHostsWritesNameAndAddress(t *testing.T) {
	path := khPath(t)
	hosts := []KnownHost{{
		Name: "hubpc",
		IP:   netip.MustParseAddr("10.99.0.1"),
		Keys: []string{"ssh-ed25519 AAAAX"},
	}}
	if _, err := SyncKnownHosts(path, hosts); err != nil {
		t.Fatalf("SyncKnownHosts: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	line := string(got)
	// Both forms, because a person types the name and locnet dials the address.
	if !strings.Contains(line, "hubpc,10.99.0.1 ssh-ed25519 AAAAX") {
		t.Errorf("entry missing name+address form:\n%s", line)
	}
	if !strings.Contains(line, Marker+":hubpc") {
		t.Errorf("entry not marked as managed:\n%s", line)
	}
}

func TestSyncKnownHostsLeavesHandWrittenEntriesAlone(t *testing.T) {
	path := khPath(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(handWritten+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := SyncKnownHosts(path, []KnownHost{{
		Name: "hubpc", IP: netip.MustParseAddr("10.99.0.1"), Keys: []string{"ssh-ed25519 AAAAX"},
	}}); err != nil {
		t.Fatal(err)
	}
	// Then remove every peer.
	if _, err := SyncKnownHosts(path, nil); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), handWritten) {
		t.Errorf("hand-written known_hosts entry was destroyed:\n%s", got)
	}
	if strings.Contains(string(got), Marker) {
		t.Errorf("managed entry survived removal:\n%s", got)
	}
}

// An unchanged netmap arrives constantly. Rewriting known_hosts every time
// would churn the file and its mtime for no reason.
func TestSyncKnownHostsIsIdempotent(t *testing.T) {
	path := khPath(t)
	hosts := []KnownHost{{
		Name: "hubpc", IP: netip.MustParseAddr("10.99.0.1"), Keys: []string{"ssh-ed25519 AAAAX"},
	}}
	if _, err := SyncKnownHosts(path, hosts); err != nil {
		t.Fatal(err)
	}
	n, err := SyncKnownHosts(path, hosts)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("second sync reported %d changes, want 0", n)
	}
}

// A rebuilt machine publishes a new host key. The old one must go, or ssh sees
// a conflict and refuses with the warning that means an attack.
func TestSyncKnownHostsReplacesRotatedHostKey(t *testing.T) {
	path := khPath(t)
	ip := netip.MustParseAddr("10.99.0.1")

	if _, err := SyncKnownHosts(path, []KnownHost{{Name: "hubpc", IP: ip, Keys: []string{"ssh-ed25519 OLD"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := SyncKnownHosts(path, []KnownHost{{Name: "hubpc", IP: ip, Keys: []string{"ssh-ed25519 NEW"}}}); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "OLD") {
		t.Errorf("stale host key still trusted:\n%s", got)
	}
	if !strings.Contains(string(got), "NEW") {
		t.Errorf("new host key missing:\n%s", got)
	}
}

func TestFirstKeyFieldDropsComment(t *testing.T) {
	in := "ssh-ed25519 AAAABASE64 root@some-other-machine\n"
	if got, want := firstKeyField(in), "ssh-ed25519 AAAABASE64"; got != want {
		t.Errorf("firstKeyField = %q, want %q", got, want)
	}
	if got := firstKeyField("not a key\n"); got != "" {
		t.Errorf("firstKeyField on junk = %q, want empty", got)
	}
	if got := firstKeyField("ecdsa-sha2-nistp256 AAAAE2V j@h\n"); got != "ecdsa-sha2-nistp256 AAAAE2V" {
		t.Errorf("ecdsa key not recognised: %q", got)
	}
}
