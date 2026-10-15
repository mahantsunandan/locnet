package sshkeys

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const humanKey = "ssh-ed25519 AAAAHUMAN sono@laptop"

func tempTarget(t *testing.T) Target {
	t.Helper()
	return Target{Path: filepath.Join(t.TempDir(), ".ssh", "authorized_keys")}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func seed(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSyncAddsKeysToAMissingFile(t *testing.T) {
	tgt := tempTarget(t)
	added, removed, err := Sync(tgt, []Entry{{Peer: "hubpc", PublicKey: "ssh-ed25519 AAAAX"}})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if added != 1 || removed != 0 {
		t.Fatalf("added=%d removed=%d, want 1/0", added, removed)
	}
	got := read(t, tgt.Path)
	if !strings.Contains(got, "ssh-ed25519 AAAAX "+Marker+":hubpc") {
		t.Errorf("key not installed:\n%s", got)
	}
}

// The one that must never regress. A key a human added by hand is very likely
// their only other way into the machine; removing it while "tidying up" managed
// entries would lock somebody out of their own server.
func TestSyncNeverTouchesUnmanagedKeys(t *testing.T) {
	tgt := tempTarget(t)
	seed(t, tgt.Path, humanKey+"\n# a comment someone wrote\n")

	if _, _, err := Sync(tgt, []Entry{{Peer: "hubpc", PublicKey: "ssh-ed25519 AAAAX"}}); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	// Then remove every managed key.
	if _, removed, err := Sync(tgt, nil); err != nil || removed != 1 {
		t.Fatalf("Sync remove: removed=%d err=%v", removed, err)
	}

	got := read(t, tgt.Path)
	if !strings.Contains(got, humanKey) {
		t.Errorf("hand-written key was removed:\n%s", got)
	}
	if !strings.Contains(got, "# a comment someone wrote") {
		t.Errorf("hand-written comment was removed:\n%s", got)
	}
	if strings.Contains(got, Marker) {
		t.Errorf("managed key survived removal:\n%s", got)
	}
}

func TestSyncIsIdempotent(t *testing.T) {
	tgt := tempTarget(t)
	want := []Entry{
		{Peer: "hubpc", PublicKey: "ssh-ed25519 AAAAX"},
		{Peer: "macbook", PublicKey: "ssh-ed25519 AAAAM"},
	}
	if _, _, err := Sync(tgt, want); err != nil {
		t.Fatalf("first Sync: %v", err)
	}
	first := read(t, tgt.Path)

	added, removed, err := Sync(tgt, want)
	if err != nil {
		t.Fatalf("second Sync: %v", err)
	}
	if added != 0 || removed != 0 {
		t.Errorf("second run changed things: added=%d removed=%d", added, removed)
	}
	if second := read(t, tgt.Path); second != first {
		t.Errorf("file changed on an unchanged sync:\n%q\nvs\n%q", first, second)
	}
}

// A peer that regenerates its key must replace the old line, not accumulate a
// second one — otherwise the stale key keeps working forever.
func TestSyncReplacesARotatedKey(t *testing.T) {
	tgt := tempTarget(t)
	if _, _, err := Sync(tgt, []Entry{{Peer: "hubpc", PublicKey: "ssh-ed25519 OLD"}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Sync(tgt, []Entry{{Peer: "hubpc", PublicKey: "ssh-ed25519 NEW"}}); err != nil {
		t.Fatal(err)
	}

	got := read(t, tgt.Path)
	if strings.Contains(got, "OLD") {
		t.Errorf("rotated-out key still present:\n%s", got)
	}
	if !strings.Contains(got, "NEW") {
		t.Errorf("new key missing:\n%s", got)
	}
	if n := strings.Count(got, Marker+":hubpc"); n != 1 {
		t.Errorf("got %d entries for hubpc, want 1:\n%s", n, got)
	}
}

func TestSyncSkipsEmptyKeys(t *testing.T) {
	tgt := tempTarget(t)
	added, _, err := Sync(tgt, []Entry{{Peer: "ghost", PublicKey: "   "}})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if added != 0 {
		t.Errorf("added=%d, want 0 for an empty key", added)
	}
}

func TestSyncWritesRestrictivePermissions(t *testing.T) {
	if os.Getenv("GOOS") == "windows" {
		t.Skip("POSIX modes")
	}
	tgt := tempTarget(t)
	if _, _, err := Sync(tgt, []Entry{{Peer: "hubpc", PublicKey: "ssh-ed25519 AAAAX"}}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(tgt.Path)
	if err != nil {
		t.Fatal(err)
	}
	// sshd ignores an authorized_keys that the group or others can read.
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("mode = %o, want no group/other bits", mode)
	}
}
