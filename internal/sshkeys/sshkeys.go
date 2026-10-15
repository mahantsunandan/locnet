// Package sshkeys installs peers' public keys where the local SSH server will
// actually read them.
//
// The complication this exists for is Windows. Microsoft's OpenSSH ships an
// sshd_config ending in
//
//	Match Group administrators
//	    AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
//
// so for any account in the Administrators group — which on a normal desktop is
// the account somebody actually uses — a key in ~/.ssh/authorized_keys is
// ignored completely. ssh-copy-id writes there, reports success, and key auth
// still does not work. That failure is silent from both ends: the file exists,
// the permissions look fine, and sshd simply never reads it. The file also
// needs its inherited ACLs stripped, or sshd rejects it without saying so in
// any log the user is likely to find.
//
// Getting this right once, here, is the difference between key distribution
// that works on every platform and key distribution that works on Unix and
// mystifies people on Windows.
package sshkeys

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Marker tags the lines this package manages.
//
// Keys are installed with a marker so they can be removed again exactly. A
// machine that leaves the network should stop being able to log in, and that
// means finding this tool's lines without disturbing keys a human put there by
// hand — which must survive untouched, since one of them is very likely the
// operator's only other way in.
const Marker = "locnet-peer"

// Entry is one peer's key.
type Entry struct {
	// Peer is the machine the key belongs to, as the network names it.
	Peer string
	// PublicKey is a single-line OpenSSH public key ("ssh-ed25519 AAAA… ").
	PublicKey string
}

// comment renders the trailing comment that marks a managed line.
func (e Entry) comment() string { return Marker + ":" + e.Peer }

// line renders the authorized_keys line for this entry.
func (e Entry) line() string {
	return strings.TrimSpace(e.PublicKey) + " " + e.comment()
}

// Target is where keys go for one account, and how to lock it down afterwards.
type Target struct {
	// Path is the authorized_keys file sshd will read for this account.
	Path string
	// Admin reports whether Path is the Windows administrators file, which is
	// shared by every administrator rather than owned by one user.
	Admin bool
}

// Sync makes the managed keys in the account's authorized_keys exactly match
// want, leaving every unmanaged line alone.
//
// Returns the number of keys added and removed. Writing is atomic: a temporary
// file in the same directory, then a rename, so an interrupted run cannot leave
// a truncated authorized_keys and lock everybody out.
func Sync(t Target, want []Entry) (added, removed int, err error) {
	existing, err := readLines(t.Path)
	if err != nil {
		return 0, 0, err
	}

	wanted := map[string]Entry{}
	for _, e := range want {
		if strings.TrimSpace(e.PublicKey) == "" {
			continue
		}
		wanted[e.comment()] = e
	}

	var kept []string
	have := map[string]bool{}
	for _, line := range existing {
		tag, managed := managedTag(line)
		if !managed {
			// Somebody else's key. Not ours to touch.
			kept = append(kept, line)
			continue
		}
		if e, ok := wanted[tag]; ok && strings.TrimSpace(line) == e.line() {
			kept = append(kept, line)
			have[tag] = true
			continue
		}
		if _, ok := wanted[tag]; !ok {
			removed++
			continue
		}
		// Managed, wanted, but the key changed: drop it and re-add below.
		removed++
	}

	var fresh []string
	for tag, e := range wanted {
		if have[tag] {
			continue
		}
		fresh = append(fresh, e.line())
		added++
	}
	sort.Strings(fresh)

	if added == 0 && removed == 0 {
		return 0, 0, nil
	}
	return added, removed, write(t, append(kept, fresh...))
}

// managedTag reports whether a line is one of ours, and its peer tag.
func managedTag(line string) (string, bool) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", false
	}
	last := fields[len(fields)-1]
	if !strings.HasPrefix(last, Marker+":") {
		return "", false
	}
	return last, true
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out, sc.Err()
}

// write replaces the file atomically and then fixes its permissions.
func write(t Target, lines []string) error {
	dir := filepath.Dir(t.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".authorized_keys-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	body := strings.Join(lines, "\n")
	if body != "" {
		body += "\n"
	}
	if _, err := tmp.WriteString(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpName, t.Path); err != nil {
		return err
	}
	return secure(t)
}

// writeLines replaces a file atomically, for callers that manage their own
// permissions. Same rename dance as write: a half-written known_hosts is a
// machine that cannot verify anybody.
func writeLines(path string, lines []string, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	body := strings.Join(lines, "\n")
	if body != "" {
		body += "\n"
	}
	if _, err := tmp.WriteString(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// ErrNoAccount is returned when there is no account to install keys for.
var ErrNoAccount = fmt.Errorf("no local account to install keys for")

// Describe names the file keys will go to, for a consent prompt.
func Describe(t Target) string {
	if t.Admin {
		return t.Path + " (shared by every administrator on this machine)"
	}
	return t.Path
}
