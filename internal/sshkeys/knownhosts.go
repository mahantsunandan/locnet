package sshkeys

import (
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// KnownHost is one peer's identity as known_hosts wants it.
type KnownHost struct {
	// Name and IP are both written, because a user may type either. `locnet
	// ssh` dials the address, but a person at a terminal often uses the name.
	Name string
	IP   netip.Addr
	// Keys are the peer's host public keys, "<type> <base64>" per line.
	Keys []string
}

// SyncKnownHosts rewrites the managed block of an account's known_hosts.
//
// This removes the trust-on-first-use prompt for mesh peers, and it is a real
// improvement in security rather than a convenient weakening of it. The prompt
// asks a question — is this fingerprint the right one? — that nobody can answer
// from the terminal they are sitting at, so in practice it is answered "yes"
// unread, which authenticates nothing. A key learned over an already
// authenticated WireGuard tunnel, from a hub the node verified by fingerprint
// when it joined, is a materially stronger claim than a human squinting at
// hex.
//
// Managed lines carry a trailing marker comment so an entry a person added by
// hand is never rewritten or removed.
func SyncKnownHosts(path string, hosts []KnownHost) (changed int, err error) {
	existing, err := readLines(path)
	if err != nil {
		return 0, err
	}

	want := map[string]string{} // marker tag -> full line
	for _, h := range hosts {
		for _, k := range h.Keys {
			k = strings.TrimSpace(k)
			if k == "" {
				continue
			}
			who := h.Name
			if h.IP.IsValid() {
				who = h.Name + "," + h.IP.String()
			}
			tag := Marker + ":" + h.Name
			want[tag+"|"+k] = who + " " + k + " " + tag
		}
	}

	var kept []string
	for _, line := range existing {
		if _, managed := managedTag(line); managed {
			continue // ours; rebuilt below
		}
		kept = append(kept, line)
	}

	var fresh []string
	for _, line := range want {
		fresh = append(fresh, line)
	}
	sort.Strings(fresh)

	// Compare against what was there so an unchanged map does not rewrite the
	// file every time a netmap arrives.
	var before []string
	for _, line := range existing {
		if _, managed := managedTag(line); managed {
			before = append(before, line)
		}
	}
	sort.Strings(before)
	if strings.Join(before, "\n") == strings.Join(fresh, "\n") {
		return 0, nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return 0, err
	}
	// known_hosts is not a credential, but it lives beside them and inherits
	// the same expectations from sshd's permission checks on ~/.ssh.
	if err := writeLines(path, append(kept, fresh...), 0o644); err != nil {
		return 0, err
	}
	return len(fresh), nil
}

// KnownHostsPath is the file for an account's home directory.
func KnownHostsPath(home string) string {
	return filepath.Join(home, ".ssh", "known_hosts")
}
