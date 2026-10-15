// Package peercfg remembers per-peer connection preferences — mainly which
// account to log in as.
//
// Usernames differ between machines: you might be "sono" on your laptop and
// "username" on the machine you are reaching. Guessing from the local account
// is wrong roughly as often as it is right, so LocNet learns the answer the
// first time you give it and stops asking.
//
// This deliberately does not store passwords. See the note on Set.
package peercfg

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
)

// Peer is what we remember about connecting to one machine.
type Peer struct {
	// User is the account to log in as, for SSH and RDP.
	User string `json:"user,omitempty"`
	// RDPDomain is a Windows domain, if the machine wants one.
	RDPDomain string `json:"rdp_domain,omitempty"`
}

// File is the whole remembered set, keyed by peer name.
type File struct {
	Peers map[string]Peer `json:"peers"`
}

var mu sync.Mutex

// Path is where preferences live: the invoking user's config directory, not a
// system one. Two people using the same machine log in as different accounts,
// and this is a preference rather than configuration.
func Path() (string, error) {
	home, err := invokingHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "locnet", "peers.json"), nil
}

// invokingHome is the home directory of the person who ran the command, seen
// through sudo. Without this, preferences set with sudo would land in /root
// and be invisible the next time.
func invokingHome() (string, error) {
	if name := os.Getenv("SUDO_USER"); name != "" && name != "root" {
		if u, err := user.Lookup(name); err == nil {
			return u.HomeDir, nil
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("peercfg: cannot find a home directory: %w", err)
	}
	return home, nil
}

// Load reads the preferences, returning an empty set if there are none.
func Load() (*File, error) {
	path, err := Path()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &File{Peers: map[string]Peer{}}, nil
		}
		return nil, fmt.Errorf("peercfg: read %s: %w", path, err)
	}
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("peercfg: %s is not valid JSON: %w", path, err)
	}
	if f.Peers == nil {
		f.Peers = map[string]Peer{}
	}
	return &f, nil
}

// UserFor returns the remembered account for a peer, or "".
func UserFor(peer string) string {
	f, err := Load()
	if err != nil {
		return ""
	}
	return f.Peers[peer].User
}

// Set remembers a preference for a peer.
//
// Only the username. LocNet stores no passwords, and that is a decision rather
// than an omission: a plaintext password file is a worse answer than the one
// the operating system already has. SSH has keys, which remove the password
// entirely — see `locnet ssh-key`. RDP and VNC clients have their own
// credential stores, tied to the system keyring, which is where such things
// belong.
func Set(peer string, p Peer) error {
	mu.Lock()
	defer mu.Unlock()

	f, err := Load()
	if err != nil {
		return err
	}
	existing := f.Peers[peer]
	if p.User != "" {
		existing.User = p.User
	}
	if p.RDPDomain != "" {
		existing.RDPDomain = p.RDPDomain
	}
	f.Peers[peer] = existing

	path, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	// Written under sudo, the file would otherwise be owned by root and
	// unreadable to the person it belongs to.
	chownToInvoker(path)
	chownToInvoker(filepath.Dir(path))
	return nil
}

// Forget removes a peer's preferences.
func Forget(peer string) error {
	mu.Lock()
	defer mu.Unlock()
	f, err := Load()
	if err != nil {
		return err
	}
	delete(f.Peers, peer)

	path, err := Path()
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func chownToInvoker(path string) {
	name := os.Getenv("SUDO_USER")
	if name == "" || name == "root" {
		return
	}
	u, err := user.Lookup(name)
	if err != nil {
		return
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return
	}
	_ = os.Chown(path, uid, gid)
}
