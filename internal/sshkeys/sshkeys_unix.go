//go:build !windows

package sshkeys

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

// TargetFor returns the account's ~/.ssh/authorized_keys.
//
// No special case for root here, unlike Windows: sshd on Unix reads the same
// per-account file whoever the account is.
func TargetFor(username string) (Target, error) {
	if username == "" {
		return Target{}, ErrNoAccount
	}
	u, err := user.Lookup(username)
	if err != nil {
		return Target{}, err
	}
	return Target{Path: filepath.Join(u.HomeDir, ".ssh", "authorized_keys")}, nil
}

// secure makes the file belong to the account it authorises.
//
// This runs as root — installing keys needs it — so a freshly created file
// would otherwise be owned by root inside a user's home directory. sshd refuses
// an authorized_keys file the account does not own, with the same unhelpfully
// quiet failure as everywhere else in this area: the key is simply not offered
// and the user is asked for a password.
func secure(t Target) error {
	username := accountFor(t.Path)
	if username == "" {
		return nil
	}
	u, err := user.Lookup(username)
	if err != nil {
		return nil
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return nil
	}
	// The .ssh directory too: sshd checks its permissions as well as the
	// file's, and a root-owned .ssh created on the way here fails the check.
	dir := filepath.Dir(t.Path)
	_ = os.Chown(dir, uid, gid)
	_ = os.Chmod(dir, 0o700)
	return os.Chown(t.Path, uid, gid)
}

// accountFor recovers the username from a path this package built.
func accountFor(path string) string {
	dir := filepath.Dir(filepath.Dir(path)) // strip /.ssh/authorized_keys
	users, err := os.ReadDir("/home")
	if err == nil {
		for _, e := range users {
			if filepath.Join("/home", e.Name()) == dir {
				return e.Name()
			}
		}
	}
	if dir == "/root" {
		return "root"
	}
	// macOS and anything unusual: ask the base name, which is the convention
	// on every platform that puts homes under a common parent.
	return filepath.Base(dir)
}
