package sshkeys

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// TargetFor returns where sshd will look for the account's keys.
//
// For an administrator that is not the account's own ~/.ssh/authorized_keys but
// a single machine-wide file, because Microsoft's default sshd_config redirects
// the whole administrators group there:
//
//	Match Group administrators
//	    AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
//
// Writing to the home directory instead is the single most common way to
// "install" a key on Windows and have nothing happen. ssh-copy-id does exactly
// that, cheerfully, which is why this package exists rather than a call to it.
func TargetFor(user string) (Target, error) {
	if user == "" {
		return Target{}, ErrNoAccount
	}
	if isAdmin(user) {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return Target{
			Path:  filepath.Join(programData, "ssh", "administrators_authorized_keys"),
			Admin: true,
		}, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return Target{}, err
	}
	return Target{Path: filepath.Join(home, ".ssh", "authorized_keys")}, nil
}

// isAdmin reports whether the account is in the local Administrators group.
//
// Asked of the group rather than of the name, because "Administrator" the
// account and "administrators" the group are different things and it is the
// group that sshd matches on. Any failure answers true: assuming administrator
// writes the machine-wide file, which sshd reads for administrators and
// ordinary users both — via the Match block for the former and not at all for
// the latter. Guessing the other way installs a key nobody will ever read.
func isAdmin(user string) bool {
	script := fmt.Sprintf(
		`$ErrorActionPreference='SilentlyContinue';`+
			`$g=Get-LocalGroupMember -Group 'Administrators' | ForEach-Object { $_.Name };`+
			`$u='%s';`+
			`exit [int](-not [bool]($g | Where-Object { $_ -eq $u -or $_ -split '\\' -contains $u }))`,
		strings.ReplaceAll(user, "'", "''"))
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	return cmd.Run() == nil
}

// secure strips inherited ACLs so sshd will accept the file.
//
// sshd refuses an authorized_keys file that anyone but SYSTEM and the owner can
// write, and says so only in its own log at a debug level nobody has turned on.
// The symptom is a password prompt after a key install that reported success —
// indistinguishable, from the client, from the key never having been installed.
func secure(t Target) error {
	if !t.Admin {
		// A user file inherits sensible ACLs from the profile directory.
		return nil
	}
	out, err := exec.Command("icacls", t.Path,
		"/inheritance:r",
		"/grant", "SYSTEM:F",
		"/grant", "BUILTIN\\Administrators:F",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls %s: %s", t.Path, strings.TrimSpace(string(out)))
	}
	return nil
}
