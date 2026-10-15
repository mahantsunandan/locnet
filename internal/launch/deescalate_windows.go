package launch

import (
	"os/exec"
	"os/user"
	"strings"
)

// deescalate is a no-op on Windows.
//
// There is no sudo: an elevated prompt is a separate logon session, and
// starting a process back as the unelevated user needs a token LocNet does not
// hold. In practice this matters less — mstsc and ssh both work fine from an
// elevated prompt, they just inherit its privileges.
func deescalate(*exec.Cmd) {}

// InvokingUser is the person who ran the command, used to pick an SSH
// username.
func InvokingUser() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	// Windows reports DOMAIN\user; SSH wants just the account name.
	if i := strings.LastIndex(u.Username, `\`); i >= 0 {
		return u.Username[i+1:]
	}
	return u.Username
}
