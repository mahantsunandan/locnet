//go:build !windows

package remote

import (
	"os/exec"
	"syscall"
)

// setGroup puts the command in its own process group.
//
// Cancelling a transfer means stopping it, and killing only the process we
// started does not do that: scp forks an ssh of its own, and killing the
// parent leaves that ssh copying happily to a machine the user just told
// LocNet to leave alone. Worse, the pipe it inherited stays open, so the wait
// never returns and the cancel appears to hang.
//
// A process group makes the whole tree killable in one signal.
func setGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	// Deescalate may already have set Credential on this struct; only the
	// group field is touched here.
	cmd.SysProcAttr.Setpgid = true
}

// killGroup stops the command and everything it started.
func killGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	// Negative pid means "the group whose leader is this pid". If the group
	// was never created — setGroup is best-effort — fall back to the one
	// process, which is still better than nothing.
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
		cmd.Process.Kill()
	}
}
