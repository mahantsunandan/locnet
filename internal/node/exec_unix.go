//go:build !windows

package node

import (
	"context"
	"fmt"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"

	"github.com/mahantsunandan/locnet/internal/resource"
)

// applyCredentials makes the job run as the configured user.
//
// locnetd runs as root because it owns a network interface. Running a peer's
// command with that inheritance would hand every allowed peer root, so unless
// the operator has explicitly asked for exactly that, the process drops to a
// named account before exec. There is nothing to release afterwards.
func applyCredentials(cmd *exec.Cmd, cfg resource.ComputeConfig) (func(), error) {
	if cfg.RunAs == "" {
		if !cfg.AllowPrivileged {
			// Validate should have caught this. Refusing here too means a
			// hand-edited state file cannot quietly widen the permission.
			return nil, fmt.Errorf("compute is misconfigured: no user to run as, and privileged execution was not allowed")
		}
		return func() {}, nil
	}

	u, err := user.Lookup(cfg.RunAs)
	if err != nil {
		return nil, fmt.Errorf("no such user %q on this machine", cfg.RunAs)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("user %q has an unusable uid %q", cfg.RunAs, u.Uid)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("user %q has an unusable gid %q", cfg.RunAs, u.Gid)
	}
	if uid == 0 && !cfg.AllowPrivileged {
		return nil, fmt.Errorf("user %q is root; enable compute with -allow-privileged if that is intended", cfg.RunAs)
	}

	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Credential = &syscall.Credential{
		Uid: uint32(uid),
		Gid: uint32(gid),
		// Drop every supplementary group rather than inheriting root's.
		// NoSetGroups would leave the job in root's groups, which is most of
		// the privilege we just gave up.
		Groups: []uint32{uint32(gid)},
	}
	if cmd.Dir == "" || cmd.Dir == "/" {
		cmd.Dir = u.HomeDir
	}
	return func() {}, nil
}

// killWholeGroup makes a cancelled or timed-out job take its children with it.
//
// A process group alone does not do that. exec.CommandContext kills the one
// process it started, so a job that was a shell script running a long helper
// lost the shell at its deadline and kept the helper — still holding the
// machine, and still holding the output pipe, which left the wait for the
// job's result hanging until the helper chose to finish. Signalling the
// negative pid reaches the whole group. The group exists from the fork, so
// there is nothing to attach after Start and nothing to release.
func killWholeGroup(cmd *exec.Cmd) (attach, release func()) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	return func() {}, func() {}
}

func defaultPath() string { return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" }

// runCommand starts the job, puts it in its process group, and waits. On
// Unix the group already exists from the fork, so attach has nothing to do.
func runCommand(_ context.Context, cmd *exec.Cmd, attach func()) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	attach()
	return cmd.Wait()
}
