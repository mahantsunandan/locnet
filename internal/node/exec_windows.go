package node

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"

	"github.com/mahantsunandan/locnet/internal/resource"
)

// applyCredentials makes the job run as the configured local account.
//
// The token comes from an S4U logon (s4u_windows.go), so LocNet never holds the
// account's password. The job gets that account's own environment and, unless
// a directory was configured, starts in its profile folder — the Windows
// equivalent of the Unix path dropping to the user and starting in $HOME.
//
// With no account named, the job runs as locnetd itself, which is SYSTEM, and
// only if the operator said so with -allow-privileged.
//
// The returned function releases the token and profile once the job is over.
func applyCredentials(cmd *exec.Cmd, cfg resource.ComputeConfig) (func(), error) {
	if cfg.RunAs == "" {
		if !cfg.AllowPrivileged {
			// Validate should have caught this. Refusing here too means a
			// hand-edited state file cannot quietly widen the permission.
			return nil, fmt.Errorf("compute is misconfigured: no user to run as, and privileged execution was not allowed")
		}
		return func() {}, nil
	}

	user, _, err := localAccount(cfg.RunAs)
	if err != nil {
		return nil, err
	}
	token, err := userToken(cfg.RunAs)
	if err != nil {
		return nil, err
	}
	// An administrator runs with the token UAC gives them at the desktop,
	// not an elevated one — the equivalent of a Unix sudoer's job running
	// without sudo. -allow-privileged keeps the elevated token.
	if !cfg.AllowPrivileged {
		if token, err = unelevated(token); err != nil {
			return nil, fmt.Errorf("%s is an administrator here and %v, so the job was not run; "+
				"pass -allow-privileged to run it elevated", user, err)
		}
	}
	unload, err := loadUserProfile(token, user)
	if err != nil {
		token.Close()
		return nil, fmt.Errorf("loading %s's profile: %w", user, err)
	}
	release := func() { unload(); token.Close() }

	env, err := token.Environ(false)
	if err != nil {
		release()
		return nil, fmt.Errorf("building %s's environment: %w", user, err)
	}
	// The user's own environment, plus what LocNet tells every job. HOME is
	// left out: on Windows it is not the profile folder, and tools that read
	// it (git, ssh) would be pointed at the job's working directory instead.
	for _, kv := range cmd.Env {
		if strings.HasPrefix(kv, "LOCNET_") {
			env = append(env, kv)
		}
	}
	cmd.Env = env

	// SYSTEM's temporary folder is where a job lands with no directory
	// configured, and an ordinary account cannot even open it.
	if cmd.Dir == "" || strings.EqualFold(cmd.Dir, os.TempDir()) {
		if dir, err := token.GetUserProfileDirectory(); err == nil {
			cmd.Dir = dir
		}
	}

	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Token = syscall.Token(token)
	return release, nil
}

func defaultPath() string {
	if p := os.Getenv("PATH"); p != "" {
		return p
	}
	return `C:\Windows\system32;C:\Windows`
}

// killWholeGroup makes a cancelled or timed-out job take its children with it,
// as a process group does on Unix. Windows has no process groups; a job object
// is the equivalent, and terminating it ends every process inside.
//
// A process can only join a job once it exists, so attach runs right after
// Start. Anything the job starts after that is in the job too. (In the moment
// between the two the process is still initialising and has started nothing.)
// release closes the handle; it does not kill what is still running, matching
// Unix, where a finished job's leftovers are not touched either.
func killWholeGroup(cmd *exec.Cmd) (attach, release func()) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		// Killing the one process is still what exec does by default.
		return func() {}, func() {}
	}
	cmd.Cancel = func() error {
		windows.TerminateJobObject(job, 1)
		// In case the process never made it into the job.
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return nil
	}
	attach = func() {
		h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE,
			false, uint32(cmd.Process.Pid))
		if err != nil {
			return
		}
		windows.AssignProcessToJobObject(job, h)
		windows.CloseHandle(h)
	}
	return attach, func() { windows.CloseHandle(job) }
}
