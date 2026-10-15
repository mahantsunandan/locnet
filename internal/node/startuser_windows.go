package node

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// runCommand starts the job, puts it in its process group, and waits.
//
// A job that runs as another account cannot be started by os/exec, for one
// reason: exec gives the child locnetd's own window station and desktop — the
// hidden one SYSTEM's services share — and the account has no access to it.
// Every program then dies while loading user32 with 0xC0000142
// (STATUS_DLL_INIT_FAILED), before it runs a line. That is what the first job
// run as an ordinary account on Windows did, `whoami` included.
//
// The fix Windows provides is an empty desktop name, which exec has no field
// for: the process is then given a window station of its own, named after its
// logon session and open only to that session. So that one path makes the
// CreateProcessAsUser call itself, and gains something on the way: the process
// is created suspended and joins the job object before its first instruction,
// so nothing it starts can slip out of the group.
func runCommand(ctx context.Context, cmd *exec.Cmd, attach func()) error {
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Token == 0 {
		if err := cmd.Start(); err != nil {
			return err
		}
		attach()
		return cmd.Wait()
	}
	return runAsUser(ctx, cmd, attach)
}

func runAsUser(ctx context.Context, cmd *exec.Cmd, attach func()) error {
	app, err := findExecutable(cmd.Args[0], cmd.Env)
	if err != nil {
		return err
	}

	// Pipes for the output, and NUL for input, as exec does. Only the
	// child's ends are inheritable, and the handle list below confines the
	// inheritance to exactly these three, so no other handle locnetd holds
	// leaks into a peer's job.
	outR, outW, err := os.Pipe()
	if err != nil {
		return err
	}
	defer outR.Close()
	errR, errW, err := os.Pipe()
	if err != nil {
		outW.Close()
		return err
	}
	defer errR.Close()
	nul, err := os.Open(os.DevNull)
	if err != nil {
		outW.Close()
		errW.Close()
		return err
	}
	child := []windows.Handle{windows.Handle(nul.Fd()), windows.Handle(outW.Fd()), windows.Handle(errW.Fd())}
	closeChildEnds := func() { nul.Close(); outW.Close(); errW.Close() }
	for _, h := range child {
		if err := windows.SetHandleInformation(h, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
			closeChildEnds()
			return err
		}
	}

	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		closeChildEnds()
		return err
	}
	defer attrs.Delete()
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
		unsafe.Pointer(&child[0]), uintptr(len(child))*unsafe.Sizeof(child[0])); err != nil {
		closeChildEnds()
		return err
	}

	emptyDesktop := []uint16{0}
	si := windows.StartupInfoEx{
		StartupInfo: windows.StartupInfo{
			Flags:     windows.STARTF_USESTDHANDLES,
			Desktop:   &emptyDesktop[0],
			StdInput:  child[0],
			StdOutput: child[1],
			StdErr:    child[2],
		},
		ProcThreadAttributeList: attrs.List(),
	}
	si.Cb = uint32(unsafe.Sizeof(si))

	appPtr, err := windows.UTF16PtrFromString(app)
	if err != nil {
		closeChildEnds()
		return err
	}
	line, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(cmd.Args))
	if err != nil {
		closeChildEnds()
		return err
	}
	dirPtr, err := windows.UTF16PtrFromString(cmd.Dir)
	if err != nil {
		closeChildEnds()
		return err
	}
	env, err := environmentBlock(cmd.Env)
	if err != nil {
		closeChildEnds()
		return err
	}

	var pi windows.ProcessInformation
	err = windows.CreateProcessAsUser(windows.Token(cmd.SysProcAttr.Token), appPtr, line, nil, nil, true,
		windows.CREATE_UNICODE_ENVIRONMENT|windows.EXTENDED_STARTUPINFO_PRESENT|
			windows.CREATE_SUSPENDED|windows.CREATE_NO_WINDOW,
		&env[0], dirPtr, &si.StartupInfo, &pi)
	closeChildEnds() // the child has its copies; ours would keep the pipes open
	if err != nil {
		return fmt.Errorf("starting %s: %w", cmd.Args[0], err)
	}

	proc, err := os.FindProcess(int(pi.ProcessId))
	if err != nil {
		windows.TerminateProcess(pi.Process, 1)
		windows.CloseHandle(pi.Thread)
		windows.CloseHandle(pi.Process)
		return err
	}
	// os.Process holds its own handle now, so the pid cannot be reused
	// under us once ours is closed.
	windows.CloseHandle(pi.Process)
	cmd.Process = proc // killWholeGroup's Cancel reads it

	attach()
	windows.ResumeThread(pi.Thread)
	windows.CloseHandle(pi.Thread)

	var copies sync.WaitGroup
	copyOut := func(w io.Writer, r *os.File) {
		defer copies.Done()
		if w == nil {
			w = io.Discard
		}
		io.Copy(w, r)
	}
	copies.Add(2)
	go copyOut(cmd.Stdout, outR)
	go copyOut(cmd.Stderr, errR)

	type exit struct {
		state *os.ProcessState
		err   error
	}
	done := make(chan exit, 1)
	go func() {
		st, err := proc.Wait()
		done <- exit{st, err}
	}()

	var res exit
	select {
	case res = <-done:
	case <-ctx.Done():
		if cmd.Cancel != nil {
			cmd.Cancel()
		} else {
			proc.Kill()
		}
		res = <-done
	}

	// As exec's WaitDelay: output still arriving from something the job left
	// running is collected for a moment, then abandoned.
	copied := make(chan struct{})
	go func() { copies.Wait(); close(copied) }()
	select {
	case <-copied:
	case <-time.After(cmd.WaitDelay):
		outR.Close()
		errR.Close()
		<-copied
	}

	if res.err != nil {
		return res.err
	}
	cmd.ProcessState = res.state
	if !res.state.Success() {
		return &exec.ExitError{ProcessState: res.state}
	}
	return nil
}

// findExecutable resolves a command the way the account's own shell would:
// through its PATH and PATHEXT, not locnetd's. exec.Command already searched
// SYSTEM's PATH, which does not have a per-user Python or anything else
// installed for that account alone.
func findExecutable(name string, env []string) (string, error) {
	lookup := func(key string) string {
		for _, kv := range env {
			if k, v, ok := strings.Cut(kv, "="); ok && strings.EqualFold(k, key) {
				return v
			}
		}
		return ""
	}
	exts := []string{""}
	if filepath.Ext(name) == "" {
		pathext := lookup("PATHEXT")
		if pathext == "" {
			pathext = ".COM;.EXE;.BAT;.CMD"
		}
		exts = strings.Split(strings.ToLower(pathext), ";")
	}
	try := func(base string) (string, bool) {
		for _, ext := range exts {
			p := base + ext
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				return p, true
			}
		}
		return "", false
	}
	if strings.ContainsAny(name, `\/:`) {
		if p, ok := try(name); ok {
			return p, nil
		}
		return "", fmt.Errorf("%s: no such program", name)
	}
	for _, dir := range filepath.SplitList(lookup("PATH")) {
		if dir == "" {
			continue
		}
		if p, ok := try(filepath.Join(dir, name)); ok {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s: not found in the account's PATH", name)
}

// environmentBlock is the NUL-separated, double-NUL-terminated UTF-16 form
// CreateProcess takes.
func environmentBlock(env []string) ([]uint16, error) {
	var block []uint16
	for _, kv := range env {
		u, err := windows.UTF16FromString(kv)
		if err != nil {
			return nil, errors.New("environment variable contains a NUL")
		}
		block = append(block, u...)
	}
	if len(block) == 0 {
		block = append(block, 0)
	}
	return append(block, 0), nil
}
