// Package remote runs commands and copies files to several peers at once over
// SSH.
//
// LocNet does not implement its own file-transfer or remote-shell protocol
// here, and that is deliberate. Once the mesh has made a peer reachable, the
// machine already has ssh and scp, which have working authentication, host-key
// checking, compression and resumption. Reimplementing that would take months
// and be worse. What LocNet adds is the part that was actually missing: doing
// it to twenty machines at once, and knowing which twenty.
//
// Everything here runs with BatchMode=yes, so a missing key fails immediately
// with an explanation instead of hanging on a password prompt nobody can see.
// The console is a web page; there is no terminal to type a password into.
// `locnet ssh-key <peer>` is the fix, and the error says so.
package remote

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mahantsunandan/locnet/internal/launch"
)

// Target is one machine to act on.
type Target struct {
	// Name is the peer name, used in output so a person can tell the
	// machines apart.
	Name string
	// Host is the overlay address to connect to.
	Host string
	// Login is the account on that machine. Empty means ssh's own default,
	// which is the local username.
	Login string
	// OS is the far machine's, as the peer reports it ("windows", "linux",
	// "darwin"). Empty is treated as Unix.
	OS string
}

// windows reports whether the far machine is Windows, where there is no
// rsync and no POSIX shell behind ssh — cmd or PowerShell instead, depending
// on how its sshd is configured.
func (t Target) windows() bool { return t.OS == "windows" }

// useRsync reports whether to copy with rsync. It needs rsync at both ends,
// and nothing installs it on Windows; asking for it there fails with "connection
// unexpectedly closed", which says nothing about the cause.
func useRsync(t Target) bool {
	if t.windows() {
		return false
	}
	_, err := exec.LookPath("rsync")
	return err == nil
}

// remotePath renders a path for scp's remote side. Single quotes guard a Unix
// path against the far shell; on Windows they would become part of the name.
func remotePath(t Target, p string) string {
	if t.windows() {
		if p == "" {
			return "."
		}
		return p
	}
	return quoteRemote(p)
}

func (t Target) dest() string {
	if t.Login == "" {
		return t.Host
	}
	return t.Login + "@" + t.Host
}

// Result is what happened on one machine.
type Result struct {
	Target string  `json:"target"`
	OK     bool    `json:"ok"`
	Error  string  `json:"error,omitempty"`
	Output string  `json:"output,omitempty"`
	Code   int     `json:"exit_code"`
	Secs   float64 `json:"seconds"`
}

// Emit receives output as it arrives, tagged with the machine it came from.
// Interleaving from several machines is expected — that is why the tag is
// there. A nil Emit is allowed; output is still collected into the Result.
type Emit func(target, line string)

// sshOpts are shared by ssh and scp.
//
// BatchMode is the important one: see the package comment. accept-new records
// a host key the first time but still refuses a *changed* one, which is the
// protection that matters and the only setting that works unattended.
func sshOpts(connectTimeout int) []string {
	return []string{
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", fmt.Sprintf("ConnectTimeout=%d", connectTimeout),
		"-o", "ServerAliveInterval=15",
	}
}

// Exec runs one command on every target, concurrently.
//
// The command is handed to the remote login shell as written, exactly as
// `ssh host "..."` would. That is different from LocNet's own `run`, which is
// shell-free by design: here the user has an account on the far machine and
// full shell access to it already, so pretending otherwise buys nothing.
func Exec(ctx context.Context, targets []Target, command string, emit Emit) []Result {
	command = strings.TrimSpace(command)
	if command == "" {
		return failAll(targets, "no command given")
	}
	return fan(ctx, targets, emit, func(t Target) (*exec.Cmd, error) {
		args := append(sshOpts(10), "-n", t.dest(), command)
		return lookCommand("ssh", args)
	})
}

// Copy sends files and folders to every target, concurrently.
//
// Directories are copied whole. dest is a path on the far machine; an empty
// dest means the login's home directory, which is what someone means by
// "send this to that computer" nine times out of ten.
func Copy(ctx context.Context, targets []Target, sources []string, dest string, emit Emit) []Result {
	sources = cleanList(sources)
	if len(sources) == 0 {
		return failAll(targets, "nothing selected to send")
	}
	if dest == "" {
		dest = "."
	}
	return fan(ctx, targets, emit, func(t Target) (*exec.Cmd, error) {
		// rsync when it is there: it reports progress as a percentage, which
		// is what lets the console draw a bar, and it re-sends only what
		// changed on a repeat. scp can do neither.
		if useRsync(t) {
			args := []string{"-a", "--info=progress2", "--no-inc-recursive",
				"--protect-args", "-e", "ssh " + strings.Join(sshOpts(10), " ")}
			args = append(args, sources...)
			args = append(args, t.dest()+":"+dest)
			return lookCommand("rsync", args)
		}
		// -r for folders, -p to keep timestamps, -B to never prompt.
		args := append([]string{"-r", "-p", "-B"}, sshOpts(10)...)
		args = append(args, sources...)
		args = append(args, t.dest()+":"+remotePath(t, dest))
		return lookCommand("scp", args)
	})
}

// Fetch pulls one remote path from every target into localDir.
//
// Each machine's copy lands in its own subfolder. Collecting the same filename
// from ten machines into one directory would leave one file and nine
// overwrites, which is not what anyone asked for.
func Fetch(ctx context.Context, targets []Target, remoteFile, localDir string, emit Emit) []Result {
	remoteFile = strings.TrimSpace(remoteFile)
	if remoteFile == "" {
		return failAll(targets, "no remote path given")
	}
	return fan(ctx, targets, emit, func(t Target) (*exec.Cmd, error) {
		if useRsync(t) {
			return lookCommand("rsync", []string{"-a", "--info=progress2",
				"--no-inc-recursive", "--protect-args",
				"-e", "ssh " + strings.Join(sshOpts(10), " "),
				t.dest() + ":" + remoteFile, path.Join(localDir, t.Name)})
		}
		args := append([]string{"-r", "-p", "-B"}, sshOpts(10)...)
		args = append(args, t.dest()+":"+remotePath(t, remoteFile),
			path.Join(localDir, t.Name))
		return lookCommand("scp", args)
	})
}

// fan runs build(t) on every target at once and collects the results.
//
// Concurrency is unbounded on purpose: these are network-bound SSH sessions to
// machines on your own mesh, and a mesh large enough for that to matter does
// not exist yet. If one ever does, this is the single place to add a limit.
func fan(ctx context.Context, targets []Target, emit Emit, build func(Target) (*exec.Cmd, error)) []Result {
	if len(targets) == 0 {
		return nil
	}

	var (
		mu  sync.Mutex
		out = make([]Result, len(targets))
		wg  sync.WaitGroup
	)
	if emit == nil {
		emit = func(string, string) {}
	}
	// Serialise callbacks. Callers append to a shared log; making that safe
	// here is cheaper than making every caller think about it.
	safeEmit := func(target, line string) {
		mu.Lock()
		defer mu.Unlock()
		emit(target, line)
	}

	for i, t := range targets {
		wg.Add(1)
		go func(i int, t Target) {
			defer wg.Done()
			out[i] = run1(ctx, t, build, safeEmit)
		}(i, t)
	}
	wg.Wait()
	return out
}

func run1(ctx context.Context, t Target, build func(Target) (*exec.Cmd, error), emit Emit) Result {
	start := time.Now()
	res := Result{Target: t.Name}

	cmd, err := build(t)
	if err != nil {
		res.Error = err.Error()
		res.Secs = time.Since(start).Seconds()
		emit(t.Name, err.Error())
		return res
	}
	launch.Deescalate(cmd)
	setGroup(cmd)

	// Merge stdout and stderr into one stream. scp reports progress on one
	// and errors on the other, and a person watching wants them in order.
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw

	if err := cmd.Start(); err != nil {
		pw.Close()
		pr.Close()
		res.Error = describeStart(cmd.Path, err)
		res.Secs = time.Since(start).Seconds()
		emit(t.Name, res.Error)
		return res
	}

	var lines []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		// rsync redraws its progress line with a carriage return rather than
		// a newline, so splitting on \n alone would deliver the whole
		// transfer as one line at the end — no progress at all.
		sc.Split(scanLinesOrCR)
		for sc.Scan() {
			line := strings.TrimRight(sc.Text(), "\r")
			if line == "" {
				continue
			}
			lines = append(lines, line)
			emit(t.Name, line)
		}
	}()

	// Honour cancellation ourselves rather than using CommandContext, so the
	// output collected before the cancel is still returned.
	waitErr := waitWithCancel(ctx, cmd)
	pw.Close()
	<-done
	pr.Close()

	res.Output = strings.Join(lines, "\n")
	res.Secs = time.Since(start).Seconds()
	if waitErr != nil {
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			res.Code = ee.ExitCode()
			res.Error = explain(res.Code, res.Output)
		} else {
			res.Error = waitErr.Error()
		}
		return res
	}
	res.OK = true
	return res
}

func waitWithCancel(ctx context.Context, cmd *exec.Cmd) error {
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		killGroup(cmd)
		<-done
		return ctx.Err()
	}
}

// scanLinesOrCR splits on \n or \r, so a progress line that is rewritten in
// place still arrives as it happens.
func scanLinesOrCR(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexAny(data, "\r\n"); i >= 0 {
		return i + 1, data[:i], nil
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}

// Percent pulls a completion figure out of a progress line, or -1.
func Percent(line string) int {
	i := strings.IndexByte(line, '%')
	if i <= 0 {
		return -1
	}
	j := i
	for j > 0 && line[j-1] >= '0' && line[j-1] <= '9' {
		j--
	}
	if j == i {
		return -1
	}
	n, err := strconv.Atoi(line[j:i])
	if err != nil || n < 0 || n > 100 {
		return -1
	}
	return n
}

// explain turns an ssh exit code into something worth reading.
//
// 255 is ssh's own "I could not connect or authenticate", and it is by far the
// most common failure here. Left as "exit status 255" it tells a person
// nothing; the fix is almost always a missing key.
func explain(code int, output string) string {
	if code != 255 {
		return fmt.Sprintf("exited %d", code)
	}
	low := strings.ToLower(output)
	switch {
	case strings.Contains(low, "permission denied"),
		strings.Contains(low, "publickey"):
		return "SSH refused the login. Set up a key:  locnet ssh-key <peer>"
	case strings.Contains(low, "host key verification failed"):
		return "the machine's SSH host key changed — check it, then remove the old line from ~/.ssh/known_hosts"
	case strings.Contains(low, "connection refused"):
		return "nothing is listening on port 22 — is the SSH server running there?"
	case strings.Contains(low, "timed out"), strings.Contains(low, "timeout"):
		// A timeout says nothing came back. It does not say the machine was
		// reached — a connection refused would prove that, and this is not
		// one. Claiming otherwise sent people looking at sshd when the
		// tunnel was down, which is the more common cause by far.
		return "no answer on port 22 — the tunnel may be down; check `locnet status` and `locnet doctor`"
	case strings.Contains(low, "no route to host"), strings.Contains(low, "unreachable"):
		return "no route to the machine — check `locnet status`"
	}
	return "SSH could not connect or log in"
}

func describeStart(bin string, err error) string {
	if strings.Contains(err.Error(), "no such file") {
		return fmt.Sprintf("%s is not installed. %s", path.Base(bin), installHint())
	}
	return err.Error()
}

func installHint() string {
	switch runtime.GOOS {
	case "linux":
		return "Install it:  sudo apt install openssh-client   |   sudo dnf install openssh-clients"
	case "windows":
		return "Enable the OpenSSH client: Settings → Apps → Optional Features → OpenSSH Client."
	}
	return ""
}

func lookCommand(bin string, args []string) (*exec.Cmd, error) {
	p, err := exec.LookPath(bin)
	if err != nil {
		return nil, fmt.Errorf("%s is not installed. %s", bin, installHint())
	}
	return exec.Command(p, args...), nil
}

// quoteRemote protects a destination path from the remote shell, which scp
// runs it through. Without this a folder with a space in its name silently
// becomes two arguments.
func quoteRemote(p string) string {
	if p == "" {
		return "."
	}
	return "'" + strings.ReplaceAll(p, "'", `'\''`) + "'"
}

func cleanList(in []string) []string {
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func failAll(targets []Target, msg string) []Result {
	out := make([]Result, 0, len(targets))
	for _, t := range targets {
		out = append(out, Result{Target: t.Name, Error: msg})
	}
	if len(out) == 0 {
		out = append(out, Result{Error: msg})
	}
	return out
}

// Summarise reduces a fan-out to one line, because after sending to twelve
// machines the thing you want to know first is whether any of them failed.
func Summarise(res []Result) string {
	var failed []string
	for _, r := range res {
		if !r.OK {
			failed = append(failed, r.Target)
		}
	}
	if len(failed) == 0 {
		return fmt.Sprintf("all %d succeeded", len(res))
	}
	sort.Strings(failed)
	return fmt.Sprintf("%d of %d failed: %s", len(failed), len(res), strings.Join(failed, ", "))
}
