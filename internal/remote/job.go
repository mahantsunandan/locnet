package remote

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
)

// Job is work sent to another machine: some files, a command, and the results
// brought back.
//
// This is the piece that makes "run it on the powerful machine" a single
// action rather than four. Without it the sequence is scp, ssh, wait, scp
// back, remember to delete the scratch directory — and people do it twice and
// then go back to running things locally.
type Job struct {
	// Dir is the local folder to send. Its *contents* are copied, so the
	// remote command sees the same relative paths it would see at home.
	Dir string
	// Command runs on the far machine, in the copy of Dir. It goes to the
	// login shell, so pipes and redirection work.
	Command string
	// Env is extra environment for the command, as KEY=VALUE.
	Env []string
	// Exclude are rsync patterns not to send: build output, .git, data.
	Exclude []string
	// Back, when true, copies the working directory back afterwards, so
	// files the job wrote appear locally.
	Back bool
	// Keep leaves the remote scratch directory in place. Useful when a job
	// failed and you want to look at what it left.
	Keep bool
}

// JobRun is what happened.
type JobRun struct {
	Target    string
	RemoteDir string
	ExitCode  int
	Err       string
	Secs      float64
}

// remoteRoot is where job directories live on the far machine. Under the
// login's home rather than /tmp: /tmp is often small, often a tmpfs sized to
// RAM, and cleared on reboot halfway through a long run.
const remoteRoot = ".locnet/jobs"

// RunJob stages, runs and collects. Output is streamed to emit as it happens,
// because a job worth sending to another machine is a job worth watching.
func RunJob(ctx context.Context, t Target, j Job, emit Emit) JobRun {
	start := time.Now()
	out := JobRun{Target: t.Name}
	if emit == nil {
		emit = func(string, string) {}
	}

	if strings.TrimSpace(j.Command) == "" {
		out.Err = "no command given"
		return out
	}
	local := j.Dir
	if local == "" {
		local = "."
	}
	abs, err := filepath.Abs(local)
	if err != nil {
		out.Err = err.Error()
		return out
	}
	if st, err := os.Stat(abs); err != nil || !st.IsDir() {
		out.Err = fmt.Sprintf("%s is not a folder", local)
		return out
	}

	// A name that says where it came from, so someone looking at the far
	// machine's disk months later can tell what left it there.
	remoteDir := fmt.Sprintf("%s/%s-%d", remoteRoot, sanitise(filepath.Base(abs)), time.Now().Unix())
	out.RemoteDir = remoteDir

	// ---- stage ----
	emit(t.Name, fmt.Sprintf("staging %s → ~/%s", local, remoteDir))
	if err := stage(ctx, t, abs, remoteDir, j.Exclude, emit); err != nil {
		out.Err = err.Error()
		out.Secs = time.Since(start).Seconds()
		return out
	}

	// ---- run ----
	emit(t.Name, "$ "+j.Command)
	var script string
	if t.windows() {
		script = windowsJobScript(remoteDir, j.Command, j.Env)
	} else {
		script = fmt.Sprintf("cd ~/%s && %s", shQuote(remoteDir), j.Command)
		if len(j.Env) > 0 {
			var sets []string
			for _, e := range j.Env {
				if k, v, ok := strings.Cut(e, "="); ok {
					sets = append(sets, fmt.Sprintf("export %s=%s", k, shQuote(v)))
				}
			}
			script = strings.Join(sets, "; ") + "; " + script
		}
	}

	// -tt forces a pty, so a program that line-buffers when it thinks it is
	// writing to a file — which is most of them, including Julia and Python
	// — still streams its output instead of delivering it all at the end.
	//
	// Not on Windows, though: there a pty means ConPTY, which repaints the
	// session as a console and drops both the program's output and its exit
	// status — a failing job came back "finished", with nothing printed.
	res := fan(ctx, []Target{t}, emit, func(t Target) (*exec.Cmd, error) {
		args := sshOpts(10)
		if !t.windows() {
			args = append(args, "-tt")
		}
		args = append(args, t.dest(), script)
		return lookCommand("ssh", args)
	})[0]
	out.ExitCode = res.Code
	if !res.OK {
		out.Err = res.Error
	}

	// ---- collect ----
	// Results come back even when the command failed. A failed run's output
	// files are often exactly what you need to see why.
	if j.Back {
		emit(t.Name, "collecting results")
		if err := collect(ctx, t, remoteDir, abs, emit); err != nil {
			emit(t.Name, "could not collect results: "+err.Error())
		}
	}
	if !j.Keep {
		cleanup(ctx, t, remoteDir)
	}

	out.Secs = time.Since(start).Seconds()
	return out
}

// stage copies the working directory over, preferring rsync.
//
// rsync matters more here than anywhere else in LocNet: re-running a job after
// changing one file should send one file, not the whole tree again. scp is the
// fallback because rsync is not installed everywhere, and a slow copy beats a
// failure.
func stage(ctx context.Context, t Target, localDir, remoteDir string, exclude []string, emit Emit) error {
	if useRsync(t) {
		args := []string{"-az", "--delete", "-e", "ssh " + strings.Join(sshOpts(10), " ")}
		for _, x := range exclude {
			args = append(args, "--exclude", x)
		}
		// Trailing slash on the source: copy the contents, not the folder.
		args = append(args, localDir+"/", t.dest()+":"+remoteDir+"/")
		return runOne(ctx, t, "rsync", args, emit)
	}

	// scp cannot create intermediate directories, so make them first.
	mkdir := "mkdir -p " + shQuote(remoteDir)
	if t.windows() {
		mkdir = powershellCommand(fmt.Sprintf(
			`New-Item -ItemType Directory -Force -Path (Join-Path $HOME %s) | Out-Null`, psQuote(remoteDir)))
	}
	mk := append(sshOpts(10), t.dest(), mkdir)
	if err := runOne(ctx, t, "ssh", mk, emit); err != nil {
		return err
	}
	args := append([]string{"-r", "-p", "-B"}, sshOpts(10)...)
	args = append(args, localDir+"/.", t.dest()+":"+remotePath(t, remoteDir)+"/")
	return runOne(ctx, t, "scp", args, emit)
}

func collect(ctx context.Context, t Target, remoteDir, localDir string, emit Emit) error {
	if useRsync(t) {
		args := []string{"-az", "-e", "ssh " + strings.Join(sshOpts(10), " "),
			t.dest() + ":" + remoteDir + "/", localDir + "/"}
		return runOne(ctx, t, "rsync", args, emit)
	}
	args := append([]string{"-r", "-p", "-B"}, sshOpts(10)...)
	args = append(args, t.dest()+":"+remotePath(t, remoteDir)+"/.", localDir+"/")
	return runOne(ctx, t, "scp", args, emit)
}

// windowsJobScript is the run step for a Windows machine.
//
// The command goes to PowerShell, which is what someone writing a command
// for a Windows machine expects, whatever shell its sshd hands out. The exit
// status is passed through explicitly: PowerShell 5 ends with 0 after a
// failing native program unless told otherwise, and a job that fails has to
// say so. (When the far sshd's shell is PowerShell, that outer shell reports
// any failure as 1; the code itself survives only under cmd.)
func windowsJobScript(remoteDir, command string, env []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Set-Location -LiteralPath (Join-Path $HOME %s) -ErrorAction Stop\n", psQuote(remoteDir))
	for _, e := range env {
		if k, v, ok := strings.Cut(e, "="); ok {
			fmt.Fprintf(&b, "${env:%s} = %s\n", strings.ReplaceAll(k, "}", ""), psQuote(v))
		}
	}
	b.WriteString(command + "\n")
	b.WriteString("if (-not $?) { if ($LASTEXITCODE) { exit $LASTEXITCODE }; exit 1 }\nexit 0\n")
	return powershellCommand(b.String())
}

// powershellCommand turns a script into one command line that runs the same
// whether the far sshd starts cmd.exe or PowerShell. -EncodedCommand is
// base64 of UTF-16LE, so no character in the script needs quoting for
// either of them.
//
// Progress records are switched off first. With no console to draw them on,
// PowerShell serialises them to stderr as CLIXML, and the first command of a
// session reports "Preparing modules for first use" that way.
func powershellCommand(script string) string {
	script = "$ProgressPreference = 'SilentlyContinue'\n" + script
	u := utf16.Encode([]rune(script))
	raw := make([]byte, 2*len(u))
	for i, c := range u {
		raw[2*i], raw[2*i+1] = byte(c), byte(c>>8)
	}
	return "powershell -NoProfile -NonInteractive -EncodedCommand " + base64.StdEncoding.EncodeToString(raw)
}

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// cleanup removes the scratch directory. Best-effort and deliberately quiet:
// a machine that has gone away is not a reason to report the job as failed,
// and the path is under ~/.locnet/jobs where it is obvious what it was.
func cleanup(ctx context.Context, t Target, remoteDir string) {
	c, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	// The guard on the path is not paranoia about our own code; it is
	// insurance against a future edit making remoteDir empty and turning
	// this into `rm -rf ~/`.
	if !strings.HasPrefix(remoteDir, remoteRoot+"/") || strings.Contains(remoteDir, "..") {
		return
	}
	rm := "rm -rf " + shQuote(remoteDir)
	if t.windows() {
		rm = powershellCommand(fmt.Sprintf(
			`Remove-Item -LiteralPath (Join-Path $HOME %s) -Recurse -Force`, psQuote(remoteDir)))
	}
	args := append(sshOpts(5), "-n", t.dest(), rm)
	cmd, err := lookCommand("ssh", args)
	if err != nil {
		return
	}
	_ = fanOne(c, t, cmd)
}

func runOne(ctx context.Context, t Target, bin string, args []string, emit Emit) error {
	res := fan(ctx, []Target{t}, emit, func(Target) (*exec.Cmd, error) {
		return lookCommand(bin, args)
	})[0]
	if !res.OK {
		return fmt.Errorf("%s: %s", bin, res.Error)
	}
	return nil
}

func fanOne(ctx context.Context, t Target, cmd *exec.Cmd) error {
	return fan(ctx, []Target{t}, nil, func(Target) (*exec.Cmd, error) { return cmd, nil })[0].err()
}

func (r Result) err() error {
	if r.OK {
		return nil
	}
	return fmt.Errorf("%s", r.Error)
}

// shQuote wraps a string for the remote shell.
func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// sanitise reduces a folder name to something safe in a path.
func sanitise(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "job"
	}
	return out
}
