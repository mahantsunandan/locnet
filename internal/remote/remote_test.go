package remote

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// shim puts fake ssh/scp binaries on PATH so the fan-out can be exercised
// without a second machine. What is under test is this package — argument
// construction, concurrency, output capture and the way failures are
// explained — not OpenSSH.
func shim(t *testing.T, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell shims are not portable to Windows")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	// rsync too: Copy and Fetch prefer it when it is installed, and a test
	// machine that happens to have it would otherwise run the real thing.
	for _, name := range []string{"ssh", "scp", "rsync"} {
		body := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + log + "\n" + script + "\n"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

func calls(t *testing.T, log string) []string {
	t.Helper()
	raw, err := os.ReadFile(log)
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(raw), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	sort.Strings(out)
	return out
}

func TestExecRunsOnEveryTarget(t *testing.T) {
	log := shim(t, `echo "ran on $*"`)

	targets := []Target{
		{Name: "alpha", Host: "10.99.0.1", Login: "username"},
		{Name: "beta", Host: "10.99.0.2"},
		{Name: "gamma", Host: "10.99.0.3", Login: "ops"},
	}
	res := Exec(context.Background(), targets, "uptime", nil)

	if len(res) != 3 {
		t.Fatalf("got %d results, want 3", len(res))
	}
	for _, r := range res {
		if !r.OK {
			t.Errorf("%s failed: %s", r.Target, r.Error)
		}
	}

	got := calls(t, log)
	if len(got) != 3 {
		t.Fatalf("ssh was called %d times, want 3:\n%s", len(got), strings.Join(got, "\n"))
	}
	joined := strings.Join(got, "\n")
	// The login must be folded into the destination, not dropped: connecting
	// as the wrong account is the failure this whole path exists to avoid.
	for _, want := range []string{"username@10.99.0.1", "10.99.0.2", "ops@10.99.0.3", "BatchMode=yes"} {
		if !strings.Contains(joined, want) {
			t.Errorf("ssh was never called with %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "@10.99.0.2") {
		t.Errorf("a target with no remembered login must not get an @ prefix:\n%s", joined)
	}
}

func TestCopySendsEverySourceAndQuotesTheDestination(t *testing.T) {
	log := shim(t, `exit 0`)

	res := Copy(context.Background(),
		[]Target{{Name: "alpha", Host: "10.99.0.1", Login: "me"}},
		[]string{"/tmp/report.pdf", "/tmp/notes"}, "/srv/incoming dir", nil)

	if len(res) != 1 || !res[0].OK {
		t.Fatalf("copy failed: %+v", res)
	}
	got := strings.Join(calls(t, log), "\n")
	for _, want := range []string{"/tmp/report.pdf", "/tmp/notes", "me@10.99.0.1:"} {
		if !strings.Contains(got, want) {
			t.Errorf("the transfer was not called with %q: %s", want, got)
		}
	}
	// A destination with a space must survive the remote shell, or the copy
	// silently lands in two wrong places. rsync needs --protect-args for
	// that; scp needs the path quoted.
	quoted := strings.Contains(got, `'/srv/incoming dir'`)
	protected := strings.Contains(got, "--protect-args") && strings.Contains(got, "/srv/incoming dir")
	if !quoted && !protected {
		t.Errorf("a destination with a space was left for the remote shell to split: %s", got)
	}
}

func TestFetchGivesEachMachineItsOwnFolder(t *testing.T) {
	log := shim(t, `exit 0`)

	Fetch(context.Background(), []Target{
		{Name: "alpha", Host: "10.99.0.1"},
		{Name: "beta", Host: "10.99.0.2"},
	}, "/var/log/syslog", "/tmp/collected", nil)

	got := strings.Join(calls(t, log), "\n")
	// Both machines have a file called syslog. Landing them in one directory
	// would leave one file and one silent overwrite.
	for _, want := range []string{"/tmp/collected/alpha", "/tmp/collected/beta"} {
		if !strings.Contains(got, want) {
			t.Errorf("fetch did not separate per machine, missing %q: %s", want, got)
		}
	}
}

func TestFailureIsExplainedRatherThanNumbered(t *testing.T) {
	shim(t, `echo "Permission denied (publickey)." >&2; exit 255`)

	res := Exec(context.Background(), []Target{{Name: "alpha", Host: "10.99.0.1"}}, "uptime", nil)
	if len(res) != 1 || res[0].OK {
		t.Fatalf("expected a failure, got %+v", res)
	}
	// "exit status 255" tells nobody anything. The point of explain() is that
	// the message names the fix.
	if !strings.Contains(res[0].Error, "locnet ssh-key") {
		t.Errorf("a rejected key should point at ssh-key, got %q", res[0].Error)
	}
	if res[0].Code != 255 {
		t.Errorf("exit code = %d, want 255", res[0].Code)
	}
}

func TestOrdinaryExitCodeIsReportedAsIs(t *testing.T) {
	shim(t, `echo "no such file"; exit 3`)

	res := Exec(context.Background(), []Target{{Name: "alpha", Host: "10.99.0.1"}}, "cat missing", nil)
	if res[0].OK || res[0].Code != 3 {
		t.Fatalf("want a clean exit-3 failure, got %+v", res[0])
	}
	if !strings.Contains(res[0].Output, "no such file") {
		t.Errorf("output was not captured: %q", res[0].Output)
	}
}

func TestOutputIsTaggedWithTheMachineItCameFrom(t *testing.T) {
	shim(t, `echo "line for $6"`)

	var mu sync.Mutex
	seen := map[string]int{}
	Exec(context.Background(), []Target{
		{Name: "alpha", Host: "10.99.0.1"},
		{Name: "beta", Host: "10.99.0.2"},
	}, "echo", func(target, line string) {
		mu.Lock()
		defer mu.Unlock()
		seen[target]++
	})

	if seen["alpha"] == 0 || seen["beta"] == 0 {
		t.Errorf("output was not attributed per machine: %v", seen)
	}
}

func TestTargetsRunConcurrently(t *testing.T) {
	shim(t, `sleep 1`)

	targets := make([]Target, 6)
	for i := range targets {
		targets[i] = Target{Name: string(rune('a' + i)), Host: "10.99.0.1"}
	}

	start := time.Now()
	Exec(context.Background(), targets, "sleep", nil)
	elapsed := time.Since(start)

	// Six one-second commands in series take six seconds. The whole reason
	// this package exists is that they should not.
	if elapsed > 3*time.Second {
		t.Errorf("six targets took %v — they ran in series", elapsed)
	}
}

func TestCancelStopsTheRunAndKeepsWhatWasCollected(t *testing.T) {
	shim(t, `echo started; sleep 30`)

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(300 * time.Millisecond); cancel() }()

	start := time.Now()
	res := Exec(ctx, []Target{{Name: "alpha", Host: "10.99.0.1"}}, "sleep 30", nil)
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("cancel did not stop the command: took %v", d)
	}
	if res[0].OK {
		t.Error("a cancelled run should not report success")
	}
	// Cancellation must not throw away the output already produced — that
	// output is often why the run was cancelled.
	if !strings.Contains(res[0].Output, "started") {
		t.Errorf("output collected before the cancel was lost: %q", res[0].Output)
	}
}

func TestEmptyInputsFailWithoutTouchingTheNetwork(t *testing.T) {
	log := shim(t, `exit 0`)
	targets := []Target{{Name: "alpha", Host: "10.99.0.1"}}

	if res := Exec(context.Background(), targets, "   ", nil); res[0].OK {
		t.Error("an empty command should not run")
	}
	if res := Copy(context.Background(), targets, []string{"", "  "}, "/tmp", nil); res[0].OK {
		t.Error("an empty source list should not run")
	}
	if got := calls(t, log); len(got) != 0 {
		t.Errorf("nothing should have been executed, got %v", got)
	}
}

func TestSummariseNamesTheFailures(t *testing.T) {
	got := Summarise([]Result{
		{Target: "alpha", OK: true},
		{Target: "beta"},
		{Target: "gamma"},
	})
	if !strings.Contains(got, "beta") || !strings.Contains(got, "gamma") {
		t.Errorf("summary should name what failed, got %q", got)
	}
	if got := Summarise([]Result{{Target: "alpha", OK: true}}); !strings.Contains(got, "all 1") {
		t.Errorf("clean run summary = %q", got)
	}
}
