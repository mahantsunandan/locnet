package node

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/mahantsunandan/locnet/internal/resource"
)

func quiet(string, ...any) {}

// TestComputeIsOffByDefault is the first line of defence: an untouched
// installation runs nobody's code.
func TestComputeIsOffByDefault(t *testing.T) {
	var cfg resource.ComputeConfig
	if cfg.Enabled {
		t.Fatal("the zero value has compute enabled")
	}
	for _, peer := range []string{"alpha", "*", ""} {
		if cfg.AllowsPeer(peer) {
			t.Errorf("a disabled config accepted a job from %q", peer)
		}
	}
}

func TestComputeAccessList(t *testing.T) {
	cfg := resource.ComputeConfig{Enabled: true, Allow: []string{"alpha"}, RunAs: "nobody"}
	if !cfg.AllowsPeer("alpha") {
		t.Error("the allowed peer was refused")
	}
	for _, peer := range []string{"beta", "alph", "ALPHA", ""} {
		if cfg.AllowsPeer(peer) {
			t.Errorf("%q was allowed but is not on the list", peer)
		}
	}

	open := resource.ComputeConfig{Enabled: true, Allow: []string{"*"}, RunAs: "nobody"}
	if !open.AllowsPeer("anyone") {
		t.Error("the wildcard did not match")
	}
}

// TestComputeValidationRefusesFootguns covers the configurations that would
// quietly hand a peer more than the operator meant to give.
func TestComputeValidationRefusesFootguns(t *testing.T) {
	bad := []resource.ComputeConfig{
		{Enabled: true},                       // nobody allowed
		{Enabled: true, Allow: []string{"a"}}, // no user given
		{Enabled: true, Allow: []string{"a"}, RunAs: "x", MaxSeconds: -1},
	}
	// Root without saying so. Windows has no root: an administrator named
	// there runs unelevated, and SYSTEM is refused as not being a user —
	// both decided per job, once the account is actually logged on.
	if runtime.GOOS != "windows" {
		bad = append(bad, resource.ComputeConfig{Enabled: true, Allow: []string{"a"}, RunAs: "root"})
	}
	for i, cfg := range bad {
		if err := cfg.Validate(); err == nil {
			t.Errorf("config %d was accepted: %+v", i, cfg)
		}
	}

	// Disabled configs never need to justify themselves.
	if err := (&resource.ComputeConfig{}).Validate(); err != nil {
		t.Errorf("a disabled config failed validation: %v", err)
	}
	good := resource.ComputeConfig{Enabled: true, Allow: []string{"a"}, RunAs: "nobody"}
	if err := good.Validate(); err != nil {
		t.Errorf("a reasonable config failed validation: %v", err)
	}
	// Root is allowed, but only when asked for in as many words.
	explicit := resource.ComputeConfig{Enabled: true, Allow: []string{"a"}, RunAs: "root", AllowPrivileged: true}
	if err := explicit.Validate(); err != nil {
		t.Errorf("an explicitly privileged config failed validation: %v", err)
	}
}

// TestExecEndpointRefusesUnlistedPeers drives the real HTTP handler.
func TestExecEndpointRefusesUnlistedPeers(t *testing.T) {
	s := newTestServer(t)
	s.setCompute(resource.ComputeConfig{
		Enabled: true, Allow: []string{"alpha"}, AllowPrivileged: true,
	})

	body := `{"command":["true"]}`

	// beta is a member of the network but not on the compute list.
	if w := request(s, http.MethodPost, "/exec", "100.100.0.3", strings.NewReader(body)); w.Code != 404 {
		t.Errorf("beta got %d from /exec, want 404", w.Code)
	}
	// A non-member is refused earlier still.
	if w := request(s, http.MethodPost, "/exec", "100.100.0.9", strings.NewReader(body)); w.Code != 403 {
		t.Errorf("a non-member got %d, want 403", w.Code)
	}

	// With compute off, even the listed peer gets nothing.
	s.setCompute(resource.ComputeConfig{})
	if w := request(s, http.MethodPost, "/exec", "100.100.0.2", strings.NewReader(body)); w.Code != 404 {
		t.Errorf("with compute disabled alpha got %d, want 404", w.Code)
	}
}

func TestExecRunsForAnAllowedPeer(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the shell-free command used here is POSIX")
	}
	s := newTestServer(t)
	s.setCompute(resource.ComputeConfig{
		Enabled: true, Allow: []string{"alpha"}, AllowPrivileged: true, WorkDir: os.TempDir(),
	})

	w := request(s, http.MethodPost, "/exec", "100.100.0.2",
		strings.NewReader(`{"command":["echo","hello from locnet"]}`))
	if w.Code != 200 {
		t.Fatalf("/exec returned %d: %s", w.Code, w.Body.String())
	}
	var res resource.JobResult
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Errorf("exit %d, stderr %q", res.ExitCode, res.Stderr)
	}
	if !strings.Contains(res.Stdout, "hello from locnet") {
		t.Errorf("stdout = %q", res.Stdout)
	}
}

// TestNoShellInterpretation is the reason Job.Command is a list. If a shell
// were involved, this would delete something.
func TestNoShellInterpretation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX commands")
	}
	cfg := resource.ComputeConfig{Enabled: true, Allow: []string{"a"}, AllowPrivileged: true, WorkDir: os.TempDir()}

	res := runJob(context.Background(), cfg, resource.Job{
		Command: []string{"echo", "one; touch /tmp/locnet-should-not-exist", "&&", "$(whoami)", "*"},
	}, "a", quiet)

	if res.ExitCode != 0 {
		t.Fatalf("echo failed: %+v", res)
	}
	// Every metacharacter should have come back as a literal.
	for _, want := range []string{";", "&&", "$(whoami)", "*"} {
		if !strings.Contains(res.Stdout, want) {
			t.Errorf("%q was interpreted rather than passed through: %q", want, res.Stdout)
		}
	}
	if _, err := os.Stat("/tmp/locnet-should-not-exist"); err == nil {
		os.Remove("/tmp/locnet-should-not-exist")
		t.Fatal("the shell ran: a file was created by an argument")
	}
}

func TestJobTimeoutKillsTheProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX commands")
	}
	cfg := resource.ComputeConfig{
		Enabled: true, Allow: []string{"a"}, AllowPrivileged: true,
		MaxSeconds: 1, WorkDir: os.TempDir(),
	}
	res := runJob(context.Background(), cfg, resource.Job{Command: []string{"sleep", "30"}}, "a", quiet)

	if !res.TimedOut {
		t.Errorf("the job was not reported as timed out: %+v", res)
	}
	if res.Seconds > 10 {
		t.Errorf("the kill took %.1fs; the limit was 1s", res.Seconds)
	}
}

// TestJobTimeoutKillsChildrenToo is the case the process group exists for: a
// job that is a script running something long. Killing only the script left
// the helper running and holding the output pipe, so the result did not come
// back until the helper finished on its own — thirty seconds here, hours for
// a real job.
func TestJobTimeoutKillsChildrenToo(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX commands")
	}
	cfg := resource.ComputeConfig{
		Enabled: true, Allow: []string{"a"}, AllowPrivileged: true,
		MaxSeconds: 1, WorkDir: os.TempDir(),
	}
	res := runJob(context.Background(), cfg,
		resource.Job{Command: []string{"sh", "-c", "sleep 30 & sleep 30 & wait"}}, "a", quiet)
	if !res.TimedOut {
		t.Errorf("the job was not reported as timed out: %+v", res)
	}
	if res.Seconds > 8 {
		t.Errorf("the result took %.1fs to come back; the children outlived the kill", res.Seconds)
	}
}

// TestJobCannotRaiseTheLimit checks that a caller's timeout only ever narrows
// the machine's own.
func TestJobCannotRaiseTheLimit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX commands")
	}
	cfg := resource.ComputeConfig{
		Enabled: true, Allow: []string{"a"}, AllowPrivileged: true,
		MaxSeconds: 1, WorkDir: os.TempDir(),
	}
	res := runJob(context.Background(), cfg,
		resource.Job{Command: []string{"sleep", "30"}, TimeoutSeconds: 600}, "a", quiet)
	if !res.TimedOut {
		t.Error("a job raised the machine's own time limit")
	}
}

func TestOutputIsCapped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX commands")
	}
	cfg := resource.ComputeConfig{Enabled: true, Allow: []string{"a"}, AllowPrivileged: true,
		MaxSeconds: 20, WorkDir: os.TempDir()}

	// yes(1) prints forever; the cap is what stops this eating the machine.
	res := runJob(context.Background(), cfg,
		resource.Job{Command: []string{"head", "-c", "20000000", "/dev/zero"}, TimeoutSeconds: 15}, "a", quiet)

	if len(res.Stdout) > resource.MaxOutputBytes+256 {
		t.Errorf("stdout is %d bytes, cap is %d", len(res.Stdout), resource.MaxOutputBytes)
	}
	if !res.Truncated {
		t.Error("oversized output was not flagged as truncated")
	}
}

func TestJobValidation(t *testing.T) {
	bad := []resource.Job{
		{},
		{Command: []string{""}},
		{Command: []string{"echo"}, Dir: "relative/path"},
	}
	for i, j := range bad {
		if err := j.Validate(); err == nil {
			t.Errorf("job %d validated: %+v", i, j)
		}
	}
	if err := (&resource.Job{Command: []string{"echo", "hi"}}).Validate(); err != nil {
		t.Errorf("a good job failed validation: %v", err)
	}
}

// TestComputeOfferHidesConfiguration checks that peers learn a machine accepts
// work without learning who it runs as or where.
func TestComputeOfferHidesConfiguration(t *testing.T) {
	cfg := resource.ComputeConfig{
		Enabled: true, Allow: []string{"alpha"}, RunAs: "buildbot",
		WorkDir: "/srv/secret-build-root", Label: "16 cores", MaxSeconds: 900,
	}
	offer := resource.ComputeOffer{Label: cfg.Label, MaxSeconds: cfg.Timeout()}
	raw, err := json.Marshal(offer)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"buildbot", "secret-build-root", "alpha"} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("the offer leaked %q: %s", leak, raw)
		}
	}
}

// TestSweepJobsKnowWhichCopyTheyAre covers what `-n N` is for.
//
// Without an index every copy runs the identical command, which is a way to
// measure a machine rather than a way to divide work — there is nothing for a
// shard to key on. The pair reaches the process as LOCNET_JOB_INDEX and
// LOCNET_JOB_COUNT.
func TestSweepJobsKnowWhichCopyTheyAre(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell")
	}
	cfg := resource.ComputeConfig{Enabled: true, Allow: []string{"*"}, AllowPrivileged: true}

	res := runJob(context.Background(), cfg, resource.Job{
		Command: []string{"/bin/sh", "-c", `echo "$LOCNET_JOB_INDEX of $LOCNET_JOB_COUNT from $LOCNET_JOB_FROM"`},
		Index:   7,
		Count:   240,
	}, "workstation", t.Logf)

	if res.ExitCode != 0 {
		t.Fatalf("exit %d: %s %s", res.ExitCode, res.Stdout, res.Stderr)
	}
	if got := strings.TrimSpace(res.Stdout); got != "7 of 240 from workstation" {
		t.Errorf("job saw %q, want %q", got, "7 of 240 from workstation")
	}
}

// A single job is not a sweep, and must not be handed a misleading index.
func TestSingleJobHasNoSweepVariables(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell")
	}
	cfg := resource.ComputeConfig{Enabled: true, Allow: []string{"*"}, AllowPrivileged: true}

	res := runJob(context.Background(), cfg, resource.Job{
		Command: []string{"/bin/sh", "-c", `echo "[$LOCNET_JOB_INDEX][$LOCNET_JOB_COUNT]"`},
	}, "workstation", t.Logf)

	if got := strings.TrimSpace(res.Stdout); got != "[][]" {
		t.Errorf("a lone job saw %q, want both variables unset", got)
	}
}
