package remote

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeMachine stands in for the far end using the local filesystem.
//
// The shims are not stubs that record arguments and return canned answers:
// rsync really copies, ssh really runs the command in the staged directory,
// and results really come back. That makes this an end-to-end test of the
// stage → run → collect sequence, which is where the interesting mistakes are
// — staging the folder instead of its contents, running in the wrong
// directory, collecting before the command has written anything.
func fakeMachine(t *testing.T) (root string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell shims are not portable to Windows")
	}
	root = t.TempDir() // stands in for the remote home directory
	bin := t.TempDir()

	// ssh: strip flags, find "user@host", run the rest under sh in `root`.
	write(t, filepath.Join(bin, "ssh"), `#!/bin/sh
while [ $# -gt 0 ]; do
  case "$1" in
    -o) shift 2 ;;
    -n|-tt) shift ;;
    *) break ;;
  esac
done
shift                       # drop the destination
# The job script cds into ~/.locnet/jobs/..., so ~ must mean the fake home.
HOME=`+root+` exec sh -c "$*"
`)

	// scp / rsync: keep the last two positional arguments as source and
	// destination, rewrite anything of the form "[user@]host:path" against the
	// fake home, and copy the source's *contents* the way rsync's trailing
	// slash means. The user@ part is optional — a peer with no remembered
	// account produces a bare "host:path".
	cp := `#!/bin/sh
src=""; dst=""; skip=0
for a in "$@"; do
  if [ "$skip" = 1 ]; then skip=0; continue; fi
  case "$a" in
    -e) skip=1 ;;          # -e takes the ssh command as its value
    -*) ;;                 # any other flag
    *)  src="$dst"; dst="$a" ;;
  esac
done
case "$src" in *:*) src="` + root + `/${src#*:}" ;; esac
case "$dst" in *:*) dst="` + root + `/${dst#*:}" ;; esac
src="${src%/}"; src="${src%/.}"; dst="${dst%/}"
mkdir -p "$dst" || exit 1
[ -e "$src" ] || exit 0
cp -R "$src/." "$dst/" || exit 1
exit 0
`
	write(t, filepath.Join(bin, "scp"), cp)
	write(t, filepath.Join(bin, "rsync"), cp)

	// Prepend rather than replace: the shims are shell scripts and need sh,
	// cp and dirname to still be findable.
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return root
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestJobStagesRunsAndBringsResultsBack(t *testing.T) {
	remoteHome := fakeMachine(t)

	work := t.TempDir()
	write(t, filepath.Join(work, "input.txt"), "42\n")

	run := RunJob(context.Background(),
		Target{Name: "lab", Host: "10.99.0.1", Login: "me"},
		Job{
			Dir: work,
			// Reads a file that must have been staged, writes one that must
			// come back.
			Command: "cat input.txt > output.txt",
			Back:    true,
			Keep:    true,
		}, nil)

	if run.Err != "" {
		t.Fatalf("job failed: %s", run.Err)
	}

	// The output file the remote command wrote must exist locally.
	got, err := os.ReadFile(filepath.Join(work, "output.txt"))
	if err != nil {
		t.Fatalf("results were not collected: %v", err)
	}
	if strings.TrimSpace(string(got)) != "42" {
		t.Errorf("collected output = %q, want 42", got)
	}

	// And the staged copy must hold the contents, not a nested folder named
	// after the local directory.
	staged := filepath.Join(remoteHome, run.RemoteDir, "input.txt")
	if _, err := os.Stat(staged); err != nil {
		t.Errorf("the folder's contents were not staged at %s: %v", run.RemoteDir, err)
	}
}

func TestJobRunsInsideTheStagedDirectory(t *testing.T) {
	fakeMachine(t)
	work := t.TempDir()
	write(t, filepath.Join(work, "marker"), "x")

	var out []string
	run := RunJob(context.Background(),
		Target{Name: "lab", Host: "10.99.0.1"},
		Job{Dir: work, Command: "ls", Back: false},
		func(_, line string) { out = append(out, line) })

	if run.Err != "" {
		t.Fatalf("job failed: %s", run.Err)
	}
	// A command that runs in the wrong directory is the failure mode that
	// looks like success until the script cannot find its own data.
	if !strings.Contains(strings.Join(out, "\n"), "marker") {
		t.Errorf("the command did not run in the staged folder; output was:\n%s",
			strings.Join(out, "\n"))
	}
}

func TestFailingJobStillReturnsItsExitCode(t *testing.T) {
	fakeMachine(t)
	work := t.TempDir()

	run := RunJob(context.Background(),
		Target{Name: "lab", Host: "10.99.0.1"},
		Job{Dir: work, Command: "exit 7", Back: false}, nil)

	if run.ExitCode != 7 {
		t.Errorf("exit code = %d, want 7", run.ExitCode)
	}
	if run.Err == "" {
		t.Error("a non-zero exit should be reported as a failure")
	}
}

func TestResultsComeBackEvenWhenTheJobFailed(t *testing.T) {
	fakeMachine(t)
	work := t.TempDir()

	// A crashed run's partial output is usually the reason you want to see.
	RunJob(context.Background(),
		Target{Name: "lab", Host: "10.99.0.1"},
		Job{Dir: work, Command: "echo partial > log.txt; exit 1", Back: true, Keep: true}, nil)

	if _, err := os.Stat(filepath.Join(work, "log.txt")); err != nil {
		t.Errorf("a failed job's output was discarded: %v", err)
	}
}

func TestEnvironmentReachesTheCommand(t *testing.T) {
	fakeMachine(t)
	work := t.TempDir()

	var out []string
	RunJob(context.Background(),
		Target{Name: "lab", Host: "10.99.0.1"},
		Job{Dir: work, Command: "echo $JULIA_NUM_THREADS", Env: []string{"JULIA_NUM_THREADS=16"}},
		func(_, line string) { out = append(out, line) })

	if !strings.Contains(strings.Join(out, "\n"), "16") {
		t.Errorf("environment did not reach the command: %v", out)
	}
}

func TestMissingFolderFailsBeforeTouchingTheNetwork(t *testing.T) {
	fakeMachine(t)

	run := RunJob(context.Background(),
		Target{Name: "lab", Host: "10.99.0.1"},
		Job{Dir: "/definitely/not/here", Command: "true"}, nil)

	if run.Err == "" {
		t.Fatal("a missing folder should fail immediately")
	}
	if !strings.Contains(run.Err, "not a folder") {
		t.Errorf("error should say what was wrong, got %q", run.Err)
	}
}

func TestCleanupRefusesAPathOutsideTheJobRoot(t *testing.T) {
	// cleanup builds an `rm -rf` on the far machine. This checks the guard by
	// running cleanup for real and asserting no ssh was launched — asserting
	// the guard's own condition back at itself would prove nothing.
	root := t.TempDir()
	bin := t.TempDir()
	log := filepath.Join(root, "invoked")
	write(t, filepath.Join(bin, "ssh"), "#!/bin/sh\necho \"$*\" >> "+log+"\n")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	target := Target{Name: "lab", Host: "10.99.0.1"}
	for _, bad := range []string{"", "/", "..", "somewhere/else", remoteRoot + "/../../etc"} {
		cleanup(context.Background(), target, bad)
	}
	if _, err := os.Stat(log); err == nil {
		got, _ := os.ReadFile(log)
		t.Errorf("cleanup ran rm for a path outside the job root:\n%s", got)
	}

	// And the good path must still be cleaned, or scratch folders pile up.
	cleanup(context.Background(), target, remoteRoot+"/proj-123")
	got, err := os.ReadFile(log)
	if err != nil || !strings.Contains(string(got), "proj-123") {
		t.Errorf("a legitimate job folder was not cleaned up: %q", got)
	}
}
