package resource

import (
	"fmt"
	"runtime"
	"strings"
)

// ComputeConfig is a machine's offer to run work for its peers.
//
// This is remote code execution, and the design says so rather than dressing
// it up. Every default is the restrictive one: off, nobody allowed, no shell,
// and — on Unix — a refusal to run anything as root unless the operator has
// said in as many words that they want that.
type ComputeConfig struct {
	// Enabled is false until someone turns it on. There is no way to enable
	// it remotely.
	Enabled bool `json:"enabled"`

	// Allow lists the peer names that may submit work. "*" means every
	// member, and is a much bigger decision here than it is for a file
	// share. An empty list means nobody, which is the default.
	Allow []string `json:"allow,omitempty"`

	// RunAs is the local user account jobs run under. Required on Unix
	// unless AllowPrivileged is set.
	RunAs string `json:"run_as,omitempty"`

	// AllowPrivileged permits jobs to run as the account locnetd itself uses
	// — root on Unix, the service account on Windows. Off by default.
	AllowPrivileged bool `json:"allow_privileged,omitempty"`

	// MaxSeconds bounds a single job. Zero means the default.
	MaxSeconds int `json:"max_seconds,omitempty"`

	// WorkDir is where jobs start. Empty means the RunAs user's home, or
	// the system temporary directory if that cannot be determined.
	WorkDir string `json:"work_dir,omitempty"`

	// Label is free text shown to peers choosing where to run something,
	// e.g. "16 cores, has CUDA".
	Label string `json:"label,omitempty"`
}

// DefaultMaxSeconds bounds a job that did not ask for a limit. Long enough for
// real work, short enough that a hung job releases the machine the same day.
const DefaultMaxSeconds = 3600

// MaxOutputBytes caps what one job may return. A command that prints
// unboundedly should be redirected to a file on the machine running it.
const MaxOutputBytes = 4 << 20

// Validate checks a configuration before it is stored.
func (c *ComputeConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if len(c.Allow) == 0 {
		return fmt.Errorf("compute is enabled but no peer is allowed to use it — pass -allow")
	}
	if c.MaxSeconds < 0 {
		return fmt.Errorf("max seconds cannot be negative")
	}

	if runtime.GOOS == "windows" {
		// locnetd gets a token for the account without its password (an S4U
		// logon), so -user works here as it does on Unix. Whether the account
		// is an elevated administrator is only known once it is logged on,
		// so that check happens per job, in applyCredentials.
		if c.RunAs == "" && !c.AllowPrivileged {
			return fmt.Errorf("compute needs a local account to run jobs as: -user <name>.\n" +
				"To run them as SYSTEM instead — which gives every allowed peer full control " +
				"of this machine — pass -allow-privileged")
		}
		return nil
	}

	if c.RunAs == "" && !c.AllowPrivileged {
		return fmt.Errorf("compute needs a user to run jobs as: -user <name>.\n" +
			"To run them as root instead — which gives every allowed peer root on this " +
			"machine — pass -allow-privileged")
	}
	if c.RunAs == "root" && !c.AllowPrivileged {
		return fmt.Errorf("-user root gives every allowed peer root on this machine; " +
			"pass -allow-privileged if that is really what you want")
	}
	return nil
}

// AllowsPeer reports whether a peer may submit work.
func (c *ComputeConfig) AllowsPeer(name string) bool {
	if !c.Enabled {
		return false
	}
	for _, a := range c.Allow {
		if a == "*" || a == name {
			return true
		}
	}
	return false
}

// AllowText renders the audience for display.
func (c *ComputeConfig) AllowText() string {
	switch {
	case !c.Enabled:
		return "disabled"
	case len(c.Allow) == 0:
		return "nobody"
	case len(c.Allow) == 1 && c.Allow[0] == "*":
		return "everyone"
	default:
		return strings.Join(c.Allow, ", ")
	}
}

// Timeout returns the effective job limit in seconds.
func (c *ComputeConfig) Timeout() int {
	if c.MaxSeconds > 0 {
		return c.MaxSeconds
	}
	return DefaultMaxSeconds
}

// ComputeOffer is what peers are told: that a machine accepts work, and
// roughly what it is. Never the user it runs as or where.
type ComputeOffer struct {
	Label      string `json:"label,omitempty"`
	MaxSeconds int    `json:"max_seconds"`
}

// Job is a request to run something.
type Job struct {
	// Command is the program and its arguments, already split. There is no
	// shell: the words you pass are the words that are exec'd, so quoting,
	// globbing and `;` have no special meaning and no injection to worry
	// about.
	Command []string `json:"command"`
	// Dir overrides the configured working directory. Relative paths are
	// refused.
	Dir string `json:"dir,omitempty"`
	// TimeoutSeconds may lower the machine's limit, never raise it.
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
	// Index and Count identify one job within a sweep submitted with -n, and
	// reach the process as LOCNET_JOB_INDEX and LOCNET_JOB_COUNT. Without
	// them `-n 240` runs the same command 240 times, which is a benchmark
	// rather than a sweep: nothing can tell the copies apart, so nothing can
	// divide the work between them.
	Index int `json:"index,omitempty"`
	Count int `json:"count,omitempty"`
}

// JobResult is what comes back.
type JobResult struct {
	Node     string  `json:"node"`
	ExitCode int     `json:"exit_code"`
	Stdout   string  `json:"stdout"`
	Stderr   string  `json:"stderr"`
	Seconds  float64 `json:"seconds"`
	// TimedOut is true when the job was killed at the limit.
	TimedOut bool `json:"timed_out,omitempty"`
	// Truncated is true when output hit MaxOutputBytes.
	Truncated bool   `json:"truncated,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Validate checks a job before it runs.
func (j *Job) Validate() error {
	if len(j.Command) == 0 {
		return fmt.Errorf("no command given")
	}
	if strings.TrimSpace(j.Command[0]) == "" {
		return fmt.Errorf("the command is blank")
	}
	if j.Dir != "" && !isAbsPath(j.Dir) {
		return fmt.Errorf("the working directory must be an absolute path, got %q", j.Dir)
	}
	return nil
}

func isAbsPath(p string) bool {
	if runtime.GOOS == "windows" {
		return len(p) > 2 && p[1] == ':'
	}
	return strings.HasPrefix(p, "/")
}
