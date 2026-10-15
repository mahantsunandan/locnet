package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/mahantsunandan/locnet/internal/ipc"
	"github.com/mahantsunandan/locnet/internal/node"
	"github.com/mahantsunandan/locnet/internal/resource"
	"github.com/mahantsunandan/locnet/internal/shareclient"
)

const computeUsage = `Usage:
  locnet compute                  show this machine's setting
  locnet compute enable [flags]   accept jobs from named peers
  locnet compute disable

Flags for enable:
  -allow    comma-separated peer names, or "*" (required)
  -user     local account jobs run as (required)
  -label    free text shown to peers, e.g. "16 cores, CUDA"
  -max      seconds a single job may run (default 3600)
  -dir      working directory for jobs
  -allow-privileged   run jobs as the locnetd account (root, or SYSTEM on
                      Windows) when no -user is given. Read the warning.

This is remote code execution. A peer you allow can run any command your
chosen user can run. It is off until you turn it on, and there is no way to
turn it on remotely.`

func cmdCompute(args []string) error {
	pos, flags := splitArgs(args)
	sub := ""
	if len(pos) > 0 {
		sub = pos[0]
	}

	switch sub {
	case "", "show":
		return computeShow()
	case "disable":
		c, err := ipc.Dial()
		if err != nil {
			return err
		}
		if err := c.Post("/compute", resource.ComputeConfig{}, nil); err != nil {
			return err
		}
		fmt.Println("Compute is off. This machine will not run jobs for anyone.")
		return nil
	case "enable":
		return computeEnable(flags)
	default:
		return fmt.Errorf("unknown compute command %q\n\n%s", sub, computeUsage)
	}
}

func computeShow() error {
	st, err := status()
	if err != nil {
		return err
	}
	c := st.Compute
	if !c.Enabled {
		fmt.Println("Compute is off. This machine will not run jobs for anyone.")
		fmt.Println("\n" + computeUsage)
		return nil
	}
	fmt.Printf("  accepting jobs from   %s\n", c.AllowText())
	if c.RunAs != "" {
		fmt.Printf("  running as            %s\n", c.RunAs)
	} else {
		fmt.Printf("  running as            the locnetd account (privileged)\n")
	}
	fmt.Printf("  time limit            %d seconds\n", c.Timeout())
	if c.WorkDir != "" {
		fmt.Printf("  working directory     %s\n", c.WorkDir)
	}
	if c.Label != "" {
		fmt.Printf("  advertised as         %s\n", c.Label)
	}
	return nil
}

func computeEnable(args []string) error {
	fs := flag.NewFlagSet("compute enable", flag.ExitOnError)
	allow := fs.String("allow", "", `peers that may submit jobs, comma-separated, or "*"`)
	user := fs.String("user", "", "local account jobs run as")
	label := fs.String("label", "", "free text shown to peers")
	max := fs.Int("max", 0, "seconds a single job may run")
	dir := fs.String("dir", "", "working directory for jobs")
	priv := fs.Bool("allow-privileged", false, "run jobs as the locnetd account")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg := resource.ComputeConfig{
		Enabled: true, RunAs: *user, Label: *label,
		MaxSeconds: *max, WorkDir: *dir, AllowPrivileged: *priv,
	}
	for _, a := range strings.Split(*allow, ",") {
		if a = strings.TrimSpace(a); a != "" {
			cfg.Allow = append(cfg.Allow, a)
		}
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	c, err := ipc.Dial()
	if err != nil {
		return err
	}
	if err := c.Post("/compute", cfg, nil); err != nil {
		return err
	}

	fmt.Printf("Compute is on. %s may run commands here", cfg.AllowText())
	if cfg.RunAs != "" {
		fmt.Printf(" as %s.\n", cfg.RunAs)
	} else {
		fmt.Printf(" as the locnetd account.\n")
	}
	if len(cfg.Allow) == 1 && cfg.Allow[0] == "*" {
		fmt.Println("\n  Every member of the network can now run commands on this machine.")
		fmt.Println("  Narrow it with: locnet compute enable -allow <peer> -user <account>")
	}
	return nil
}

// ------------------------------------------------------------------- run

const runUsage = `Usage:
  locnet run <peer> -- <command> [args…]
  locnet run -group <name> -- <command> [args…]
  locnet run -idle -- <command> [args…]

Flags:
  -group    run on every machine in a policy group
  -idle     run on whichever machine that accepts your jobs is least busy
  -timeout  seconds to allow (never more than the machine's own limit)
  -dir      absolute working directory on the far machine

There is no shell. The words after -- are exec'd exactly as written, so
quoting, globs and semicolons carry no special meaning.`

func cmdRun(args []string) error {
	// Everything after -- is the command, untouched.
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 0 {
		return errors.New(runUsage)
	}
	head, command := args[:sep], args[sep+1:]
	if len(command) == 0 {
		return errors.New("nothing to run after --")
	}

	pos, flags := splitArgs(head)
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	group := fs.String("group", "", "run on every machine in a policy group")
	idle := fs.Bool("idle", false, "run on the least busy machine that accepts your jobs")
	timeout := fs.Int("timeout", 0, "seconds to allow")
	dir := fs.String("dir", "", "absolute working directory on the far machine")
	if err := fs.Parse(flags); err != nil {
		return err
	}

	st, err := status()
	if err != nil {
		return err
	}

	targets, err := chooseTargets(st, pos, *group, *idle)
	if err != nil {
		return err
	}

	job := resource.Job{Command: command, Dir: *dir, TimeoutSeconds: *timeout}
	results := runEverywhere(targets, job)

	failed := 0
	for _, r := range results {
		if len(results) > 1 {
			fmt.Printf("\n── %s ── exit %d in %.1fs\n", r.Node, r.ExitCode, r.Seconds)
		}
		if r.Stdout != "" {
			fmt.Print(r.Stdout)
			if !strings.HasSuffix(r.Stdout, "\n") {
				fmt.Println()
			}
		}
		if r.Stderr != "" {
			fmt.Fprint(os.Stderr, r.Stderr)
			if !strings.HasSuffix(r.Stderr, "\n") {
				fmt.Fprintln(os.Stderr)
			}
		}
		if r.Error != "" {
			fmt.Fprintf(os.Stderr, "locnet: %s: %s\n", r.Node, r.Error)
		}
		if r.ExitCode != 0 {
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d machine(s) returned a non-zero exit code", failed, len(results))
	}
	return nil
}

// chooseTargets resolves the machines a job should run on.
func chooseTargets(st node.Status, pos []string, group string, idle bool) ([]node.PeerStatus, error) {
	willing := func(p node.PeerStatus) bool { return p.Online && p.Compute != nil }

	switch {
	case idle:
		var best *node.PeerStatus
		for i := range st.Peers {
			p := st.Peers[i]
			if !willing(p) {
				continue
			}
			if best == nil || busyness(p) < busyness(*best) {
				best = &st.Peers[i]
			}
		}
		if best == nil {
			return nil, errors.New("no machine on this network is offering to run jobs for you")
		}
		fmt.Fprintf(os.Stderr, "locnet: running on %s (%s)\n", best.Name, loadText(best.Stats))
		return []node.PeerStatus{*best}, nil

	case group != "":
		var out []node.PeerStatus
		for _, p := range st.Peers {
			for _, g := range p.Groups {
				if g == group && willing(p) {
					out = append(out, p)
				}
			}
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("no online machine in group %q is offering to run jobs for you", group)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		return out, nil

	case len(pos) == 1:
		p, err := resolvePeer(pos[0])
		if err != nil {
			return nil, err
		}
		if p.Compute == nil {
			return nil, fmt.Errorf("%s is not offering to run jobs for this machine.\n"+
				"On %s, run: locnet compute enable -allow %s -user <account>", p.Name, p.Name, st.Name)
		}
		return []node.PeerStatus{p}, nil

	default:
		return nil, errors.New(runUsage)
	}
}

// busyness ranks machines for -idle. Load is the signal that matters; free
// memory breaks ties, because a machine at 5% CPU with no RAM left is not
// actually available.
func busyness(p node.PeerStatus) float64 {
	load := p.Stats.LoadPercent
	if p.Stats.CPUs == 0 {
		load = 50 // unmeasured: assume middling rather than idle
	}
	mem := p.Stats.MemUsedPercent()
	if mem < 0 {
		mem = 50
	}
	return load*0.8 + mem*0.2
}

// runEverywhere submits the job to every target at once.
func runEverywhere(targets []node.PeerStatus, job resource.Job) []resource.JobResult {
	results := make([]resource.JobResult, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t node.PeerStatus) {
			defer wg.Done()
			limit := resource.DefaultMaxSeconds
			if t.Compute != nil && t.Compute.MaxSeconds > 0 {
				limit = t.Compute.MaxSeconds
			}
			ctx, cancel := context.WithTimeout(context.Background(),
				time.Duration(limit+30)*time.Second)
			defer cancel()

			r, err := shareclient.New(t.IP).Exec(ctx, job)
			if err != nil {
				r = &resource.JobResult{ExitCode: -1, Error: err.Error()}
			}
			r.Node = t.Name
			results[i] = *r
		}(i, t)
	}
	wg.Wait()
	return results
}

// cmdCompute's listing of who will run work for us.
func cmdComputePeers() error {
	st, err := status()
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PEER\tSTATUS\tCPU\tFREE RAM\tLIMIT\tLABEL")
	found := 0
	for _, p := range st.Peers {
		if p.Compute == nil {
			continue
		}
		found++
		state := "offline"
		if p.Online {
			state = "ready"
		}
		ram := "-"
		if p.Stats.MemTotalMB > 0 && p.Stats.MemFreeMB > 0 {
			ram = fmt.Sprintf("%.1f GB", float64(p.Stats.MemFreeMB)/1024)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%ds\t%s\n",
			p.Name, state, loadText(p.Stats), ram, p.Compute.MaxSeconds, orDash(p.Compute.Label))
	}
	w.Flush()
	if found == 0 {
		fmt.Println("No machine on this network is offering to run jobs for you.")
		fmt.Println("\nOn a machine that should:  locnet compute enable -allow <this machine> -user <account>")
	}
	return nil
}
