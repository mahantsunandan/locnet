package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/mahantsunandan/locnet/internal/peercfg"
	"github.com/mahantsunandan/locnet/internal/placement"
	"github.com/mahantsunandan/locnet/internal/remote"
)

// needFlags are the requirements shared by `best` and `job`.
type needFlags struct {
	gpu   bool
	cpus  int
	memGB float64
	vram  float64
	disk  uint64
}

func (n *needFlags) register(fs *flag.FlagSet) {
	fs.BoolVar(&n.gpu, "gpu", false, "only machines with a GPU")
	fs.IntVar(&n.cpus, "cpus", 0, "minimum CPU cores")
	fs.Float64Var(&n.memGB, "mem", 0, "minimum free memory, in GB")
	fs.Float64Var(&n.vram, "vram", 0, "minimum free GPU memory, in GB (implies -gpu)")
	fs.Uint64Var(&n.disk, "disk", 0, "minimum free disk, in GB")
}

func (n needFlags) need() placement.Need {
	return placement.Need{
		CPUs:   n.cpus,
		MemMB:  uint64(n.memGB * 1024),
		GPU:    n.gpu,
		VRAMMB: uint64(n.vram * 1024),
		DiskGB: n.disk,
	}
}

// candidates builds the pool from the live status, this machine included.
//
// Including this machine matters: sometimes the honest answer to "where should
// this run" is "right here", and a tool that always sends work away would hide
// that.
func candidates() ([]placement.Candidate, error) {
	st, err := status()
	if err != nil {
		return nil, err
	}
	out := []placement.Candidate{{
		Name: st.Name, Host: st.IP.String(), Online: st.Running,
		Stats: st.Stats, Self: true,
	}}
	for _, p := range st.Peers {
		out = append(out, placement.Candidate{
			Name: p.Name, Host: p.IP.String(), Online: p.Online, Stats: p.Stats,
		})
	}
	return out, nil
}

// cmdBest shows where work would go, and why.
//
// Printed rather than silently chosen because a scheduler people cannot see
// into is a scheduler people stop trusting the first time it surprises them.
func cmdBest(args []string) error {
	fs := flag.NewFlagSet("best", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "machine-readable output, for editors and scripts")
	var nf needFlags
	nf.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	cands, err := candidates()
	if err != nil {
		return err
	}
	ranked := placement.Rank(cands, nf.need())

	if *asJSON {
		type row struct {
			Name    string  `json:"name"`
			Host    string  `json:"host"`
			Self    bool    `json:"self"`
			Usable  bool    `json:"usable"`
			Score   float64 `json:"score"`
			Reason  string  `json:"reason,omitempty"`
			Skipped string  `json:"skipped,omitempty"`
			CPUs    int     `json:"cpus,omitempty"`
			MemMB   uint64  `json:"mem_free_mb,omitempty"`
			GPU     string  `json:"gpu,omitempty"`
			VRAMMB  uint64  `json:"gpu_free_mb,omitempty"`
		}
		out := make([]row, 0, len(ranked))
		for _, r := range ranked {
			out = append(out, row{
				Name: r.Name, Host: r.Host, Self: r.Self, Usable: r.Why == "",
				Score: r.Score, Reason: r.Reason, Skipped: r.Why,
				CPUs: r.Stats.CPUs, MemMB: r.Stats.MemFreeMB,
				GPU: r.Stats.GPUSummary(), VRAMMB: r.Stats.GPUMemFreeMB(),
			})
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "RANK\tMACHINE\tSCORE\tWHY")
	n := 0
	for _, r := range ranked {
		if r.Why != "" {
			continue
		}
		n++
		name := r.Name
		if r.Self {
			name += " (this one)"
		}
		fmt.Fprintf(w, "%d\t%s\t%.0f\t%s\n", n, name, r.Score, r.Reason)
	}
	if n == 0 {
		fmt.Fprintln(w, "—\t(none qualify)\t\t")
	}
	for _, r := range ranked {
		if r.Why == "" {
			continue
		}
		fmt.Fprintf(w, "—\t%s\t\tskipped: %s\n", r.Name, r.Why)
	}
	w.Flush()

	if n > 0 {
		fmt.Printf("\nlocnet job -best -- <command>   runs on %s\n", ranked[0].Name)
	}
	return nil
}

// cmdJob sends a folder and a command to another machine and brings the
// results back.
func cmdJob(args []string) error {
	fs := flag.NewFlagSet("job", flag.ExitOnError)
	on := fs.String("on", "", "machine to run on (default: the best fit)")
	dir := fs.String("dir", ".", "folder to send")
	back := fs.Bool("back", true, "copy the folder back afterwards, so output files appear locally")
	keep := fs.Bool("keep", false, "leave the remote copy in place instead of deleting it")
	exclude := fs.String("exclude", ".git,node_modules,target,build,__pycache__",
		"comma-separated patterns not to send")
	env := fs.String("env", "", "comma-separated KEY=VALUE for the remote command")
	var nf needFlags
	nf.register(fs)

	pos, flags := splitArgs(args)
	// Everything after `--` is the command. Without the separator, flags
	// meant for the remote program would be eaten by this flag set.
	if i := indexOf(args, "--"); i >= 0 {
		pos = args[i+1:]
		flags = args[:i]
		if j := indexOf(flags, "--"); j >= 0 {
			flags = flags[:j]
		}
	}
	if err := fs.Parse(flags); err != nil {
		return err
	}
	command := strings.Join(pos, " ")
	if strings.TrimSpace(command) == "" {
		return fmt.Errorf("usage: locnet job [-on peer] [-gpu] [-dir .] -- <command>\n" +
			"Examples:\n" +
			"  locnet job -- julia -t 16 run.jl\n" +
			"  locnet job -gpu -vram 8 -- python train.py\n" +
			"  locnet job -on lab-1 -dir ./sim -- make -j32")
	}

	cands, err := candidates()
	if err != nil {
		return err
	}

	var target remote.Target
	var chosen string
	if *on != "" {
		p, err := resolvePeer(*on)
		if err != nil {
			return err
		}
		target, chosen = targetFor(p), p.Name
	} else {
		best, err := placement.Best(cands, nf.need())
		if err != nil {
			return err
		}
		if best.Self {
			return fmt.Errorf("this machine is already the best fit (%s).\n"+
				"Run it here, or name another with -on <peer>.", best.Reason)
		}
		chosen = best.Name
		target = remote.Target{Name: best.Name, Host: best.Host, Login: peercfg.UserFor(best.Name)}
		// The far machine's OS decides how the job is staged and started.
		if p, err := resolvePeer(best.Name); err == nil {
			target = targetFor(p)
		}
		fmt.Printf("locnet: chose %s — %s\n", best.Name, best.Reason)
	}

	job := remote.Job{
		Dir:     *dir,
		Command: command,
		Back:    *back,
		Keep:    *keep,
		Exclude: splitComma(*exclude),
		Env:     splitComma(*env),
	}

	ctx, stop := interruptible()
	defer stop()

	run := remote.RunJob(ctx, target, job, func(_, line string) { fmt.Println(line) })

	fmt.Println()
	if run.Err != "" {
		return fmt.Errorf("%s: %s", chosen, run.Err)
	}
	fmt.Printf("locnet: finished on %s in %.1fs\n", chosen, run.Secs)
	if *back {
		fmt.Printf("        results copied back into %s\n", *dir)
	}
	if *keep {
		fmt.Printf("        remote copy left at ~/%s\n", run.RemoteDir)
	}
	return nil
}

// cmdJulia writes the glue for Julia's Distributed standard library.
//
// Julia already runs workers on other machines over SSH; what stops people is
// that it needs stable hostnames, matching paths and working key auth, which
// on an ordinary office network it does not have. LocNet supplies exactly
// those, so this command is small — and that is the point.
func cmdJulia(args []string) error {
	fs := flag.NewFlagSet("julia", flag.ExitOnError)
	on := fs.String("on", "all", "machines to use: comma-separated names, or \"all\"")
	exename := fs.String("exename", "julia", "path to julia on the far machines")
	perHost := fs.Int("procs", 0, "workers per machine (default: one per core)")
	file := fs.String("machine-file", "", "also write a --machine-file to this path")
	var nf needFlags
	nf.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	cands, err := candidates()
	if err != nil {
		return err
	}
	want := map[string]bool{}
	all := *on == "all" || *on == ""
	for _, n := range splitComma(*on) {
		want[n] = true
	}

	need := nf.need()
	var specs, machineLines []string
	var total int
	for _, r := range placement.Rank(cands, need) {
		if r.Why != "" || r.Self {
			continue
		}
		if !all && !want[r.Name] {
			continue
		}
		n := *perHost
		if n == 0 {
			// One worker per core is Julia's own default shape. Leaving a
			// core for the OS matters less than it sounds on a machine
			// dedicated to the run, and users who care pass -procs.
			n = r.Stats.CPUs
		}
		if n <= 0 {
			n = 1
		}
		total += n
		dest := r.Host
		if u := peercfg.UserFor(r.Name); u != "" {
			dest = u + "@" + dest
		}
		specs = append(specs, fmt.Sprintf("    (\"%s\", %d),   # %s — %s", dest, n, r.Name, r.Reason))
		for i := 0; i < n; i++ {
			machineLines = append(machineLines, dest)
		}
	}
	if len(specs) == 0 {
		return fmt.Errorf("no machines qualify. Try `locnet best` to see why")
	}

	if *file != "" {
		if err := os.WriteFile(*file, []byte(strings.Join(machineLines, "\n")+"\n"), 0o644); err != nil {
			return err
		}
		fmt.Printf("Wrote %s (%d workers).\nRun:  julia --machine-file %s yourscript.jl\n\n",
			*file, total, *file)
	}

	fmt.Printf(`# %d workers across %d machine(s). Paste into Julia, or into your script.
using Distributed

addprocs([
%s
];
    exename    = "%s",
    tunnel     = false,        # LocNet already carries the traffic
    sshflags   = `+"`"+`-o BatchMode=yes -o StrictHostKeyChecking=accept-new`+"`"+`,
    topology   = :master_worker,
)

@everywhere using Base.Threads
println("workers: ", nworkers(), "  threads each: ", fetch(@spawnat 2 nthreads()))
`, total, len(specs), strings.Join(specs, "\n"), *exename)

	fmt.Printf(`
# Requirements on each machine, once:
#   locnet login <peer> <account> && locnet ssh-key <peer>
#   the same Julia version at %s, and the packages your script needs
`, *exename)
	return nil
}

func splitComma(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func indexOf(list []string, want string) int {
	for i, x := range list {
		if x == want {
			return i
		}
	}
	return -1
}
