package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/mahantsunandan/locnet/internal/hubapi"
	"github.com/mahantsunandan/locnet/internal/ipc"
	"github.com/mahantsunandan/locnet/internal/placement"
	"github.com/mahantsunandan/locnet/internal/resource"
)

const queueUsage = `Usage:
  locnet queue                      what is waiting and what is running
  locnet queue submit [flags] -- <command>
  locnet queue log <id>             the output of one job
  locnet queue cancel <id>
  locnet queue workers              machines that will take queued work

Flags for submit:
  -on <peer>      run it on that machine and no other
  -cpus N         needs at least N cores
  -mem GB         needs at least GB of free memory
  -disk GB        needs at least GB of free disk
  -gpu            needs a GPU
  -vram GB        needs GB free on a single card (implies -gpu)
  -dir <path>     working directory on the machine that runs it
  -max <seconds>  time limit for one attempt
  -priority N     higher numbers run first
  -label <text>   a name for you to recognise it by
  -n N            submit the same job N times, e.g. for a sweep
  -wait           stay until it finishes, then print the output

The queue lives on the hub, which is the machine that is always on. Jobs wait
there until a machine that meets what they need asks for work, so submitting at
midnight to a fleet that is asleep is a reasonable thing to do.

A machine takes queued work only if its own compute setting already allows you:
  locnet compute enable -allow <your machine> -user <account>
There is no way to make a machine take work it has not agreed to take.`

func cmdQueue(args []string) error {
	pos, flags := splitArgs(args)
	sub := ""
	if len(pos) > 0 {
		sub = pos[0]
	}

	switch sub {
	case "", "list", "ls":
		return queueList(flags)
	case "submit", "add":
		return queueSubmit(args[1:])
	case "log", "logs", "show":
		if len(pos) < 2 {
			return fmt.Errorf("which job? Try: locnet queue log <id>")
		}
		return queueLog(pos[1])
	case "cancel", "stop":
		if len(pos) < 2 {
			return fmt.Errorf("which job? Try: locnet queue cancel <id>")
		}
		return queueCancel(pos[1])
	case "workers":
		return queueWorkers()
	default:
		return fmt.Errorf("unknown queue command %q\n\n%s", sub, queueUsage)
	}
}

// queueJobs lists the queue, or one job. brief leaves out output, which is what
// a listing wants and a log does not.
func queueJobs(id string, brief bool) ([]hubapi.Job, error) {
	c, err := ipc.Dial()
	if err != nil {
		return nil, err
	}
	var jobs []hubapi.Job
	if err := c.Post("/queue/list", map[string]any{"id": id, "brief": brief}, &jobs); err != nil {
		return nil, err
	}
	return jobs, nil
}

func queueList(args []string) error {
	fs := flag.NewFlagSet("queue list", flag.ExitOnError)
	all := fs.Bool("all", false, "include jobs that have already finished")
	mine := fs.Bool("mine", false, "only jobs this machine submitted")
	if err := fs.Parse(args); err != nil {
		return err
	}

	jobs, err := queueJobs("", true)
	if err != nil {
		return err
	}
	me := thisMachineName()

	shown := 0
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "JOB\tSTATE\tWHERE\tAGE\tFROM\tCOMMAND")
	for _, j := range jobs {
		if !*all && j.Terminal() && j.Age() > time.Hour {
			continue
		}
		if *mine && j.Submitter != me {
			continue
		}
		where := j.Node
		if where == "" {
			where = waitingFor(j)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			j.ID, state(j), where, short(j.Age()), j.Submitter, command(j))
		shown++
	}
	w.Flush()

	if shown == 0 {
		fmt.Println("Nothing in the queue.")
		fmt.Println("\n" + queueUsage)
	}
	return nil
}

// waitingFor says what a queued job is waiting for, which is the question
// somebody staring at a queue actually has.
func waitingFor(j hubapi.Job) string {
	switch {
	case j.State != hubapi.JobQueued:
		return "—"
	case j.On != "":
		return "waiting for " + j.On
	case j.Need.GPU || j.Need.VRAMMB > 0:
		return "waiting for a GPU"
	case j.Need.CPUs > 0:
		return fmt.Sprintf("waiting for %d cores", j.Need.CPUs)
	default:
		return "waiting"
	}
}

func state(j hubapi.Job) string {
	if j.State == hubapi.JobFailed && j.ExitCode != 0 {
		return fmt.Sprintf("failed(%d)", j.ExitCode)
	}
	return j.State
}

func command(j hubapi.Job) string {
	c := strings.Join(j.Command, " ")
	if j.Label != "" {
		c = j.Label + ": " + c
	}
	if len(c) > 60 {
		c = c[:57] + "…"
	}
	return c
}

func short(d time.Duration) string {
	switch {
	case d <= 0:
		return "—"
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	default:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
}

func queueSubmit(args []string) error {
	// Everything after -- is the command, exactly as typed.
	var flagArgs, cmd []string
	for i, a := range args {
		if a == "--" {
			flagArgs, cmd = args[:i], args[i+1:]
			break
		}
	}
	if cmd == nil {
		return fmt.Errorf("put the command after --, e.g.\n" +
			"  locnet queue submit -cpus 8 -- make -j8")
	}
	if len(cmd) == 0 {
		return fmt.Errorf("there is no command after --")
	}

	fs := flag.NewFlagSet("queue submit", flag.ExitOnError)
	on := fs.String("on", "", "run on this machine and no other")
	cpus := fs.Int("cpus", 0, "minimum cores")
	mem := fs.Int("mem", 0, "minimum free memory, in GB")
	disk := fs.Int("disk", 0, "minimum free disk, in GB")
	gpu := fs.Bool("gpu", false, "needs a GPU")
	vram := fs.Int("vram", 0, "minimum free GPU memory on one card, in GB")
	dir := fs.String("dir", "", "working directory on the machine that runs it")
	max := fs.Int("max", 0, "time limit for one attempt, in seconds")
	priority := fs.Int("priority", 0, "higher numbers run first")
	label := fs.String("label", "", "a name for you to recognise it by")
	count := fs.Int("n", 1, "submit this many copies")
	wait := fs.Bool("wait", false, "wait for it to finish and print the output")
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}

	job := hubapi.Job{
		Command:    cmd,
		Dir:        *dir,
		Label:      *label,
		On:         *on,
		Priority:   *priority,
		MaxSeconds: *max,
		Need: placement.Need{
			CPUs:   *cpus,
			MemMB:  uint64(*mem) * 1024,
			DiskGB: uint64(*disk),
			GPU:    *gpu,
			VRAMMB: uint64(*vram) * 1024,
		},
	}

	c, err := ipc.Dial()
	if err != nil {
		return err
	}
	var ids []string
	n := max1(*count)
	for i := 0; i < n; i++ {
		// Each copy is told which of the set it is, so a sweep can divide the
		// work. Only meaningful when there is more than one.
		if n > 1 {
			job.Index, job.Count = i, n
		}
		var out hubapi.Job
		if err := c.Post("/queue/submit", job, &out); err != nil {
			return err
		}
		ids = append(ids, out.ID)
	}

	if len(ids) == 1 {
		fmt.Printf("Queued %s: %s\n", ids[0], strings.Join(cmd, " "))
	} else {
		fmt.Printf("Queued %d jobs: %s\n", len(ids), strings.Join(ids, " "))
	}
	if !*wait {
		fmt.Println("Watch it with:  locnet queue")
		return nil
	}
	return waitForJobs(ids)
}

func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

// waitForJobs polls until every id has stopped, then prints the output.
func waitForJobs(ids []string) error {
	pending := map[string]bool{}
	for _, id := range ids {
		pending[id] = true
	}
	for len(pending) > 0 {
		time.Sleep(2 * time.Second)
		jobs, err := queueJobs("", true)
		if err != nil {
			return err
		}
		for _, j := range jobs {
			if !pending[j.ID] || !j.Terminal() {
				continue
			}
			delete(pending, j.ID)
			// The listing leaves output out; fetch it for the one that finished.
			if full, err := queueJobs(j.ID, false); err == nil && len(full) == 1 {
				j = full[0]
			}
			printJob(j)
		}
	}
	return nil
}

func queueLog(id string) error {
	jobs, err := queueJobs(id, false)
	if err != nil {
		return err
	}
	if len(jobs) == 0 {
		return fmt.Errorf("no job called %q", id)
	}
	printJob(jobs[0])
	return nil
}

func printJob(j hubapi.Job) {
	fmt.Printf("%s  %s  %s\n", j.ID, state(j), strings.Join(j.Command, " "))
	if j.Node != "" {
		fmt.Printf("  ran on %s in %.1fs\n", j.Node, j.Seconds)
	}
	if j.Attempts > 1 {
		fmt.Printf("  attempt %d of %d\n", j.Attempts, j.MaxAttempts)
	}
	if j.Error != "" {
		fmt.Printf("  %s\n", j.Error)
	}
	if j.Stdout != "" {
		fmt.Println("--- output")
		fmt.Print(j.Stdout)
		if !strings.HasSuffix(j.Stdout, "\n") {
			fmt.Println()
		}
	}
	if j.Stderr != "" {
		fmt.Println("--- errors")
		fmt.Print(j.Stderr)
		if !strings.HasSuffix(j.Stderr, "\n") {
			fmt.Println()
		}
	}
}

func queueCancel(id string) error {
	c, err := ipc.Dial()
	if err != nil {
		return err
	}
	if err := c.Post("/queue/cancel", map[string]string{"id": id}, nil); err != nil {
		return err
	}
	fmt.Printf("Cancelled %s.\n", id)
	fmt.Println("A job that is already running is stopped within ten seconds.")
	return nil
}

// queueWorkers lists the machines that would take work, which is the first
// thing to check when a queue is not moving.
func queueWorkers() error {
	st, err := status()
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "MACHINE\tSTATE\tCORES\tFREE MEM\tGPU\tTAKES WORK FROM")

	rows := 0
	if st.Compute.Enabled {
		fmt.Fprintf(w, "%s (this one)\t%s\t%d\t%s\t%s\t%s\n", st.Name,
			onlineWord(true), st.Stats.CPUs, gbText(st.Stats.MemFreeMB),
			gpuText(st.Stats), st.Compute.AllowText())
		rows++
	}
	for _, p := range st.Peers {
		if p.Compute == nil {
			continue
		}
		label := p.Compute.Label
		if label == "" {
			label = "you"
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\n", p.Name, onlineWord(p.Online),
			p.Stats.CPUs, gbText(p.Stats.MemFreeMB), gpuText(p.Stats), label)
		rows++
	}
	w.Flush()

	if rows == 0 {
		fmt.Println("No machine on this network will take queued work yet.")
		fmt.Println()
		fmt.Println("On each machine that should:")
		fmt.Println("    locnet compute enable -allow <who may submit> -user <account>")
	}
	return nil
}

func onlineWord(up bool) string {
	if up {
		return "online"
	}
	return "offline"
}

// gpuText names the accelerator, or says plainly that there is not one.
func gpuText(st resource.Stats) string {
	if s := st.GPUSummary(); s != "" {
		return s
	}
	return "—"
}

func gbText(mb uint64) string {
	if mb == 0 {
		return "—"
	}
	return fmt.Sprintf("%.1f GB", float64(mb)/1024)
}
