// Package placement decides which machine should run a piece of work.
//
// The question "which computer is most powerful" has no single answer, and
// pretending otherwise is how scheduling goes wrong. A 64-core server is the
// wrong place for a CUDA job and the right place for a parallel build; a
// laptop with a 4090 is the reverse. So the caller states what the work needs,
// and machines that cannot meet it are excluded rather than ranked low —
// sending a job to a machine that will fail is worse than saying no.
//
// Among the machines that qualify, the ranking prefers the one with the most
// *free* capacity rather than the largest hardware. A 64-core machine already
// running at 95% is slower than an idle 8-core one, and it is the free figure
// that predicts how long the job takes.
package placement

import (
	"fmt"
	"sort"
	"strings"

	"github.com/mahantsunandan/locnet/internal/resource"
)

// Need describes what a job requires. The zero value means "anywhere".
type Need struct {
	// CPUs is the minimum core count.
	CPUs int `json:"cpus,omitempty"`
	// MemMB is the minimum *free* memory.
	MemMB uint64 `json:"mem_mb,omitempty"`
	// GPU requires an accelerator of any kind.
	GPU bool `json:"gpu,omitempty"`
	// VRAMMB is the minimum free memory on a single card. Implies GPU.
	VRAMMB uint64 `json:"vram_mb,omitempty"`
	// DiskGB is the minimum free disk, for jobs that write large outputs.
	DiskGB uint64 `json:"disk_gb,omitempty"`
}

// Candidate is a machine that might run the work.
type Candidate struct {
	Name   string
	Host   string
	Online bool
	Stats  resource.Stats
	// Self marks this machine. It stays in the running — sometimes the
	// machine you are sitting at really is the best place — but it loses a
	// tie, because moving work off it is usually the point.
	Self bool
}

// Ranked is a candidate with its score and the reasoning behind it.
type Ranked struct {
	Candidate
	Score  float64
	Reason string
	// Why is set when the machine was excluded, and says what it lacked.
	Why string
}

// Fits reports whether a candidate meets the need, and what is missing if not.
func (n Need) Fits(c Candidate) (bool, string) {
	if !c.Online {
		return false, "offline"
	}
	if n.CPUs > 0 && c.Stats.CPUs > 0 && c.Stats.CPUs < n.CPUs {
		return false, fmt.Sprintf("has %d cores, needs %d", c.Stats.CPUs, n.CPUs)
	}
	if n.MemMB > 0 && c.Stats.MemFreeMB > 0 && c.Stats.MemFreeMB < n.MemMB {
		return false, fmt.Sprintf("has %s free memory, needs %s",
			gb(c.Stats.MemFreeMB), gb(n.MemMB))
	}
	if n.DiskGB > 0 && c.Stats.DiskFreeGB > 0 && c.Stats.DiskFreeGB < n.DiskGB {
		return false, fmt.Sprintf("has %d GB free disk, needs %d GB", c.Stats.DiskFreeGB, n.DiskGB)
	}
	if (n.GPU || n.VRAMMB > 0) && len(c.Stats.GPUs) == 0 {
		return false, "no GPU detected"
	}
	if n.VRAMMB > 0 && c.Stats.GPUMemFreeMB() < n.VRAMMB {
		return false, fmt.Sprintf("largest card has %s free, needs %s",
			gb(c.Stats.GPUMemFreeMB()), gb(n.VRAMMB))
	}
	return true, ""
}

// Rank orders candidates best-first. Machines that cannot meet the need are
// returned too, at the end, with Why set — so a caller can tell the user why
// their GPU job has nowhere to go instead of just "no machines available".
func Rank(cands []Candidate, n Need) []Ranked {
	var ok, no []Ranked
	for _, c := range cands {
		fits, why := n.Fits(c)
		if !fits {
			no = append(no, Ranked{Candidate: c, Why: why})
			continue
		}
		score, reason := score(c, n)
		ok = append(ok, Ranked{Candidate: c, Score: score, Reason: reason})
	}

	sort.SliceStable(ok, func(i, j int) bool {
		if ok[i].Score != ok[j].Score {
			return ok[i].Score > ok[j].Score
		}
		// Prefer moving work away from the machine being used.
		if ok[i].Self != ok[j].Self {
			return !ok[i].Self
		}
		return ok[i].Name < ok[j].Name
	})
	sort.SliceStable(no, func(i, j int) bool { return no[i].Name < no[j].Name })
	return append(ok, no...)
}

// Best returns the single best machine, or an error explaining why there is
// none. The error names every machine and what it lacked, because "no suitable
// machine" on its own is the least useful thing a scheduler can say.
func Best(cands []Candidate, n Need) (Ranked, error) {
	ranked := Rank(cands, n)
	if len(ranked) > 0 && ranked[0].Why == "" {
		return ranked[0], nil
	}
	if len(ranked) == 0 {
		return Ranked{}, fmt.Errorf("no machines on this network yet")
	}
	var lines []string
	for _, r := range ranked {
		lines = append(lines, fmt.Sprintf("  %-14s %s", r.Name, r.Why))
	}
	return Ranked{}, fmt.Errorf("no machine meets what this job needs:\n%s", strings.Join(lines, "\n"))
}

// score rates a machine's free capacity. Higher is better.
//
// The weights are deliberately blunt. A scheduler that models cache hierarchy
// and memory bandwidth would be more accurate and would still be guessing,
// because it does not know what the job does. What it can know is that free
// cores, free memory and an idle GPU all make a job finish sooner.
func score(c Candidate, n Need) (float64, string) {
	s := c.Stats
	var total float64
	var parts []string

	// Free cores: cores scaled by how idle the machine is.
	if s.CPUs > 0 {
		idle := 1 - clamp(s.LoadPercent/100)
		free := float64(s.CPUs) * idle
		total += free * 10
		parts = append(parts, fmt.Sprintf("%.0f of %d cores free", free, s.CPUs))
	}

	// Free memory, in GB, weighted below cores: most work is core-bound
	// until it runs out of memory, and running out is handled by Fits.
	if s.MemFreeMB > 0 {
		total += float64(s.MemFreeMB) / 1024 * 2
		parts = append(parts, gb(s.MemFreeMB)+" RAM free")
	}

	// A GPU dominates when the job asked for one, and counts for a little
	// when it did not — a spare accelerator is worth having either way.
	if len(s.GPUs) > 0 {
		weight := 0.5
		if n.GPU || n.VRAMMB > 0 {
			weight = 20
		}
		total += float64(s.GPUMemFreeMB()) / 1024 * weight
		parts = append(parts, fmt.Sprintf("%s (%s free)", s.GPUSummary(), gb(s.GPUMemFreeMB())))
	}

	return total, strings.Join(parts, ", ")
}

func clamp(f float64) float64 {
	if f < 0 {
		return 0
	}
	if f > 1 {
		return 1
	}
	return f
}

func gb(mb uint64) string {
	if mb == 0 {
		return "0"
	}
	if mb < 1024 {
		return fmt.Sprintf("%d MB", mb)
	}
	return fmt.Sprintf("%.1f GB", float64(mb)/1024)
}
