package resource

import (
	"bufio"
	"context"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// GPU is one accelerator found on a machine.
//
// Reported because "run it on the powerful machine" is usually a question
// about the GPU, and until now LocNet could not answer it. A machine with 64
// cores and no CUDA is the wrong place to send a training job, and a laptop
// with a 4090 is the right place despite having eight cores.
type GPU struct {
	// Name is the marketing name, e.g. "NVIDIA GeForce RTX 4090".
	Name string `json:"name"`
	// Vendor is "nvidia", "amd", "intel" or "apple".
	Vendor string `json:"vendor,omitempty"`
	// MemTotalMB is the card's memory. Zero when it could not be read.
	MemTotalMB uint64 `json:"mem_total_mb,omitempty"`
	// MemFreeMB is what is currently unused — the number that decides
	// whether a model will fit.
	MemFreeMB uint64 `json:"mem_free_mb,omitempty"`
	// UtilPercent is how busy the card is right now.
	UtilPercent float64 `json:"util_percent,omitempty"`
}

// Free reports the usable memory in MB, falling back to total when the free
// figure was not available.
func (g GPU) Free() uint64 {
	if g.MemFreeMB > 0 {
		return g.MemFreeMB
	}
	return g.MemTotalMB
}

// DetectGPUs looks for accelerators.
//
// Each vendor is asked with its own tool rather than by reading sysfs or PCI
// IDs: the vendor tool is the only thing that reports *free* memory, and free
// memory is the number that decides whether a model loads or dies. A missing
// tool means no GPUs are reported, which is correct — a card whose driver
// stack is not installed cannot run anything either.
func DetectGPUs() []GPU {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if g := nvidiaGPUs(ctx); len(g) > 0 {
		return g
	}
	if g := amdGPUs(ctx); len(g) > 0 {
		return g
	}
	if runtime.GOOS == "darwin" {
		return appleGPUs(ctx)
	}
	return nil
}

func nvidiaGPUs(ctx context.Context) []GPU {
	out, err := run(ctx, "nvidia-smi",
		"--query-gpu=name,memory.total,memory.free,utilization.gpu",
		"--format=csv,noheader,nounits")
	if err != nil {
		return nil
	}
	var gpus []GPU
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		f := splitCSV(sc.Text())
		if len(f) < 2 {
			continue
		}
		g := GPU{Name: f[0], Vendor: "nvidia", MemTotalMB: num(f[1])}
		if len(f) > 2 {
			g.MemFreeMB = num(f[2])
		}
		if len(f) > 3 {
			g.UtilPercent, _ = strconv.ParseFloat(f[3], 64)
		}
		gpus = append(gpus, g)
	}
	return gpus
}

func amdGPUs(ctx context.Context) []GPU {
	// rocm-smi's output format has changed between releases; the --csv form
	// is the stable one. Failure here is expected on most machines.
	out, err := run(ctx, "rocm-smi", "--showproductname", "--showmeminfo", "vram", "--csv")
	if err != nil {
		return nil
	}
	var gpus []GPU
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "card") {
			continue
		}
		f := splitCSV(line)
		g := GPU{Vendor: "amd", Name: "AMD GPU"}
		for _, v := range f[1:] {
			if n := num(v); n > 1024*1024 {
				// rocm reports VRAM in bytes.
				g.MemTotalMB = n / (1024 * 1024)
			} else if v != "" && !isNumeric(v) {
				g.Name = v
			}
		}
		gpus = append(gpus, g)
	}
	return gpus
}

func appleGPUs(ctx context.Context) []GPU {
	// Apple silicon shares one pool between CPU and GPU, so there is no
	// separate VRAM figure to report. The name is still worth having: it is
	// what tells you a machine can run a large model at all.
	out, err := run(ctx, "sysctl", "-n", "machdep.cpu.brand_string")
	if err != nil {
		return nil
	}
	name := strings.TrimSpace(out)
	if !strings.Contains(name, "Apple") {
		return nil
	}
	return []GPU{{Name: name + " (unified memory)", Vendor: "apple"}}
}

func run(ctx context.Context, bin string, args ...string) (string, error) {
	path, err := exec.LookPath(bin)
	if err != nil {
		return "", err
	}
	out, err := exec.CommandContext(ctx, path, args...).Output()
	return string(out), err
}

func splitCSV(line string) []string {
	f := strings.Split(line, ",")
	for i := range f {
		f[i] = strings.TrimSpace(f[i])
	}
	return f
}

func num(s string) uint64 {
	f := strings.Fields(s)
	if len(f) == 0 {
		return 0
	}
	n, _ := strconv.ParseUint(f[0], 10, 64)
	return n
}

func isNumeric(s string) bool {
	_, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return err == nil
}
