package placement

import (
	"strings"
	"testing"

	"github.com/mahantsunandan/locnet/internal/resource"
)

func machine(name string, cpus int, load float64, freeMB uint64, gpus ...resource.GPU) Candidate {
	return Candidate{
		Name: name, Host: "10.99.0.1", Online: true,
		Stats: resource.Stats{
			CPUs: cpus, LoadPercent: load,
			MemTotalMB: freeMB * 2, MemFreeMB: freeMB,
			DiskTotalGB: 500, DiskFreeGB: 400,
			GPUs: gpus,
		},
	}
}

func TestBusyBigMachineLosesToIdleSmallOne(t *testing.T) {
	// The whole point of ranking on free capacity: a 64-core machine at 95%
	// has three usable cores, and a job sent there finishes after one sent to
	// an idle eight-core box.
	busy := machine("big", 64, 95, 8000)
	idle := machine("small", 8, 5, 8000)

	best, err := Best([]Candidate{busy, idle}, Need{})
	if err != nil {
		t.Fatal(err)
	}
	if best.Name != "small" {
		t.Errorf("chose %q; a 64-core machine at 95%% load has ~3 free cores", best.Name)
	}
}

func TestGPUJobNeverGoesToAMachineWithoutOne(t *testing.T) {
	huge := machine("cpu-monster", 128, 0, 500000)
	tiny := machine("gpu-laptop", 4, 50, 4000,
		resource.GPU{Name: "RTX 4090", Vendor: "nvidia", MemTotalMB: 24576, MemFreeMB: 24000})

	best, err := Best([]Candidate{huge, tiny}, Need{GPU: true})
	if err != nil {
		t.Fatal(err)
	}
	if best.Name != "gpu-laptop" {
		t.Errorf("a CUDA job went to %q, which has no GPU", best.Name)
	}
}

func TestNotEnoughVRAMIsAnExclusionNotALowScore(t *testing.T) {
	// Sending a 20 GB model to an 8 GB card does not run slowly; it fails.
	small := machine("has-8gb", 16, 0, 32000,
		resource.GPU{Name: "RTX 3070", MemTotalMB: 8192, MemFreeMB: 8000})

	_, err := Best([]Candidate{small}, Need{VRAMMB: 20 * 1024})
	if err == nil {
		t.Fatal("a job needing 20 GB of VRAM was placed on an 8 GB card")
	}
	if !strings.Contains(err.Error(), "has-8gb") || !strings.Contains(err.Error(), "free") {
		t.Errorf("the refusal should name the machine and what it lacked, got: %v", err)
	}
}

func TestLargestCardDecidesRatherThanTheSum(t *testing.T) {
	// Two 8 GB cards do not hold a 12 GB model without work most software
	// will not do, so summing them would place jobs that then fail.
	twoSmall := machine("dual", 16, 0, 32000,
		resource.GPU{Name: "A", MemTotalMB: 8192, MemFreeMB: 8000},
		resource.GPU{Name: "B", MemTotalMB: 8192, MemFreeMB: 8000})

	if got := twoSmall.Stats.GPUMemFreeMB(); got != 8000 {
		t.Errorf("free VRAM = %d, want the largest single card (8000)", got)
	}
	if _, err := Best([]Candidate{twoSmall}, Need{VRAMMB: 12 * 1024}); err == nil {
		t.Error("two 8 GB cards were treated as one 16 GB card")
	}
}

func TestOfflineMachinesAreExcluded(t *testing.T) {
	down := machine("down", 64, 0, 100000)
	down.Online = false
	up := machine("up", 4, 0, 4000)

	best, err := Best([]Candidate{down, up}, Need{})
	if err != nil {
		t.Fatal(err)
	}
	if best.Name != "up" {
		t.Errorf("chose the offline machine %q", best.Name)
	}
}

func TestThisMachineLosesATie(t *testing.T) {
	me := machine("mine", 8, 10, 8000)
	me.Self = true
	other := machine("other", 8, 10, 8000)

	best, err := Best([]Candidate{me, other}, Need{})
	if err != nil {
		t.Fatal(err)
	}
	// Identical machines: prefer moving the work away, since that is why
	// someone reached for this in the first place.
	if best.Name != "other" {
		t.Errorf("chose %q; an exact tie should move work off this machine", best.Name)
	}
}

func TestThisMachineStillWinsWhenItIsActuallyBetter(t *testing.T) {
	me := machine("mine", 32, 0, 64000)
	me.Self = true
	other := machine("other", 2, 90, 1000)

	best, err := Best([]Candidate{me, other}, Need{})
	if err != nil {
		t.Fatal(err)
	}
	if best.Name != "mine" {
		t.Errorf("chose %q; sending work to a worse machine helps nobody", best.Name)
	}
}

func TestRefusalExplainsEveryMachine(t *testing.T) {
	_, err := Best([]Candidate{
		machine("a", 2, 0, 1000),
		machine("b", 4, 0, 2000),
	}, Need{CPUs: 64})
	if err == nil {
		t.Fatal("expected a refusal")
	}
	for _, want := range []string{"a", "b", "needs 64"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal should mention %q, got: %v", want, err)
		}
	}
}

func TestRankReturnsUnsuitableMachinesLast(t *testing.T) {
	ranked := Rank([]Candidate{
		machine("no-gpu", 64, 0, 100000),
		machine("gpu", 8, 0, 8000, resource.GPU{Name: "card", MemTotalMB: 16384, MemFreeMB: 16000}),
	}, Need{GPU: true})

	if len(ranked) != 2 {
		t.Fatalf("got %d rows, want 2", len(ranked))
	}
	if ranked[0].Name != "gpu" || ranked[0].Why != "" {
		t.Errorf("first row should be the usable machine, got %+v", ranked[0])
	}
	if ranked[1].Why == "" {
		t.Error("the excluded machine should carry a reason")
	}
}

func TestUnmeasuredFieldsDoNotExcludeAMachine(t *testing.T) {
	// A platform whose collector could not read free memory reports zero.
	// Treating that as "no memory" would silently remove every Windows or
	// BSD machine from the pool.
	unknown := Candidate{Name: "unknown", Online: true,
		Stats: resource.Stats{CPUs: 8}}

	if fits, why := (Need{MemMB: 4096}).Fits(unknown); !fits {
		t.Errorf("a machine that did not report memory was excluded: %s", why)
	}
}
