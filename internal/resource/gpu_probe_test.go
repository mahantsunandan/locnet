package resource

import "testing"

func TestProbeThisMachine(t *testing.T) {
	g := DetectGPUs()
	s := CollectStats()
	s.GPUs = g
	t.Logf("gpus=%d summary=%q freeVRAM=%dMB cpus=%d mem=%dMB",
		len(g), s.GPUSummary(), s.GPUMemFreeMB(), s.CPUs, s.MemTotalMB)
	for _, x := range g {
		t.Logf("  %s vendor=%s total=%d free=%d util=%.0f", x.Name, x.Vendor, x.MemTotalMB, x.MemFreeMB, x.UtilPercent)
	}
}
