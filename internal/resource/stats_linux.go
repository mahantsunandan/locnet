package resource

import (
	"os"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// CollectStats describes this machine. Anything it cannot measure is left at
// zero rather than guessed at.
func CollectStats() Stats {
	s := Stats{CPUs: runtime.NumCPU()}

	// Load average is per-core-hours of demand, so it only means anything
	// once divided by the core count. A load of 4 is idle on a 16-core box
	// and desperate on a single-core one.
	if raw, err := os.ReadFile("/proc/loadavg"); err == nil {
		if f := strings.Fields(string(raw)); len(f) > 0 && s.CPUs > 0 {
			if v, err := strconv.ParseFloat(f[0], 64); err == nil {
				s.LoadPercent = v / float64(s.CPUs) * 100
			}
		}
	}

	if raw, err := os.ReadFile("/proc/meminfo"); err == nil {
		fields := parseMeminfo(string(raw))
		s.MemTotalMB = fields["MemTotal"] / 1024
		// MemAvailable, not MemFree: the kernel counts reclaimable cache as
		// used, and MemFree on a healthy machine is alarmingly small for no
		// reason.
		s.MemFreeMB = fields["MemAvailable"] / 1024
	}

	if raw, err := os.ReadFile("/proc/uptime"); err == nil {
		if f := strings.Fields(string(raw)); len(f) > 0 {
			if v, err := strconv.ParseFloat(f[0], 64); err == nil {
				s.UptimeHours = uint64(v / 3600)
			}
		}
	}

	var fs unix.Statfs_t
	if err := unix.Statfs("/", &fs); err == nil {
		const gb = 1 << 30
		bs := uint64(fs.Bsize)
		s.DiskTotalGB = fs.Blocks * bs / gb
		// Bavail, not Bfree: Bfree includes blocks reserved for root, which
		// an ordinary process cannot use.
		s.DiskFreeGB = fs.Bavail * bs / gb
	}
	return s
}

// parseMeminfo pulls the kB values out of /proc/meminfo.
func parseMeminfo(text string) map[string]uint64 {
	out := make(map[string]uint64, 4)
	for _, line := range strings.Split(text, "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			continue
		}
		if v, err := strconv.ParseUint(f[0], 10, 64); err == nil {
			out[name] = v
		}
	}
	return out
}
