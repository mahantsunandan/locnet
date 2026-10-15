package resource

import (
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

// CollectStats describes this machine.
//
// macOS reports less than Linux here. Free memory in particular is not a
// single number the kernel will hand over — it lives in the Mach VM statistics
// and means something different from the Linux figure. Rather than approximate
// it, MemFreeMB is left at zero and the console hides the field.
func CollectStats() Stats {
	s := Stats{CPUs: runtime.NumCPU()}

	if total, err := unix.SysctlUint64("hw.memsize"); err == nil {
		s.MemTotalMB = total / (1 << 20)
	}

	if boot, err := unix.SysctlTimeval("kern.boottime"); err == nil {
		up := time.Since(time.Unix(boot.Sec, int64(boot.Usec)*1000))
		if up > 0 {
			s.UptimeHours = uint64(up.Hours())
		}
	}

	var fs unix.Statfs_t
	if err := unix.Statfs("/", &fs); err == nil {
		const gb = 1 << 30
		bs := uint64(fs.Bsize)
		s.DiskTotalGB = fs.Blocks * bs / gb
		s.DiskFreeGB = fs.Bavail * bs / gb
	}
	return s
}
