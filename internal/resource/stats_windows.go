package resource

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// These two are resolved lazily rather than imported from x/sys/windows,
// which does not wrap either of them. Declaring them here keeps the dependency
// at the version the rest of the project already uses instead of chasing one
// that happens to export a particular helper.
var (
	kernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	procGetTickCount64       = kernel32.NewProc("GetTickCount64")
	procGlobalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
)

// memoryStatusEx mirrors the Win32 MEMORYSTATUSEX structure. Field order and
// widths are load-bearing: the kernel writes into this layout directly.
type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

// CollectStats describes this machine.
//
// Windows reports no load average. CPU utilisation would mean sampling
// performance counters over an interval, which is more machinery than a status
// line justifies, so LoadPercent is left at zero.
func CollectStats() Stats {
	s := Stats{CPUs: runtime.NumCPU()}

	var mem memoryStatusEx
	mem.Length = uint32(unsafe.Sizeof(mem))
	if ok, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&mem))); ok != 0 {
		const mb = 1 << 20
		s.MemTotalMB = mem.TotalPhys / mb
		s.MemFreeMB = mem.AvailPhys / mb
	}

	if ticks, _, _ := procGetTickCount64.Call(); ticks > 0 {
		s.UptimeHours = uint64(ticks) / (1000 * 60 * 60)
	}

	// The system drive is the one worth reporting; a machine with a full C:
	// is in trouble regardless of what else is mounted.
	root, err := windows.UTF16PtrFromString(systemDrive())
	if err == nil {
		var freeToCaller, total, totalFree uint64
		if err := windows.GetDiskFreeSpaceEx(root, &freeToCaller, &total, &totalFree); err == nil {
			const gb = 1 << 30
			s.DiskTotalGB = total / gb
			s.DiskFreeGB = freeToCaller / gb
		}
	}
	return s
}

func systemDrive() string {
	if d, err := windows.GetSystemDirectory(); err == nil && len(d) >= 2 {
		return d[:2] + `\`
	}
	return `C:\`
}
