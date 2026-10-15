// Package paths resolves the per-OS locations LocNet writes to.
//
// Every path here is machine-scoped, not user-scoped: locnetd runs as a system
// service and its state must survive user logout and be readable by the
// service account, not by whoever happened to run the installer.
package paths

import (
	"os"
	"path/filepath"
	"runtime"
)

// StateDir is where locnetd keeps node.json (its keys and cached netmap).
func StateDir() string {
	if d := os.Getenv("LOCNET_STATE_DIR"); d != "" {
		return d
	}
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(programData(), "LocNet")
	case "darwin":
		return "/Library/Application Support/LocNet"
	default:
		return "/var/lib/locnet"
	}
}

// HubStateDir is where locnet-hub keeps the network database.
func HubStateDir() string {
	if d := os.Getenv("LOCNET_HUB_STATE_DIR"); d != "" {
		return d
	}
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(programData(), "LocNet", "hub")
	case "darwin":
		return "/Library/Application Support/LocNet/hub"
	default:
		return "/var/lib/locnet-hub"
	}
}

// ControlSocket is the address the CLI uses to reach locnetd. On Windows this
// is a named pipe; elsewhere a Unix socket.
func ControlSocket() string {
	if s := os.Getenv("LOCNET_SOCKET"); s != "" {
		return s
	}
	switch runtime.GOOS {
	case "windows":
		return `\\.\pipe\locnetd`
	case "darwin":
		return "/var/run/locnetd.sock"
	default:
		return "/run/locnet/locnetd.sock"
	}
}

// LogDir is where the service writes logs when it is not attached to a
// journal.
func LogDir() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(programData(), "LocNet", "logs")
	case "darwin":
		return "/var/log/locnet"
	default:
		return "/var/log/locnet"
	}
}

// DefaultInterface is the tunnel interface name for this platform.
//
// macOS insists on utunN and will pick N itself — but the way you ask for that
// is the literal string "utun", not an empty string. wireguard-go's darwin
// CreateTUN special-cases exactly "utun" and otherwise requires the name to
// scan as "utun%d"; an empty name matches neither, and fails with
// "Interface name must be utun[0-9]*" alongside a misleading hint about
// running as root.
func DefaultInterface() string {
	switch runtime.GOOS {
	case "darwin":
		return "utun"
	case "windows":
		return "LocNet"
	default:
		return "locnet0"
	}
}

func programData() string {
	if d := os.Getenv("ProgramData"); d != "" {
		return d
	}
	return `C:\ProgramData`
}

// EnsureDir creates dir with restrictive permissions if it does not exist.
// State directories hold private keys, so 0700 rather than the usual 0755.
func EnsureDir(dir string) error {
	return os.MkdirAll(dir, 0o700)
}
