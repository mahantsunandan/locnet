package deskserve

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Starting the helper at login is the difference between "screen sharing
// works" and "screen sharing works if somebody remembered". It has to be
// arranged per user rather than per machine, because the whole point of the
// helper is that it lives inside a desktop session — so this writes into the
// user's own configuration and needs no administrator.

// AutostartPath is where the login entry for this user lives.
func AutostartPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	switch runtime.GOOS {
	case "linux":
		return filepath.Join(home, ".config", "systemd", "user", "locnet-desktop.service"), nil
	case "darwin":
		return filepath.Join(home, "Library", "LaunchAgents", "net.locnet.desktop.plist"), nil
	case "windows":
		return filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows",
			"Start Menu", "Programs", "Startup", "locnet-desktop.cmd"), nil
	}
	return "", fmt.Errorf("no login-start mechanism is known for %s", runtime.GOOS)
}

// EnableAutostart arranges for `locnet desktop serve` to run at every login,
// and starts it now. Any extra arguments are passed to the helper, so a
// machine that needs the VNC bridge keeps needing it after a reboot without
// anyone hand-editing a unit file.
//
// It returns the path it wrote and any command it ran.
func EnableAutostart(args ...string) (path string, ran []string, err error) {
	exe, err := os.Executable()
	if err != nil {
		return "", nil, err
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return "", nil, err
	}
	path, err = AutostartPath()
	if err != nil {
		return "", nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", nil, err
	}

	quoted := ""
	for _, a := range args {
		quoted += " " + a
	}

	switch runtime.GOOS {
	case "linux":
		unit := `[Unit]
Description=LocNet desktop session helper
Documentation=https://github.com/mahantsunandan/locnet
After=graphical-session.target
PartOf=graphical-session.target

[Service]
ExecStart=` + exe + ` desktop serve` + quoted + `
Restart=on-failure
RestartSec=5

[Install]
WantedBy=graphical-session.target
`
		if err := os.WriteFile(path, []byte(unit), 0o644); err != nil {
			return "", nil, err
		}
		// A user unit is not picked up until systemd is told to look again.
		for _, args := range [][]string{
			{"systemctl", "--user", "daemon-reload"},
			{"systemctl", "--user", "enable", "--now", "locnet-desktop.service"},
		} {
			cmd := exec.Command(args[0], args[1:]...)
			if out, err := cmd.CombinedOutput(); err != nil {
				return path, ran, fmt.Errorf("%s: %v: %s",
					strings.Join(args, " "), err, strings.TrimSpace(string(out)))
			}
			ran = append(ran, strings.Join(args, " "))
		}

	case "darwin":
		plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>net.locnet.desktop</string>
  <key>ProgramArguments</key>
  <array>
    <string>` + exe + `</string>
    <string>desktop</string>
    <string>serve</string>` + plistArgs(args) + `
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
`
		if err := os.WriteFile(path, []byte(plist), 0o644); err != nil {
			return "", nil, err
		}
		args := []string{"launchctl", "load", "-w", path}
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			return path, ran, fmt.Errorf("%s: %v: %s",
				strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		ran = append(ran, strings.Join(args, " "))

	case "windows":
		// A .cmd in the Startup folder rather than a shortcut: making a .lnk
		// needs COM, and this needs nothing. `start ""` returns immediately
		// so the console window closes instead of sitting on the desktop.
		script := "@echo off\r\nstart \"\" /min \"" + exe + "\" desktop serve" + quoted + "\r\n"
		if err := os.WriteFile(path, []byte(script), 0o644); err != nil {
			return "", nil, err
		}

	default:
		return "", nil, fmt.Errorf("no login-start mechanism is known for %s", runtime.GOOS)
	}
	return path, ran, nil
}

// DisableAutostart undoes it.
func DisableAutostart() (string, error) {
	path, err := AutostartPath()
	if err != nil {
		return "", err
	}
	switch runtime.GOOS {
	case "linux":
		_ = exec.Command("systemctl", "--user", "disable", "--now", "locnet-desktop.service").Run()
	case "darwin":
		_ = exec.Command("launchctl", "unload", "-w", path).Run()
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return path, err
	}
	return path, nil
}

// plistArgs renders extra arguments as launchd array elements.
func plistArgs(args []string) string {
	out := ""
	for _, a := range args {
		out += "\n    <string>" + xmlEscape(a) + "</string>"
	}
	return out
}

// xmlEscape is enough for a file path and a flag name. Anything needing more
// than this does not belong on a command line either.
func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}
