//go:build !windows

package launch

import (
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
)

// deescalate makes a client program run as the person who typed the command
// rather than as root.
//
// This matters more than it sounds. `sudo locnet ssh othermachine` run as root
// tries to log in as *root@othermachine*, which is almost never what anyone
// wanted and fails confusingly. A remote-desktop client started as root reads
// root's configuration and often cannot reach the logged-in graphical session
// at all.
//
// So when the process is root but SUDO_USER says who is really driving, the
// client is started as that user, with the handful of environment variables a
// graphical program needs to find the session it belongs to.
func deescalate(cmd *exec.Cmd) {
	if os.Geteuid() != 0 {
		return
	}
	name := os.Getenv("SUDO_USER")
	if name == "" || name == "root" {
		return
	}
	u, err := user.Lookup(name)
	if err != nil {
		return
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil || uid == 0 {
		return
	}

	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Credential = &syscall.Credential{
		Uid: uint32(uid),
		Gid: uint32(gid),
	}

	env := []string{
		"HOME=" + u.HomeDir,
		"USER=" + u.Username,
		"LOGNAME=" + u.Username,
		"PATH=" + envOr("PATH", "/usr/local/bin:/usr/bin:/bin"),
	}
	// Without these a graphical client cannot find the display it should
	// open on. sudo strips some of them, so fall back to the conventional
	// location for the user's runtime directory.
	for _, k := range []string{"DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "TERM", "LANG"} {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	if os.Getenv("XDG_RUNTIME_DIR") == "" {
		env = append(env, "XDG_RUNTIME_DIR=/run/user/"+u.Uid)
	}
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		// A very common case under sudo. :0 is the near-universal default
		// and costs nothing if wrong — the client says it cannot open a
		// display, which is a far clearer error than silently misbehaving.
		env = append(env, "DISPLAY=:0")
	}
	cmd.Env = env

	if cmd.Dir == "" {
		cmd.Dir = u.HomeDir
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// InvokingUser is the person who ran the command, seeing through sudo. Used to
// pick an SSH username.
func InvokingUser() string {
	if name := os.Getenv("SUDO_USER"); name != "" && name != "root" {
		return name
	}
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}
