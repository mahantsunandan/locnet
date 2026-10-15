package setup

// distro is unused on macOS but keeps the shared code simple.
type distro struct{ id, name string }

func detectDistro() distro { return distro{id: "darwin", name: "macOS"} }

func planFor() ([]Step, error) {
	return []Step{
		// Remote Login is macOS's SSH server. `systemsetup` is the supported
		// way to toggle it and needs root.
		{
			Name:     "SSH server (Remote Login)",
			Why:      "so `locnet ssh <this machine>` works from a peer",
			Done:     remoteLoginOn(),
			Detail:   "already on",
			Commands: [][]string{{"systemsetup", "-setremotelogin", "on"}},
		},
		// Screen Sharing is macOS's built-in VNC server. Enabling it from
		// the command line is possible but the supported path also grants
		// access to specific users, which is a decision worth making
		// explicitly rather than having a tool make it.
		{
			Name:   "Screen Sharing (VNC server)",
			Why:    "so a peer's VNC client can show this machine's screen",
			Done:   screenSharingOn(),
			Detail: "already on",
			Manual: "Turn it on by hand:\n" +
				"  System Settings → General → Sharing → Screen Sharing\n" +
				"Choose which users may connect while you are there. LocNet does\n" +
				"not do this for you because the answer is not the same on every\n" +
				"machine, and the wrong answer exposes a desktop.",
		},
	}, nil
}

func remoteLoginOn() bool {
	out, ok := runOutput("systemsetup", "-getremotelogin")
	return ok && containsFold(out, "On")
}

func screenSharingOn() bool {
	// The launchd job is present and loaded when Screen Sharing is enabled.
	out, ok := runOutput("launchctl", "list")
	return ok && containsFold(out, "com.apple.screensharing")
}

func hasApp(path string) bool { return dirExists(path) }

// vncDisplay is fixed here. Choosing a free X display is a Linux problem: the
// screen server on this platform is the one the system ships, listening where
// the system puts it, and LocNet does not get to move it.
func vncDisplay() int { return 1 }
