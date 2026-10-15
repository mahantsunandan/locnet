package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/mahantsunandan/locnet/internal/ipc"
	"github.com/mahantsunandan/locnet/internal/resource"
	"github.com/mahantsunandan/locnet/internal/setup"
)

const setupUsage = `Usage:
  locnet setup                 show what this machine still needs
  locnet setup -install        install it, after showing you the commands
  locnet setup rdp             give this desktop's RDP server a login, so peers
                               can see its real screen (run without sudo)

Flags:
  -install   actually make the changes
  -yes       do not ask for confirmation (for unattended provisioning)

This installs two things and only two: an SSH server and a screen-sharing
server, and only if they are missing. That is everything a machine needs in
order to be reached. What you connect *with* is your own choice — Remmina, a
VNC viewer, your terminal — and LocNet will not install a client for you.

Nothing is changed without showing you the exact commands first.`

func cmdSetup(args []string) error {
	if len(args) > 0 && args[0] == "rdp" {
		replace := len(args) > 1 && (args[1] == "-new" || args[1] == "--new")
		return setupRDP(replace)
	}
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	install := fs.Bool("install", false, "make the changes rather than just listing them")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	if err := fs.Parse(args); err != nil {
		return err
	}

	steps, err := setup.Plan()
	if err != nil {
		return err
	}

	fmt.Printf("\nLocNet setup — %s\n\n", setup.Platform())
	fmt.Print(setup.Describe(steps))
	fmt.Print(rdpNote())

	pending := setup.Pending(steps)
	if len(pending) == 0 {
		fmt.Println()
		return nil
	}

	if !*install {
		fmt.Printf("\n  %d step(s) would run. Apply them with:\n\n      sudo locnet setup -install\n\n", len(pending))
		return nil
	}

	if !isPrivileged() {
		return errors.New("installing packages and enabling services needs administrator privileges.\n" +
			privilegeHint())
	}

	if !*yes {
		fmt.Printf("\n  %d step(s) will run as shown above.\n", len(pending))
		fmt.Print("  Type 'yes' to continue: ")
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(answer)) != "yes" {
			return errors.New("cancelled — nothing was changed")
		}
	}

	fmt.Println()
	logf := func(format string, a ...any) { fmt.Printf(format+"\n", a...) }
	var failed []string
	for _, s := range pending {
		fmt.Printf("  %s\n", s.Name)
		if err := setup.Run(s, logf); err != nil {
			fmt.Printf("    ✗ %v\n", err)
			failed = append(failed, s.Name)
			continue
		}
		fmt.Printf("    ✓ done\n")
	}

	fmt.Println()
	if len(failed) > 0 {
		// Not a hard failure: a partial setup is still progress, and the
		// operator needs to see what else worked.
		fmt.Printf("  %d step(s) failed: %s\n", len(failed), strings.Join(failed, ", "))
		fmt.Println("  Run the commands above by hand to see the full output.")
		return errors.New("setup did not finish")
	}

	if runtime.GOOS == "linux" || runtime.GOOS == "windows" {
		publishScreenShare()
	}

	fmt.Println("  Done. Check what is now visible to peers with:  locnet status")
	fmt.Println("  Services can take a minute to appear — the scan runs every 5 minutes.")
	return nil
}

// screenSharePort is where a peer reaches this machine's screen, always. The
// display number behind it varies from machine to machine; this does not, so
// `locnet vnc <peer>` needs to know nothing about the far machine's X server.
const screenSharePort = 5900

// publishScreenShare puts the local VNC server on the overlay.
//
// The server itself listens on loopback, which is what makes it safe and also
// what makes it useless on its own: a peer dialling this machine's overlay
// address finds nothing, and reports — accurately, and to everyone's
// confusion — that there is no VNC here. A port share closes that gap, and it
// is the right way round: the forwarder checks the peer's identity against an
// access list before it connects anything, so the door is guarded by
// WireGuard's key check rather than by a VNC password somebody has to keep.
func publishScreenShare() {
	// Only a server that answers is worth publishing. A share in front of
	// nothing is worse than no share: peers see "vnc" and get a dead socket.
	if !screenServerUp() {
		fmt.Printf("\n  No screen server is answering on 127.0.0.1:%d, so nothing was published.\n", setup.VNCPort())
		return
	}
	c, err := ipc.Dial()
	if err != nil {
		// The daemon not running is not a setup failure. The packages are
		// installed either way; this is the one step that needs locnetd.
		fmt.Printf("\n  Screen sharing is running locally, but locnetd is not reachable,\n"+
			"  so peers cannot see it yet (%v). Once the daemon is up:\n"+
			"      locnet share add screen :%d -on %d -allow \"*\"\n", err, setup.VNCPort(), screenSharePort)
		return
	}

	// The overlay port is fixed at 5900 and the local one is whatever display
	// was free. They used to be the same number, which was wrong twice over.
	//
	// It deadlocked: the share binds the overlay address on that port, and
	// TigerVNC's own "is this display free" check binds the wildcard — so
	// LocNet's share made LocNet's VNC server unable to restart, with setup
	// waiting for a display that its own daemon was holding.
	//
	// And it leaked an irrelevant local detail to every peer. Which display a
	// machine happened to pick is nobody else's business; peers want one
	// address for "this machine's screen", and now they have one.
	sh := resource.Share{
		Name:        "screen",
		Kind:        resource.KindPort,
		Target:      fmt.Sprintf("127.0.0.1:%d", setup.VNCPort()),
		Port:        screenSharePort,
		Allow:       []string{"*"},
		Description: "this machine's VNC desktop",
	}
	if runtime.GOOS == "windows" {
		sh.Description = "this machine's screen (VNC)"
	}
	if err := c.Post("/share/add", sh, nil); err != nil {
		fmt.Printf("\n  Could not publish the screen to peers: %v\n", err)
		return
	}
	fmt.Printf("\n  Published as the share \"screen\" on overlay port %d (local port %d).\n", screenSharePort, setup.VNCPort())
	fmt.Println("  Every member of this network may now watch this desktop. To narrow that:")
	fmt.Printf("      locnet share add screen :%d -on %d -allow <peer>,<peer>\n", setup.VNCPort(), screenSharePort)
	fmt.Println("  To stop sharing entirely:  locnet share remove screen")
}

// isPrivileged reports whether this process can install software.
func isPrivileged() bool {
	if runtime.GOOS == "windows" {
		// A reliable check needs a token query. Attempting a privileged
		// registry read is a cheap proxy and fails safe.
		return canWriteSystemRegistry()
	}
	return os.Geteuid() == 0
}

func privilegeHint() string {
	if runtime.GOOS == "windows" {
		return "  Right-click PowerShell and choose “Run as Administrator”, then run it again."
	}
	return "  Run it again with: sudo locnet setup -install"
}

// screenServerUp reports whether the local VNC server is answering.
func screenServerUp() bool {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", setup.VNCPort()), 2*time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}
