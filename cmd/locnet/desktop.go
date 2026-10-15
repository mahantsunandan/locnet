package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"path/filepath"

	"github.com/mahantsunandan/locnet/internal/deskserve"
	"github.com/mahantsunandan/locnet/internal/ipc"
	"github.com/mahantsunandan/locnet/internal/node"
	"github.com/mahantsunandan/locnet/internal/resource"
)

const desktopUsage = `Usage:
  locnet desktop                  show whether this machine shares its screen
  locnet desktop share [flags]    let named peers watch this screen
  locnet desktop stop             stop sharing
  locnet desktop serve            run the session helper in the foreground
  locnet desktop autostart        start the helper at every login
  locnet desktop autostart off

Flags for serve and autostart:
  -vnc <addr>           bridge this VNC server when the platform cannot be
                        captured directly. Default: look on loopback. "off"
                        disables the fallback
  -vnc-password-file    file holding that server's password

Flags for share:
  -allow    comma-separated peer names, or "*" (required)
  -control  let those peers use the keyboard and mouse, not only watch
  -label    free text shown to peers, e.g. "the lab PC"
  -fps      frame rate cap, 1 to 30 (default 12)
  -quality  JPEG quality for changed tiles, 1 to 100 (default 62)

This is LocNet's own screen-sharing protocol, and nothing ships a viewer for
it any more: the in-browser one has been removed. For everyday remote desktop
use "locnet vnc <peer>" or "locnet rdp <peer>", which open the client you
already have, and "locnet setup -install" to put a screen server on a machine
that has none.

Two things have to be true for a peer to see anything here. This machine must
be sharing — that is the setting above, which only someone at this machine can
change. And somebody must be logged in here, with the session helper running
in their session, because a service cannot see a desktop.`

func cmdDesktop(args []string) error {
	pos, flags := splitArgs(args)
	sub := ""
	if len(pos) > 0 {
		sub = pos[0]
	}

	switch sub {
	case "", "show":
		return desktopShow()
	case "serve":
		return desktopServe(flags)
	case "autostart":
		off := len(pos) > 1 && (pos[1] == "off" || pos[1] == "disable")
		return desktopAutostart(off, flags)
	case "stop", "disable":
		c, err := ipc.Dial()
		if err != nil {
			return err
		}
		if err := c.Post("/desktop", resource.DesktopConfig{}, nil); err != nil {
			return err
		}
		fmt.Println("This screen is no longer shared.")
		return nil
	case "share", "enable":
		return desktopShare(flags)
	default:
		return fmt.Errorf("unknown desktop command %q\n\n%s", sub, desktopUsage)
	}
}

func desktopShow() error {
	c, err := ipc.Dial()
	if err != nil {
		return err
	}
	var out node.DesktopJSON
	if err := c.Get("/desktop", &out); err != nil {
		return err
	}

	if !out.Config.Enabled {
		fmt.Println("This screen is not shared. Nobody can watch it.")
		fmt.Println("\n" + desktopUsage)
		return nil
	}
	mode := "watch only"
	if out.Config.Control {
		mode = "watch and control"
	}
	fmt.Printf("  shared with           %s\n", out.Config.AllowText())
	fmt.Printf("  they may              %s\n", mode)
	fmt.Printf("  frame rate            up to %d per second\n", out.Config.FPS())
	fmt.Printf("  quality               %d\n", out.Config.JPEGQuality())
	if out.Config.Label != "" {
		fmt.Printf("  advertised as         %s\n", out.Config.Label)
	}

	// The second half of the answer: whether there is anything to watch
	// right now. These fail independently and for different reasons, so
	// they are reported separately rather than as one verdict.
	switch {
	case out.Status.Error != "":
		fmt.Printf("\n  session helper        attached, but it cannot capture:\n    %s\n",
			out.Status.Error)
	case out.Status.Ready:
		input := "cannot be driven from here"
		if out.Status.Control {
			input = "keyboard and mouse available"
		}
		fmt.Printf("\n  session helper        attached, %dx%d, %s\n",
			out.Status.Width, out.Status.Height, input)
		if out.Status.Via != "" {
			fmt.Printf("  pixels come from      %s\n", out.Status.Via)
		}
	default:
		fmt.Printf("\n  session helper        not running — nobody is logged in, or\n" +
			"                        `locnet desktop serve` is not started in their session\n")
	}
	return nil
}

func desktopShare(args []string) error {
	fs := flag.NewFlagSet("desktop share", flag.ExitOnError)
	allow := fs.String("allow", "", `peers that may watch, comma-separated, or "*"`)
	control := fs.Bool("control", false, "let them use the keyboard and mouse")
	label := fs.String("label", "", "free text shown to peers")
	fps := fs.Int("fps", 0, "frame rate cap, 1 to 30")
	quality := fs.Int("quality", 0, "JPEG quality, 1 to 100")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg := resource.DesktopConfig{
		Enabled: true, Control: *control, Label: *label,
		MaxFPS: *fps, Quality: *quality,
	}
	for _, a := range strings.Split(*allow, ",") {
		if a = strings.TrimSpace(a); a != "" {
			cfg.Allow = append(cfg.Allow, a)
		}
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	c, err := ipc.Dial()
	if err != nil {
		return err
	}
	var out node.DesktopJSON
	if err := c.Post("/desktop", cfg, &out); err != nil {
		return err
	}

	if cfg.Control {
		fmt.Printf("%s can now watch this screen and use it.\n", cfg.AllowText())
	} else {
		fmt.Printf("%s can now watch this screen. They cannot type or click.\n", cfg.AllowText())
	}
	if !out.Status.Ready {
		fmt.Println("\nNothing is being captured yet. The session helper runs in the")
		fmt.Println("logged-in desktop session, not in the service:")
		fmt.Println("    locnet desktop autostart      (starts it now, and at every login)")
	}
	return nil
}

// desktopServe runs the capture helper in the foreground.
func desktopServe(args []string) error {
	fs := flag.NewFlagSet("desktop serve", flag.ExitOnError)
	quiet := fs.Bool("quiet", false, "say nothing unless something goes wrong")
	vnc := fs.String("vnc", "", `VNC server to bridge when this platform cannot be captured ("off" to disable)`)
	pwFile := fs.String("vnc-password-file", "", "file holding the VNC server's password")
	if err := fs.Parse(args); err != nil {
		return err
	}

	opts, err := desktopOptions(*vnc, *pwFile)
	if err != nil {
		return err
	}

	logf := func(format string, a ...any) { fmt.Printf(format+"\n", a...) }
	if *quiet {
		logf = func(string, ...any) {}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return deskserve.Run(ctx, logf, opts)
}

// desktopOptions reads the helper's local settings.
//
// The password comes from a file rather than a flag so that it does not sit in
// the process list for every user on the machine to read.
func desktopOptions(vncAddr, passwordFile string) (deskserve.Options, error) {
	opts := deskserve.Options{VNCAddr: vncAddr}
	if passwordFile == "" {
		return opts, nil
	}
	raw, err := os.ReadFile(passwordFile)
	if err != nil {
		return opts, fmt.Errorf("reading the VNC password: %w", err)
	}
	opts.VNCPassword = strings.TrimRight(string(raw), "\r\n")
	return opts, nil
}

// cmdScreen used to open a desktop viewer inside the browser console. That
// viewer is gone, along with the terminal that sat beside it: LocNet's job is
// to make a machine reachable, and watching a screen is a job the viewer you
// already have does better. Rather than delete the command and leave anyone
// who typed it guessing, it says where the screen went.
func cmdScreen(args []string) error {
	pos, _ := splitArgs(args)
	peer := "<peer>"
	if len(pos) > 0 {
		peer = pos[0]
	}
	return fmt.Errorf("`locnet screen` was the in-browser desktop viewer, which has been removed.\n"+
		"Use your own client instead — LocNet still finds the machine and opens it:\n\n"+
		"    locnet vnc %s      a Linux or macOS screen\n"+
		"    locnet rdp %s      a Windows desktop\n\n"+
		"Run `locnet setup -install` on the far machine if it has no screen server yet.", peer, peer)
}

// thisMachineName is used only to write a helpful command line, so a failure
// to ask the daemon is not worth reporting.
func thisMachineName() string {
	st, err := status()
	if err != nil || st.Name == "" {
		return "<this machine>"
	}
	return st.Name
}

// desktopAutostart makes the session helper start with the desktop.
//
// It writes into this user's own configuration, not the system's, because the
// helper has to run inside a graphical session and there is no such thing as a
// session without a user.
func desktopAutostart(off bool, args []string) error {
	if off {
		path, err := deskserve.DisableAutostart()
		if err != nil {
			return err
		}
		fmt.Printf("Removed %s. The helper will not start at login any more.\n", path)
		return nil
	}

	// Whatever flags were given here are what the login entry will use, so
	// `locnet desktop autostart -vnc 127.0.0.1:5901` keeps working after a
	// reboot without anyone editing a unit file.
	fs := flag.NewFlagSet("desktop autostart", flag.ExitOnError)
	vnc := fs.String("vnc", "", "VNC server to bridge")
	pwFile := fs.String("vnc-password-file", "", "file holding the VNC server's password")
	if err := fs.Parse(args); err != nil {
		return err
	}
	extra := []string{"-quiet"}
	if *vnc != "" {
		extra = append(extra, "-vnc", *vnc)
	}
	if *pwFile != "" {
		abs, err := filepath.Abs(*pwFile)
		if err != nil {
			return err
		}
		extra = append(extra, "-vnc-password-file", abs)
	}

	path, ran, err := deskserve.EnableAutostart(extra...)
	if err != nil {
		if path != "" {
			fmt.Printf("Wrote %s.\n", path)
		}
		return err
	}
	fmt.Printf("Wrote %s.\n", path)
	for _, cmd := range ran {
		fmt.Printf("Ran %s.\n", cmd)
	}
	if len(ran) == 0 {
		fmt.Println("It will start at your next login. To start it now:  locnet desktop serve")
	}
	fmt.Println()
	fmt.Println("This is per user, and deliberately so: the helper has to live inside a")
	fmt.Println("graphical session, and only the person logging in has one.")
	return nil
}
