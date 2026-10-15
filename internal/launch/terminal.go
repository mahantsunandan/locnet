package launch

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// terminals lists the terminal emulators to try, and how each one is told to
// run a command.
//
// The argument that introduces the command differs between them — "-e",
// "--", "-x" — and getting it wrong opens an empty terminal rather than the
// session you asked for, so each is spelled out rather than guessed.
func terminals() []struct {
	bin  string
	args func(cmd []string) []string
} {
	type term = struct {
		bin  string
		args func(cmd []string) []string
	}
	dashDash := func(cmd []string) []string { return append([]string{"--"}, cmd...) }
	dashE := func(cmd []string) []string { return append([]string{"-e"}, cmd...) }

	switch runtime.GOOS {
	case "darwin":
		return []term{{bin: "open", args: func(cmd []string) []string {
			// Terminal.app has no "run this" flag; AppleScript is the
			// supported route and osascript is handled separately below.
			return cmd
		}}}
	case "windows":
		return []term{
			{bin: "wt.exe", args: func(cmd []string) []string { return cmd }},
			{bin: "cmd.exe", args: func(cmd []string) []string {
				return append([]string{"/c", "start", ""}, cmd...)
			}},
		}
	default:
		return []term{
			// The Debian/Ubuntu alternatives symlink, which points at
			// whatever the user actually chose.
			{bin: "x-terminal-emulator", args: dashE},
			{bin: "gnome-terminal", args: dashDash},
			{bin: "konsole", args: dashE},
			{bin: "xfce4-terminal", args: dashE},
			{bin: "tilix", args: dashE},
			{bin: "kitty", args: func(cmd []string) []string { return cmd }},
			{bin: "alacritty", args: dashE},
			{bin: "wezterm", args: func(cmd []string) []string {
				return append([]string{"start", "--"}, cmd...)
			}},
			{bin: "ptyxis", args: dashDash},
			{bin: "xterm", args: dashE},
		}
	}
}

// Terminal opens a terminal window running cmd.
//
// The console needs this because a graphical page cannot host an interactive
// shell. Handing back a command for the user to paste, which is what LocNet
// did before, is not a feature — it is a button that does nothing.
func Terminal(cmd []string) error {
	if len(cmd) == 0 {
		return fmt.Errorf("nothing to run")
	}

	if runtime.GOOS == "darwin" {
		// Terminal.app is driven by AppleScript. Quoting matters: the
		// command becomes a string inside an AppleScript string.
		script := fmt.Sprintf(`tell application "Terminal"
	activate
	do script "%s"
end tell`, strings.ReplaceAll(strings.Join(cmd, " "), `"`, `\"`))
		c := exec.Command("osascript", "-e", script)
		deescalate(c)
		if err := c.Start(); err != nil {
			return fmt.Errorf("could not open Terminal: %w", err)
		}
		go c.Wait()
		return nil
	}

	var tried []string
	for _, t := range terminals() {
		path, err := exec.LookPath(t.bin)
		if err != nil {
			tried = append(tried, t.bin)
			continue
		}
		c := exec.Command(path, t.args(cmd)...)
		deescalate(c)
		if err := c.Start(); err != nil {
			tried = append(tried, t.bin)
			continue
		}
		go c.Wait()
		return nil
	}
	return fmt.Errorf("no terminal emulator found (tried %s).\n"+
		"Run it yourself:  %s", strings.Join(tried, ", "), strings.Join(cmd, " "))
}
