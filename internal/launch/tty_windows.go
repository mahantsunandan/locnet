package launch

import "golang.org/x/sys/windows"

// isTerminal is true when fd is a console. A redirected handle is not, and a
// client that tried to prompt on one would hang with nothing on screen.
func isTerminal(fd uintptr) bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(fd), &mode) == nil
}
