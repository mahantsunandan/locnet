//go:build !windows

package launch

import "golang.org/x/sys/unix"

// isTerminal asks the kernel whether fd has terminal attributes. Only a real
// terminal answers; a pipe, a file and /dev/null all fail.
func isTerminal(fd uintptr) bool {
	_, err := unix.IoctlGetTermios(int(fd), termiosGet)
	return err == nil
}
