//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package launch

import "golang.org/x/sys/unix"

const termiosGet = unix.TIOCGETA
