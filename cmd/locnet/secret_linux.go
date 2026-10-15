package main

import (
	"bufio"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// readSecret reads one line from the terminal without echoing it.
func readSecret() (string, error) {
	fd := int(os.Stdin.Fd())
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err == nil {
		quiet := *old
		quiet.Lflag &^= unix.ECHO
		quiet.Lflag |= unix.ICANON | unix.ISIG
		if err := unix.IoctlSetTermios(fd, unix.TCSETS, &quiet); err == nil {
			defer unix.IoctlSetTermios(fd, unix.TCSETS, old)
		}
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	os.Stdout.WriteString("\n")
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
