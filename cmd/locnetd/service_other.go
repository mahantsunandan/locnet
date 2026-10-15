//go:build !windows

package main

import "context"

// runAsService is a no-op everywhere except Windows. systemd and launchd run a
// daemon as an ordinary foreground process and read its exit status, so there
// is nothing to adapt to.
func runAsService(func(context.Context) error) (bool, error) { return false, nil }
