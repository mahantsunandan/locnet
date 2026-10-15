//go:build !linux

package main

import "errors"

// readSecret is only needed by `locnet setup rdp`, which does its work on
// Linux; elsewhere it explains and returns before asking for anything.
func readSecret() (string, error) {
	return "", errors.New("reading a password is only supported on Linux")
}
