//go:build !linux && !windows && !darwin

package screen

import "runtime"

func open() (Session, error) {
	return nil, unsupported("there is no screen capture for %s in this build", runtime.GOOS)
}
