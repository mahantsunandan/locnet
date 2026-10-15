//go:build linux

package launch

import "golang.org/x/sys/unix"

// The request that reads terminal attributes is spelled differently on each
// Unix, which is the only reason this is not one file.
const termiosGet = unix.TCGETS
