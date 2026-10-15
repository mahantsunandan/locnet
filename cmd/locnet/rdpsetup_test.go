package main

import (
	"fmt"
	"testing"
)

var sprintf = fmt.Sprintf

// The layout `grdctl status` prints on GNOME 50: an RDP section and a VNC
// section with fields of the same names, so reading the wrong section's Port
// would point the check at the VNC server.
const grdStatus = "Overall:\n\tUnit status: active\nRDP:\n\tStatus: enabled\n\tPort: 3390\n" +
	"\tAuthentication methods: credentials\n\tView-only: no\n\tUsername: %s\n\tPassword: (hidden)\n" +
	"VNC:\n\tStatus: disabled\n\tPort: 5900\n\tPassword: (hidden)\n"

func TestReadingGrdctlStatus(t *testing.T) {
	unset := sprintf(grdStatus, "(null)")
	if got := rdpPort(unset); got != "3390" {
		t.Errorf("port = %q, want the RDP section's 3390", got)
	}
	if hasRDPLogin(unset) {
		t.Error("an unset username was read as a login")
	}
	if !hasRDPLogin(sprintf(grdStatus, "(hidden)")) {
		t.Error("a set username, shown as (hidden), was not read as a login")
	}
	if got := rdpPort("nothing useful"); got != "3389" {
		t.Errorf("port with no status = %q, want the default 3389", got)
	}
}
