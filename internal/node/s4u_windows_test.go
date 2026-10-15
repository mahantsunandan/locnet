package node

import (
	"os/user"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The LSA copies the logon block into its own process and rebases pointers
// that fall inside it, so both strings must be inside the block, right after
// the header, with lengths in bytes.
func TestS4ULogonLayout(t *testing.T) {
	block := newS4ULogon("winpc-01", "WINPC-01")
	start := uintptr(unsafe.Pointer(&block[0]))
	end := start + uintptr(len(block)*8)
	h := (*msv1_0S4ULogonHeader)(unsafe.Pointer(&block[0]))

	if h.MessageType != msv1_0S4ULogon {
		t.Fatalf("message type %d", h.MessageType)
	}
	for name, s := range map[string]windows.NTUnicodeString{"user": h.UserPrincipalName, "domain": h.DomainName} {
		p := uintptr(unsafe.Pointer(s.Buffer))
		if p < start+unsafe.Sizeof(*h) || p+uintptr(s.Length) > end {
			t.Errorf("%s string lies outside the block", name)
		}
		if s.Length != 16 {
			t.Errorf("%s length %d bytes, want 16", name, s.Length)
		}
	}
	if got := windows.UTF16PtrToString(h.UserPrincipalName.Buffer); !strings.HasPrefix(got, "winpc-01") {
		t.Errorf("user string reads %q", got)
	}
}

// The account running the test resolves however it is written, and a name
// that is not a user account is refused rather than logged on.
func TestLocalAccount(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	_, name, _ := strings.Cut(me.Username, `\`)
	computer, _ := windows.ComputerName()
	for _, form := range []string{name, `.\` + name, computer + `\` + name} {
		u, d, err := localAccount(form)
		if err != nil {
			t.Errorf("%q: %v", form, err)
			continue
		}
		if !strings.EqualFold(u, name) || d != computer {
			t.Errorf("%q resolved to %s\\%s", form, d, u)
		}
	}
	if _, _, err := localAccount("Administrators"); err == nil {
		t.Error("a group was accepted as an account")
	}
	if _, _, err := localAccount(`SOMEDOMAIN\` + name); err == nil {
		t.Error("a domain account was accepted")
	}
}
