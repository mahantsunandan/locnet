package resource

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// serve runs one fake server: handle gets each accepted connection.
func serve(t *testing.T, handle func(c net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); handle(c) }()
		}
	}()
	return ln.Addr().String()
}

// readRequest consumes the 19-byte connection request a client sends first.
func readRequest(c net.Conn) {
	buf := make([]byte, len(rdpConnectionRequest))
	io.ReadFull(c, buf)
}

func TestRDPServerThatNegotiatesIsFine(t *testing.T) {
	addr := serve(t, func(c net.Conn) {
		readRequest(c)
		// Connection Confirm with RDP_NEG_RSP selecting CredSSP.
		c.Write([]byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0, 0, 0x12, 0x34, 0,
			0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00})
	})
	if p := CheckProtocol(context.Background(), "rdp", addr); p != "" {
		t.Errorf("a working RDP server was reported as %q", p)
	}
}

// TestRDPServerThatHangsUpIsReported is GNOME Remote Desktop with no RDP
// credentials set: it accepts, reads the request, and closes.
func TestRDPServerThatHangsUpIsReported(t *testing.T) {
	addr := serve(t, func(c net.Conn) { readRequest(c) })
	p := CheckProtocol(context.Background(), "rdp", addr)
	if !strings.Contains(p, "hangs up") || !strings.Contains(p, FixRDP) {
		t.Errorf("a server that hangs up before login gave %q; want the explanation and %q", p, FixRDP)
	}
}

func TestRDPNegotiationFailureIsNamed(t *testing.T) {
	addr := serve(t, func(c net.Conn) {
		readRequest(c)
		c.Write([]byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0, 0, 0x12, 0x34, 0,
			0x03, 0x00, 0x08, 0x00, 0x05, 0x00, 0x00, 0x00})
	})
	if p := CheckProtocol(context.Background(), "rdp", addr); !strings.Contains(p, "network-level authentication") {
		t.Errorf("negotiation failure 5 gave %q", p)
	}
}

func TestWrongServerOnTheRDPPort(t *testing.T) {
	addr := serve(t, func(c net.Conn) { c.Write([]byte("SSH-2.0-OpenSSH_9.9\r\n")) })
	if p := CheckProtocol(context.Background(), "rdp", addr); !strings.Contains(p, "not an RDP server") {
		t.Errorf("an SSH server on the RDP port gave %q", p)
	}
}

func TestVNCBanner(t *testing.T) {
	good := serve(t, func(c net.Conn) { c.Write([]byte("RFB 003.008\n")); io.Copy(io.Discard, c) })
	if p := CheckProtocol(context.Background(), "vnc-1", good); p != "" {
		t.Errorf("a VNC server was reported as %q", p)
	}
	silent := serve(t, func(c net.Conn) {})
	if p := CheckProtocol(context.Background(), "vnc", silent); !strings.Contains(p, "closes the connection") {
		t.Errorf("a forwarder with nothing behind it gave %q", p)
	}
}

func TestUncheckedProtocolsAreLeftAlone(t *testing.T) {
	if p := CheckProtocol(context.Background(), "ssh", "127.0.0.1:1"); p != "" {
		t.Errorf("ssh is not checked, but reported %q", p)
	}
}

// TestWakeVNCTapsShift plays a password-free VNC server and checks that a
// Shift key press arrives — what wakes a blanked desktop before the viewer
// opens.
func TestWakeVNCTapsShift(t *testing.T) {
	moved := make(chan bool, 1)
	addr := serve(t, func(c net.Conn) {
		c.Write([]byte("RFB 003.008\n"))
		io.ReadFull(c, make([]byte, 12))
		c.Write([]byte{1, 1}) // one security type: None
		io.ReadFull(c, make([]byte, 1))
		c.Write([]byte{0, 0, 0, 0})
		io.ReadFull(c, make([]byte, 1))
		// ServerInit: 1600x900, a pixel format, and a four-byte name.
		init := append([]byte{0x06, 0x40, 0x03, 0x84}, make([]byte, 16)...)
		init = append(init, 0, 0, 0, 4)
		c.Write(append(init, []byte("test")...))
		msg := make([]byte, 8)
		if _, err := io.ReadFull(c, msg); err == nil && msg[0] == 4 && msg[1] == 1 &&
			msg[4] == 0 && msg[5] == 0 && msg[6] == 0xff && msg[7] == 0xe1 {
			moved <- true
		}
	})
	WakeVNC(context.Background(), addr)
	select {
	case <-moved:
	case <-time.After(3 * time.Second):
		t.Fatal("no Shift key press reached the server")
	}
}

// TestWakeVNCLeavesPasswordedServersAlone checks that a server wanting a VNC
// password is not sent anything that could count as a failed login.
func TestWakeVNCLeavesPasswordedServersAlone(t *testing.T) {
	chose := make(chan []byte, 1)
	addr := serve(t, func(c net.Conn) {
		c.Write([]byte("RFB 003.008\n"))
		io.ReadFull(c, make([]byte, 12))
		c.Write([]byte{1, 2}) // VNC authentication only
		buf := make([]byte, 1)
		n, _ := c.Read(buf)
		chose <- buf[:n]
	})
	WakeVNC(context.Background(), addr)
	if got := <-chose; len(got) != 0 {
		t.Errorf("chose security type %v on a server that wants a password", got)
	}
}
