package resource

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// protocolTimeout bounds one protocol check: a connection, one request and the
// first reply. Generous next to the port probe because it crosses the tunnel
// when a peer runs it, and a slow answer is still an answer.
const protocolTimeout = 4 * time.Second

// FixRDP is the command that gives a GNOME machine's RDP server a login, which
// is what it is missing when it hangs up on everyone.
const FixRDP = "locnet setup rdp"

// CheckProtocol speaks the first few bytes of a service's own protocol and
// reports what is wrong with it, or "" when it answers the way a working
// server does.
//
// A port that accepts a TCP connection is not a service anybody can use, and
// treating the two as the same was a long-running lie. GNOME Remote Desktop
// with RDP switched on but no username and password set listens on 3389,
// accepts every connection — and hangs up on every client before the first
// byte of RDP, logging "Credentials are not set, denying client". LocNet's
// scan saw the open port, a peer confirmed it, the console showed a green
// "rdp ✓", and every attempt to use it failed inside the RDP client with
// nothing to say why.
//
// Only protocols LocNet launches a client for are checked; the rest report "".
// target is host:port.
func CheckProtocol(ctx context.Context, name, target string) string {
	switch ClientFor(name) {
	case "rdp":
		return checkRDP(ctx, target)
	case "vnc":
		return checkVNC(ctx, target)
	}
	return ""
}

func dialProtocol(ctx context.Context, target string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, protocolTimeout)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(protocolTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = c.SetDeadline(deadline)
	return c, nil
}

// rdpConnectionRequest is an X.224 Connection Request carrying an RDP
// negotiation request for every security protocol a client might offer — TLS,
// CredSSP and the extended form — so that no server can turn it down for
// asking for too little.
var rdpConnectionRequest = []byte{
	0x03, 0x00, 0x00, 0x13, // TPKT, version 3, 19 bytes
	0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, // X.224 CR
	0x01, 0x00, 0x08, 0x00, 0x0b, 0x00, 0x00, 0x00, // RDP_NEG_REQ: TLS|CredSSP|HybridEx
}

// rdpFailures names the codes of an RDP_NEG_FAILURE.
var rdpFailures = map[uint32]string{
	1: "it insists on plain TLS security",
	2: "it does not allow TLS",
	3: "it has no certificate",
	4: "it found the request inconsistent",
	5: "it requires network-level authentication",
	6: "it requires TLS with user authentication",
}

func checkRDP(ctx context.Context, target string) string {
	c, err := dialProtocol(ctx, target)
	if err != nil {
		return "nothing answers on " + target
	}
	defer c.Close()
	if _, err := c.Write(rdpConnectionRequest); err != nil {
		return rdpHungUp
	}

	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		if isTimeout(err) {
			return "the RDP server accepted the connection and then said nothing"
		}
		return rdpHungUp
	}
	if hdr[0] != 3 {
		return "something answers on this port, but it is not an RDP server"
	}
	n := int(binary.BigEndian.Uint16(hdr[2:4]))
	if n < 11 || n > 512 {
		return "something answers on this port, but it is not an RDP server"
	}
	body := make([]byte, n-4)
	if _, err := io.ReadFull(c, body); err != nil {
		return rdpHungUp
	}
	if len(body) < 2 || body[1]&0xf0 != 0xd0 { // X.224 Connection Confirm
		return "something answers on this port, but it is not an RDP server"
	}
	// The confirm is seven bytes — length, code, two references, class — and
	// any negotiation reply follows it: type, flags, length, then a 32-bit
	// value. An old server confirms without negotiating; that is still a
	// server.
	if len(body) >= 15 && body[7] == 0x03 {
		code := binary.LittleEndian.Uint32(body[11:15])
		why := rdpFailures[code]
		if why == "" {
			why = fmt.Sprintf("failure code %d", code)
		}
		return "the RDP server refuses the connection: " + why
	}
	return ""
}

// rdpHungUp is what a server that hangs up before negotiating means in
// practice. GNOME Remote Desktop is by far the commonest cause, and saying so
// with the fix beats "connection reset by peer".
const rdpHungUp = "the RDP server hangs up on every client before anyone can log in. " +
	"GNOME Remote Desktop does this when it has no RDP username and password — or has " +
	"them in a keyring that is locked, as it is after an automatic login or a restart. " +
	"Fix it on that machine, as the person who logs in there: " + FixRDP

func checkVNC(ctx context.Context, target string) string {
	c, err := dialProtocol(ctx, target)
	if err != nil {
		return "nothing answers on " + target
	}
	defer c.Close()

	// The server speaks first, with its version. Reading that and leaving is
	// enough to know it is a VNC server and stops short of authentication,
	// so no server counts it as a failed login.
	banner := make([]byte, 12)
	if _, err := io.ReadFull(c, banner); err != nil {
		if isTimeout(err) {
			return "the VNC server accepted the connection and then said nothing"
		}
		return "the VNC server closes the connection before saying anything — " +
			"it may be refusing this machine, or nothing is running behind LocNet's share"
	}
	if !bytes.HasPrefix(banner, []byte("RFB ")) {
		return "something answers on this port, but it is not a VNC server"
	}
	return ""
}

func isTimeout(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return strings.Contains(err.Error(), "i/o timeout")
}

// WakeVNC taps the Shift key on a VNC desktop that lets clients in without a
// password, so a viewer opened a moment later finds it awake.
//
// A Linux virtual desktop blanks itself after a few idle minutes, and a VNC
// viewer connecting to a blanked desktop shows a black window — which nothing
// on screen explains, and which looks exactly like a broken connection. A key
// press wakes it, and on a desktop that locks itself it brings up the unlock
// prompt, which at least says what to do next.
//
// Shift, and only Shift, because it is the one input with no effect of its own:
// a click would land on whatever is under the pointer of a desktop that is
// already awake, and pointer motion turned out not to wake xfce4-screensaver
// once its lock dialog had come and gone.
//
// It only acts on a server offering the "None" security type, which is how
// LocNet's own virtual desktop is set up — its access is decided by the share
// in front of it. A server that wants a password is left alone: guessing at it
// would count as a failed login. Errors are ignored; this is a courtesy, and
// the viewer will report anything that is really wrong.
func WakeVNC(ctx context.Context, target string) {
	c, err := dialProtocol(ctx, target)
	if err != nil {
		return
	}
	defer c.Close()

	banner := make([]byte, 12)
	if _, err := io.ReadFull(c, banner); err != nil || !bytes.HasPrefix(banner, []byte("RFB 003.")) {
		return
	}
	if _, err := c.Write([]byte("RFB 003.008\n")); err != nil {
		return
	}
	n := make([]byte, 1)
	if _, err := io.ReadFull(c, n); err != nil || n[0] == 0 {
		return
	}
	types := make([]byte, n[0])
	if _, err := io.ReadFull(c, types); err != nil || !bytes.Contains(types, []byte{1}) {
		return // a password is needed; not ours to try
	}
	if _, err := c.Write([]byte{1}); err != nil { // security type None
		return
	}
	result := make([]byte, 4)
	if _, err := io.ReadFull(c, result); err != nil || binary.BigEndian.Uint32(result) != 0 {
		return
	}
	if _, err := c.Write([]byte{1}); err != nil { // ClientInit: share the desktop
		return
	}
	init := make([]byte, 24)
	if _, err := io.ReadFull(c, init); err != nil {
		return
	}
	if nameLen := binary.BigEndian.Uint32(init[20:24]); nameLen < 1<<16 {
		_, _ = io.CopyN(io.Discard, c, int64(nameLen))
	}
	const shiftL = 0xffe1
	for _, down := range []byte{1, 0} {
		msg := []byte{4, down, 0, 0, 0, 0, 0, 0} // KeyEvent
		binary.BigEndian.PutUint32(msg[4:8], shiftL)
		if _, err := c.Write(msg); err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}
