//go:build linux

package screen

// The tests in this file need something a build machine does not have: a real
// X server whose root window can be captured, or a real VNC server. They skip
// themselves unless told where to find one, so `go test ./...` stays green on
// a machine with no display at all.
//
// Everything here can be run against a throwaway server in one line. TigerVNC
// is both at once — an X server and a VNC server showing the same screen:
//
//	Xvnc :47 -geometry 640x480 -depth 24 -SecurityTypes None -rfbport 5947 &
//	DISPLAY=:47 XAUTHORITY=/dev/null LOCNET_TEST_X11=1 LOCNET_TEST_XTEST=1 \
//	    LOCNET_TEST_VNC=127.0.0.1:5947 go test ./internal/screen -run Real -v
//
// The X11 ones are gated on LOCNET_TEST_X11 rather than on DISPLAY being set,
// because a Wayland desktop sets DISPLAY too — Xwayland is listening on it —
// and capturing that root window fails by design. Opting in explicitly is the
// only way to be sure the test is pointed at a server it can actually work
// against.
//
// That covers the two paths this package cannot otherwise prove: capturing a
// root window, which Xwayland refuses, and speaking RFB to an implementation
// that is not the fake in vnc_test.go.

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
	"time"
)

// TestRealX11RootCapture captures a real X server's root window, which is the
// one path this package cannot exercise on a Wayland build machine.
func TestRealX11RootCapture(t *testing.T) {
	if os.Getenv("LOCNET_TEST_X11") == "" {
		t.Skip("set LOCNET_TEST_X11=1, with DISPLAY pointing at a real X server")
	}
	x, err := dialX11()
	if err != nil {
		t.Skipf("no X server: %v", err)
	}
	defer x.Close()

	img, err := x.Capture()
	if err != nil {
		t.Fatalf("capturing the root window: %v", err)
	}
	b := img.Bounds()
	t.Logf("captured %dx%d, depth %d, bpp %d, xtest opcode %d", b.Dx(), b.Dy(), x.depth, x.bpp, x.testOp)
	if b.Dx() == 0 || b.Dy() == 0 {
		t.Fatal("captured nothing")
	}
	// Alpha must be filled in for every pixel, or the JPEG encoder and the
	// canvas both get confused.
	for i := 3; i < len(img.Pix); i += 4 {
		if img.Pix[i] != 0xff {
			t.Fatalf("pixel %d has alpha %d", i/4, img.Pix[i])
		}
	}

	if p, ok := x.Pointer(); ok {
		t.Logf("pointer at %v", p)
	} else {
		t.Error("QueryPointer returned nothing on a real server")
	}

	// A second capture must produce a frame of the same shape, and the
	// encoder must find it unchanged on a still screen.
	first := append([]byte(nil), img.Pix...)
	time.Sleep(300 * time.Millisecond)
	img2, err := x.Capture()
	if err != nil {
		t.Fatal(err)
	}
	if img2.Bounds() != b {
		t.Fatalf("second capture is %v, first was %v", img2.Bounds(), b)
	}
	if !bytes.Equal(first, img2.Pix) {
		t.Log("the screen changed between captures, which is fine on a live display")
	}

	var buf bytes.Buffer
	enc := &Encoder{}
	n, err := enc.Frame(&buf, img2)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("first frame: %d tiles, %d bytes", n, buf.Len())
	if n == 0 {
		t.Error("the first frame sent no tiles")
	}
}

// TestRealX11Input presses a key and moves the pointer on a real server.
func TestRealX11Input(t *testing.T) {
	if os.Getenv("LOCNET_TEST_XTEST") == "" {
		t.Skip("set LOCNET_TEST_XTEST=1 to drive a real X server")
	}
	x, err := dialX11()
	if err != nil {
		t.Skipf("no X server: %v", err)
	}
	defer x.Close()
	if !x.Controllable() {
		t.Fatal("XTEST is missing on this server")
	}

	if err := x.Input(Event{Type: "move", X: 120, Y: 90}); err != nil {
		t.Fatal(err)
	}
	// Give the server a moment to process the fake motion.
	time.Sleep(200 * time.Millisecond)
	p, ok := x.Pointer()
	if !ok {
		t.Fatal("cannot read the pointer back")
	}
	if p.X != 120 || p.Y != 90 {
		t.Errorf("pointer is at %v after asking for 120,90", p)
	}

	for _, ev := range []Event{
		{Type: "key", Key: "a", Code: "KeyA", Down: true},
		{Type: "key", Key: "a", Code: "KeyA", Down: false},
		{Type: "key", Key: "Enter", Code: "Enter", Down: true},
		{Type: "key", Key: "Enter", Code: "Enter", Down: false},
		{Type: "key", Key: "€", Down: true},
		{Type: "key", Key: "€", Down: false},
		{Type: "down", X: 120, Y: 90, Button: 1},
		{Type: "up", X: 120, Y: 90, Button: 1},
		{Type: "wheel", DY: 2},
	} {
		if err := x.Input(ev); err != nil {
			t.Fatalf("input %+v: %v", ev, err)
		}
	}
	// Any error from those would surface on the next request with a reply.
	if _, _, err := x.geometry(); err != nil {
		t.Fatalf("the server complained after the input: %v", err)
	}
}

// TestRealVNCServer runs the RFB client against whatever server is at
// LOCNET_TEST_VNC. It is skipped unless that is set, because a build machine
// has no VNC server; the point is to check the client against a real
// implementation rather than only against this package's own fake.
func TestRealVNCServer(t *testing.T) {
	addr := os.Getenv("LOCNET_TEST_VNC")
	if addr == "" {
		t.Skip("set LOCNET_TEST_VNC to a host:port to run this")
	}
	if !ProbeVNC(addr, 3*time.Second) {
		t.Fatalf("nothing speaking RFB at %s", addr)
	}
	s, err := DialVNC(addr, os.Getenv("LOCNET_TEST_VNC_PASSWORD"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		img, err := s.Capture()
		if err != nil {
			t.Fatal(err)
		}
		b := img.Bounds()
		if b.Dx() > 0 && b.Dy() > 0 {
			if _, _, _, a := img.At(b.Dx()/2, b.Dy()/2).RGBA(); a != 0 {
				t.Logf("captured %dx%d from %s", b.Dx(), b.Dy(), addr)
				// Drive it a little; a server that dislikes our input
				// messages closes the connection, which the next Capture
				// reports.
				for _, ev := range []Event{
					{Type: "move", X: 10, Y: 10},
					{Type: "down", X: 10, Y: 10, Button: 1},
					{Type: "up", X: 10, Y: 10, Button: 1},
					{Type: "key", Key: "a", Code: "KeyA", Down: true},
					{Type: "key", Key: "a", Code: "KeyA", Down: false},
					{Type: "wheel", DY: 1},
				} {
					if err := s.Input(ev); err != nil {
						t.Fatalf("input %+v: %v", ev, err)
					}
				}
				time.Sleep(500 * time.Millisecond)
				if _, err := s.Capture(); err != nil {
					t.Fatalf("the server dropped us after input: %v", err)
				}
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("no frame arrived within ten seconds")
}

// TestRealBothPathsAgree paints a known colour onto a real X server's root window
// and reads it back through both capture paths.
//
// The two decoders were written days apart from different specifications, and
// the failure they would share is a channel order that is wrong in the same
// way twice. Comparing them against a colour with three different channels
// catches that.
func TestRealBothPathsAgree(t *testing.T) {
	vncAddr := os.Getenv("LOCNET_TEST_VNC")
	if vncAddr == "" || os.Getenv("LOCNET_TEST_X11") == "" {
		t.Skip("set LOCNET_TEST_X11=1 and LOCNET_TEST_VNC, both pointing at one server")
	}

	x, err := dialX11()
	if err != nil {
		t.Skipf("no X server: %v", err)
	}
	defer x.Close()

	// Paint the root window. Red 0x20, green 0x40, blue 0x80.
	const want = 0x204080
	gc := x.newID()
	req := make([]byte, 20)
	req[0] = 55 // CreateGC
	binary.LittleEndian.PutUint16(req[2:], 5)
	binary.LittleEndian.PutUint32(req[4:], gc)
	binary.LittleEndian.PutUint32(req[8:], x.root)
	binary.LittleEndian.PutUint32(req[12:], 0x00000004) // foreground
	binary.LittleEndian.PutUint32(req[16:], want)
	if _, err := x.request(req); err != nil {
		t.Fatal(err)
	}
	req = make([]byte, 20)
	req[0] = 70 // PolyFillRectangle
	binary.LittleEndian.PutUint16(req[2:], 5)
	binary.LittleEndian.PutUint32(req[4:], x.root)
	binary.LittleEndian.PutUint32(req[8:], gc)
	binary.LittleEndian.PutUint16(req[16:], x.width)
	binary.LittleEndian.PutUint16(req[18:], x.height)
	if _, err := x.request(req); err != nil {
		t.Fatal(err)
	}
	if _, _, err := x.geometry(); err != nil { // sync
		t.Fatal(err)
	}

	img, err := x.Capture()
	if err != nil {
		t.Fatal(err)
	}
	r, g, b, a := img.At(img.Bounds().Dx()/2, img.Bounds().Dy()/2).RGBA()
	if r>>8 != 0x20 || g>>8 != 0x40 || b>>8 != 0x80 || a>>8 != 0xff {
		t.Errorf("X11 read the root back as %02x%02x%02x%02x, painted 204080ff",
			r>>8, g>>8, b>>8, a>>8)
	}

	// The same screen, through a VNC server serving that same X display.
	v, err := DialVNC(vncAddr, "")
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		vimg, err := v.Capture()
		if err != nil {
			t.Fatal(err)
		}
		vr, vg, vb, va := vimg.At(vimg.Bounds().Dx()/2, vimg.Bounds().Dy()/2).RGBA()
		if va>>8 == 0xff && (vr|vg|vb) != 0 {
			if vr>>8 != 0x20 || vg>>8 != 0x40 || vb>>8 != 0x80 {
				t.Fatalf("VNC read the same screen as %02x%02x%02x, X11 read 204080",
					vr>>8, vg>>8, vb>>8)
			}
			if vimg.Bounds() != img.Bounds() {
				t.Errorf("the two paths disagree on the size: X11 %v, VNC %v",
					img.Bounds(), vimg.Bounds())
			}
			t.Logf("both paths agree: %v, colour 204080", vimg.Bounds())
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("the VNC path never produced the painted screen")
}
