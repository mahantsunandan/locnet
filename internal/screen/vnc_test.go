package screen

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeVNC is a scripted RFB server: enough of one to drive the client through
// a real handshake and a real framebuffer update, and to record what the
// client sent back.
type fakeVNC struct {
	ln net.Listener

	mu       sync.Mutex
	received [][]byte // client messages, whole
	requests int      // FramebufferUpdateRequests seen

	// what to serve
	w, h     int
	password string
	// paint is called to produce the pixels of the first update.
	paint func() []byte
	// afterFirst runs once the first update has been sent, for tests that
	// want a second rectangle with a different encoding.
	afterFirst func(conn net.Conn)
}

func startFakeVNC(t *testing.T, f *fakeVNC) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.ln = ln

	// The server goroutine logs through t, which is only legal until the test
	// completes, so cleanup closes its connection and waits for it to return.
	var (
		connMu sync.Mutex
		served net.Conn
		done   = make(chan struct{})
	)
	t.Cleanup(func() {
		ln.Close()
		connMu.Lock()
		if served != nil {
			served.Close()
		}
		connMu.Unlock()
		<-done
	})

	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		connMu.Lock()
		served = conn
		connMu.Unlock()
		defer conn.Close()
		if err := f.serve(conn); err != nil && err != io.EOF && !strings.Contains(err.Error(), "use of closed") {
			t.Logf("fake vnc: %v", err)
		}
	}()
	return ln.Addr().String()
}

func (f *fakeVNC) serve(conn net.Conn) error {
	if _, err := conn.Write([]byte("RFB 003.008\n")); err != nil {
		return err
	}
	var version [12]byte
	if _, err := io.ReadFull(conn, version[:]); err != nil {
		return err
	}

	if f.password == "" {
		if _, err := conn.Write([]byte{1, 1}); err != nil { // one type: None
			return err
		}
		var chosen [1]byte
		if _, err := io.ReadFull(conn, chosen[:]); err != nil {
			return err
		}
	} else {
		if _, err := conn.Write([]byte{1, 2}); err != nil { // one type: VNC auth
			return err
		}
		var chosen [1]byte
		if _, err := io.ReadFull(conn, chosen[:]); err != nil {
			return err
		}
		challenge := make([]byte, 16)
		for i := range challenge {
			challenge[i] = byte(i * 7)
		}
		if _, err := conn.Write(challenge); err != nil {
			return err
		}
		var reply [16]byte
		if _, err := io.ReadFull(conn, reply[:]); err != nil {
			return err
		}
		want, err := vncAuthResponse(challenge, f.password)
		if err != nil {
			return err
		}
		if string(reply[:]) != string(want) {
			// Failure, with the 3.8 reason string.
			_, _ = conn.Write([]byte{0, 0, 0, 1})
			msg := "wrong password"
			var n [4]byte
			binary.BigEndian.PutUint32(n[:], uint32(len(msg)))
			_, _ = conn.Write(n[:])
			_, _ = conn.Write([]byte(msg))
			return nil
		}
	}
	if _, err := conn.Write([]byte{0, 0, 0, 0}); err != nil { // SecurityResult: ok
		return err
	}

	var shared [1]byte
	if _, err := io.ReadFull(conn, shared[:]); err != nil {
		return err
	}

	init := make([]byte, 24)
	binary.BigEndian.PutUint16(init[0:], uint16(f.w))
	binary.BigEndian.PutUint16(init[2:], uint16(f.h))
	init[4] = 32 // bits per pixel
	init[5] = 24 // depth
	init[7] = 1  // true colour
	binary.BigEndian.PutUint16(init[8:], 255)
	binary.BigEndian.PutUint16(init[10:], 255)
	binary.BigEndian.PutUint16(init[12:], 255)
	init[14], init[15], init[16] = 16, 8, 0
	binary.BigEndian.PutUint32(init[20:], 4)
	if _, err := conn.Write(append(init, []byte("test")...)); err != nil {
		return err
	}

	first := true
	for {
		var kind [1]byte
		if _, err := io.ReadFull(conn, kind[:]); err != nil {
			return err
		}
		var rest []byte
		switch kind[0] {
		case msgSetPixelFormat:
			rest = make([]byte, 19)
		case msgSetEncodings:
			head := make([]byte, 3)
			if _, err := io.ReadFull(conn, head); err != nil {
				return err
			}
			n := int(binary.BigEndian.Uint16(head[1:]))
			rest = make([]byte, 4*n)
			if _, err := io.ReadFull(conn, rest); err != nil {
				return err
			}
			f.record(append(kind[:], append(head, rest...)...))
			continue
		case msgFramebufferUpdateRequest:
			rest = make([]byte, 9)
		case msgKeyEvent:
			rest = make([]byte, 7)
		case msgPointerEvent:
			rest = make([]byte, 5)
		default:
			return nil
		}
		if _, err := io.ReadFull(conn, rest); err != nil {
			return err
		}
		f.record(append(kind[:], rest...))

		if kind[0] == msgFramebufferUpdateRequest {
			f.mu.Lock()
			f.requests++
			f.mu.Unlock()
			if first {
				first = false
				if err := f.sendRaw(conn); err != nil {
					return err
				}
				if f.afterFirst != nil {
					f.afterFirst(conn)
				}
			}
		}
	}
}

// sendRaw sends one full-screen Raw rectangle.
//
// The layout is message type, one padding byte, the rectangle count, and then
// each rectangle as x, y, width, height, encoding.
func (f *fakeVNC) sendRaw(conn net.Conn) error {
	head := make([]byte, 4+12)
	head[0] = msgFramebufferUpdate
	binary.BigEndian.PutUint16(head[2:], 1) // one rectangle
	binary.BigEndian.PutUint16(head[4:], 0) // x
	binary.BigEndian.PutUint16(head[6:], 0) // y
	binary.BigEndian.PutUint16(head[8:], uint16(f.w))
	binary.BigEndian.PutUint16(head[10:], uint16(f.h))
	binary.BigEndian.PutUint32(head[12:], 0) // Raw
	if _, err := conn.Write(head); err != nil {
		return err
	}
	_, err := conn.Write(f.paint())
	return err
}

func (f *fakeVNC) record(msg []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.received = append(f.received, append([]byte(nil), msg...))
}

func (f *fakeVNC) messages() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte(nil), f.received...)
}

// solid paints every pixel the same colour, in the little-endian BGRX layout
// the client asks the server for.
func solid(w, h int, r, g, b byte) []byte {
	buf := make([]byte, w*h*4)
	for i := 0; i < w*h; i++ {
		buf[i*4+0] = b
		buf[i*4+1] = g
		buf[i*4+2] = r
		buf[i*4+3] = 0
	}
	return buf
}

// waitForFrame polls Capture until the framebuffer stops being blank, because
// the first update arrives on the reader goroutine.
func waitForFrame(t *testing.T, s Session) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		img, err := s.Capture()
		if err == nil && img != nil {
			if _, _, _, a := img.At(0, 0).RGBA(); a != 0 {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no frame arrived from the VNC server")
}

func TestVNCBridgeCarriesPixels(t *testing.T) {
	f := &fakeVNC{w: 64, h: 48, paint: func() []byte { return solid(64, 48, 0x20, 0x40, 0x80) }}
	addr := startFakeVNC(t, f)

	s, err := DialVNC(addr, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	waitForFrame(t, s)

	img, err := s.Capture()
	if err != nil {
		t.Fatal(err)
	}
	if got := img.Bounds(); got.Dx() != 64 || got.Dy() != 48 {
		t.Fatalf("framebuffer is %v", got)
	}
	// A red/blue swap is the classic way to get this wrong, so the test
	// colour has three different channels.
	for _, p := range [][2]int{{0, 0}, {63, 47}, {30, 20}} {
		r, g, b, a := img.At(p[0], p[1]).RGBA()
		if r>>8 != 0x20 || g>>8 != 0x40 || b>>8 != 0x80 || a>>8 != 0xff {
			t.Fatalf("pixel %v is %02x%02x%02x%02x, wanted 204080ff",
				p, r>>8, g>>8, b>>8, a>>8)
		}
	}
	if !s.Controllable() {
		t.Error("a VNC session should report that it can be driven")
	}
}

func TestVNCBridgeAsksForTheRightFormat(t *testing.T) {
	f := &fakeVNC{w: 16, h: 16, paint: func() []byte { return solid(16, 16, 1, 2, 3) }}
	addr := startFakeVNC(t, f)

	s, err := DialVNC(addr, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	waitForFrame(t, s)

	var sawFormat, sawEncodings bool
	for _, m := range f.messages() {
		switch m[0] {
		case msgSetPixelFormat:
			sawFormat = true
			if m[4] != 32 || m[5] != 24 || m[6] != 0 || m[7] != 1 {
				t.Errorf("pixel format asked for is %v, wanted 32bpp depth 24 little-endian true-colour", m[4:8])
			}
			if m[14] != 16 || m[15] != 8 || m[16] != 0 {
				t.Errorf("colour shifts are %v, wanted 16/8/0", m[14:17])
			}
		case msgSetEncodings:
			sawEncodings = true
		}
	}
	if !sawFormat || !sawEncodings {
		t.Errorf("client sent SetPixelFormat=%v SetEncodings=%v", sawFormat, sawEncodings)
	}
}

func TestVNCBridgeCopyRect(t *testing.T) {
	const w, h = 64, 32
	f := &fakeVNC{w: w, h: h}
	f.paint = func() []byte {
		// Left half red, right half black.
		buf := make([]byte, w*h*4)
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				i := (y*w + x) * 4
				if x < w/2 {
					buf[i+2] = 0xf0 // red
				}
				buf[i+3] = 0
			}
		}
		return buf
	}
	// Then copy the left half onto the right half.
	f.afterFirst = func(conn net.Conn) {
		msg := make([]byte, 4+12+4)
		msg[0] = msgFramebufferUpdate
		binary.BigEndian.PutUint16(msg[2:], 1)
		binary.BigEndian.PutUint16(msg[4:], uint16(w/2)) // dst x
		binary.BigEndian.PutUint16(msg[6:], 0)           // dst y
		binary.BigEndian.PutUint16(msg[8:], uint16(w/2)) // width
		binary.BigEndian.PutUint16(msg[10:], uint16(h))  // height
		binary.BigEndian.PutUint32(msg[12:], 1)          // CopyRect
		binary.BigEndian.PutUint16(msg[16:], 0)          // src x
		binary.BigEndian.PutUint16(msg[18:], 0)          // src y
		_, _ = conn.Write(msg)
	}
	addr := startFakeVNC(t, f)

	s, err := DialVNC(addr, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	waitForFrame(t, s)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		img, err := s.Capture()
		if err != nil {
			t.Fatal(err)
		}
		if r, _, _, _ := img.At(w-1, h/2).RGBA(); r>>8 == 0xf0 {
			return // the copy landed
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("CopyRect never moved the pixels")
}

func TestVNCBridgeSendsInput(t *testing.T) {
	f := &fakeVNC{w: 32, h: 32, paint: func() []byte { return solid(32, 32, 5, 6, 7) }}
	addr := startFakeVNC(t, f)

	s, err := DialVNC(addr, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	waitForFrame(t, s)

	if err := s.Input(Event{Type: "move", X: 10, Y: 20}); err != nil {
		t.Fatal(err)
	}
	if err := s.Input(Event{Type: "down", X: 10, Y: 20, Button: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.Input(Event{Type: "up", X: 10, Y: 20, Button: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.Input(Event{Type: "key", Key: "a", Code: "KeyA", Down: true}); err != nil {
		t.Fatal(err)
	}

	var pointers, keys [][]byte
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		pointers, keys = nil, nil
		for _, m := range f.messages() {
			switch m[0] {
			case msgPointerEvent:
				pointers = append(pointers, m)
			case msgKeyEvent:
				keys = append(keys, m)
			}
		}
		if len(pointers) >= 3 && len(keys) >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if len(pointers) < 3 {
		t.Fatalf("server saw %d pointer events, wanted 3", len(pointers))
	}
	x := binary.BigEndian.Uint16(pointers[0][2:])
	y := binary.BigEndian.Uint16(pointers[0][4:])
	if x != 10 || y != 20 {
		t.Errorf("first pointer event is at %d,%d", x, y)
	}
	if pointers[1][1] != 1 {
		t.Errorf("button mask on press is %d, wanted 1", pointers[1][1])
	}
	if pointers[2][1] != 0 {
		t.Errorf("button mask on release is %d, wanted 0", pointers[2][1])
	}

	if len(keys) < 1 {
		t.Fatal("server saw no key event")
	}
	if keys[0][1] != 1 {
		t.Error("key event was not marked as a press")
	}
	// RFB keys are X11 keysyms, which is what this package already speaks.
	if ks := binary.BigEndian.Uint32(keys[0][4:]); ks != 0x61 {
		t.Errorf("keysym sent is %#x, wanted 0x61 for 'a'", ks)
	}
}

func TestVNCBridgeAuthentication(t *testing.T) {
	f := &fakeVNC{w: 16, h: 16, password: "hunter2",
		paint: func() []byte { return solid(16, 16, 1, 1, 1) }}
	addr := startFakeVNC(t, f)

	s, err := DialVNC(addr, "hunter2")
	if err != nil {
		t.Fatalf("the right password was rejected: %v", err)
	}
	s.Close()

	// A wrong password, and no password at all, both have to fail with
	// something a person can act on.
	f2 := &fakeVNC{w: 16, h: 16, password: "hunter2",
		paint: func() []byte { return solid(16, 16, 1, 1, 1) }}
	addr2 := startFakeVNC(t, f2)
	if _, err := DialVNC(addr2, "wrong"); err == nil {
		t.Error("a wrong password was accepted")
	} else if !strings.Contains(err.Error(), "wrong password") {
		t.Errorf("unhelpful error for a bad password: %v", err)
	}

	f3 := &fakeVNC{w: 16, h: 16, password: "hunter2",
		paint: func() []byte { return solid(16, 16, 1, 1, 1) }}
	addr3 := startFakeVNC(t, f3)
	_, err = DialVNC(addr3, "")
	if err == nil {
		t.Fatal("a password-protected server was entered with no password")
	}
	if !strings.Contains(err.Error(), "password") {
		t.Errorf("the error does not mention a password: %v", err)
	}
}

func TestVNCBridgeRejectsSomethingElse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 \r\n\r\n"))
		conn.Close()
	}()

	if _, err := DialVNC(ln.Addr().String(), ""); err == nil {
		t.Error("a web server was accepted as a VNC server")
	}
	if ProbeVNC(ln.Addr().String(), time.Second) {
		t.Error("the probe called a web server a VNC server")
	}
}

func TestVNCProbe(t *testing.T) {
	f := &fakeVNC{w: 16, h: 16, paint: func() []byte { return solid(16, 16, 1, 1, 1) }}
	addr := startFakeVNC(t, f)
	if !ProbeVNC(addr, 2*time.Second) {
		t.Error("the probe did not recognise a real RFB greeting")
	}
	// Nothing listening at all.
	if ProbeVNC("127.0.0.1:1", 300*time.Millisecond) {
		t.Error("the probe found a server on a closed port")
	}
}

func TestReverseBits(t *testing.T) {
	// VNC's authentication reverses the bits of every byte of the password
	// before using it as a DES key. Getting this backwards produces a
	// response that is wrong in a way no server explains.
	cases := map[byte]byte{
		0x00: 0x00, 0xff: 0xff, 0x01: 0x80, 0x80: 0x01,
		0x0f: 0xf0, 0xa5: 0xa5, 0x12: 0x48,
	}
	for in, want := range cases {
		if got := reverseBits(in); got != want {
			t.Errorf("reverseBits(%#02x) = %#02x, want %#02x", in, got, want)
		}
	}
}
