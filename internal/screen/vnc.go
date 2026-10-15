package screen

import (
	"bufio"
	"crypto/des"
	"encoding/binary"
	"fmt"
	"image"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// An RFB client, so that a machine LocNet cannot capture directly can still be
// watched from the browser if it is already running a VNC server.
//
// This is the Wayland answer. Wayland's own capture goes through the desktop
// portal — dbus, PipeWire, and a consent dialog — which is a large dependency
// to carry for one platform. A VNC server is a dependency too, but it is one
// you install deliberately, can see running, and can turn off. Under the
// bridge the person watching still needs nothing: they open the same browser
// viewer, and the fact that the pixels arrived over RFB rather than from X11
// never reaches them.
//
// It is also the general escape hatch. Anything that speaks RFB — a virtual
// machine's console, a KVM switch, a Raspberry Pi running wayvnc — becomes
// something the console can show.

// vncTimeout bounds the handshake. The stream that follows has no deadline: a
// screen that is not changing sends nothing, for as long as that lasts.
const vncTimeout = 15 * time.Second

// RFB message types, client to server and server to client.
const (
	msgSetPixelFormat           = 0
	msgSetEncodings             = 2
	msgFramebufferUpdateRequest = 3
	msgKeyEvent                 = 4
	msgPointerEvent             = 5

	msgFramebufferUpdate   = 0
	msgSetColourMapEntries = 1
	msgBell                = 2
	msgServerCutText       = 3
)

// Encodings we ask for. Raw is mandatory and always works; CopyRect turns a
// scroll or a dragged window into a handful of bytes; DesktopSize is a
// pseudo-encoding that lets the server tell us the resolution changed instead
// of us discovering it as corruption.
var vncEncodings = []int32{1 /* CopyRect */, 0 /* Raw */, -223 /* DesktopSize */}

type vncSession struct {
	conn net.Conn
	br   *bufio.Reader

	// wmu serialises writes. Input arrives from the HTTP handler while the
	// reader goroutine is sending update requests, and two halves of two
	// messages interleaved would desynchronise the stream permanently.
	wmu sync.Mutex

	// raw is the reusable landing buffer for one rectangle. Only the reader
	// goroutine touches it.
	raw []byte

	mu      sync.Mutex
	fb      *image.RGBA // painted by the reader goroutine
	out     *image.RGBA // the copy handed to callers
	err     error
	name    string
	lastX   int
	lastY   int
	buttons uint8

	closed chan struct{}
	once   sync.Once
}

// DialVNC connects to an RFB server and serves it as a Session.
func DialVNC(addr, password string) (Session, error) {
	if !strings.Contains(addr, ":") {
		addr += ":5900"
	}
	conn, err := net.DialTimeout("tcp", addr, vncTimeout)
	if err != nil {
		return nil, unsupported("cannot reach a VNC server at %s: %v", addr, err)
	}

	s := &vncSession{conn: conn, br: bufio.NewReaderSize(conn, 1<<16), closed: make(chan struct{})}
	if err := conn.SetDeadline(time.Now().Add(vncTimeout)); err != nil {
		conn.Close()
		return nil, err
	}
	if err := s.handshake(password); err != nil {
		conn.Close()
		return nil, err
	}
	// The handshake is done; from here a quiet screen is not a failure.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}

	if err := s.requestUpdate(false); err != nil {
		conn.Close()
		return nil, err
	}
	go s.readLoop()
	return s, nil
}

// ProbeVNC reports whether something at addr speaks RFB, without completing a
// session. It is how the helper finds a local server to bridge without being
// told where one is.
func ProbeVNC(addr string, timeout time.Duration) bool {
	if !strings.Contains(addr, ":") {
		addr += ":5900"
	}
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	var banner [12]byte
	if _, err := io.ReadFull(conn, banner[:]); err != nil {
		return false
	}
	return strings.HasPrefix(string(banner[:]), "RFB ")
}

// ------------------------------------------------------------- handshake

func (s *vncSession) handshake(password string) error {
	var banner [12]byte
	if _, err := io.ReadFull(s.br, banner[:]); err != nil {
		return unsupported("no RFB greeting: %v", err)
	}
	if !strings.HasPrefix(string(banner[:]), "RFB ") {
		return unsupported("that port is not a VNC server (it said %q)",
			strings.TrimSpace(string(banner[:])))
	}
	// Answer with the highest version we implement that the server also
	// offers. 3.8 is the one with useful error messages.
	version := "RFB 003.008\n"
	if string(banner[:]) < "RFB 003.007" {
		version = "RFB 003.003\n"
	}
	if _, err := s.conn.Write([]byte(version)); err != nil {
		return err
	}

	if err := s.authenticate(version, password); err != nil {
		return err
	}

	// ClientInit: 1 means share the desktop rather than kicking off whoever
	// else is watching. Kicking someone off their own screen because a
	// monitoring page refreshed would be inexcusable.
	if _, err := s.conn.Write([]byte{1}); err != nil {
		return err
	}
	return s.serverInit()
}

func (s *vncSession) authenticate(version, password string) error {
	var chosen uint32

	if version == "RFB 003.003\n" {
		var raw [4]byte
		if _, err := io.ReadFull(s.br, raw[:]); err != nil {
			return err
		}
		chosen = binary.BigEndian.Uint32(raw[:])
	} else {
		count, err := s.br.ReadByte()
		if err != nil {
			return err
		}
		if count == 0 {
			return unsupported("the VNC server refused the connection: %s", s.readReason())
		}
		types := make([]byte, count)
		if _, err := io.ReadFull(s.br, types); err != nil {
			return err
		}
		// Prefer None; fall back to VNC authentication if a password was
		// given. Anything else — TLS, SASL, vendor schemes — is out of scope.
		for _, t := range types {
			if t == 1 {
				chosen = 1
				break
			}
			if t == 2 && password != "" {
				chosen = 2
			}
		}
		if chosen == 0 {
			if contains(types, 2) {
				return unsupported("that VNC server wants a password — pass one with -vnc-password-file")
			}
			return unsupported("that VNC server offers no authentication LocNet implements (types %v)", types)
		}
		if _, err := s.conn.Write([]byte{byte(chosen)}); err != nil {
			return err
		}
	}

	if chosen == 2 {
		var challenge [16]byte
		if _, err := io.ReadFull(s.br, challenge[:]); err != nil {
			return err
		}
		resp, err := vncAuthResponse(challenge[:], password)
		if err != nil {
			return err
		}
		if _, err := s.conn.Write(resp); err != nil {
			return err
		}
	}

	// SecurityResult. Version 3.3 with security type None skips it.
	if version == "RFB 003.003\n" && chosen == 1 {
		return nil
	}
	var result [4]byte
	if _, err := io.ReadFull(s.br, result[:]); err != nil {
		return err
	}
	if binary.BigEndian.Uint32(result[:]) != 0 {
		reason := s.readReason()
		if reason == "" {
			reason = "the password was rejected"
		}
		return unsupported("the VNC server refused the connection: %s", reason)
	}
	return nil
}

// readReason reads the length-prefixed explanation 3.8 servers send with a
// failure. An older server sends nothing, which is why this never blocks
// waiting for it beyond the handshake deadline already in force.
func (s *vncSession) readReason() string {
	var n [4]byte
	if _, err := io.ReadFull(s.br, n[:]); err != nil {
		return ""
	}
	length := binary.BigEndian.Uint32(n[:])
	if length == 0 || length > 4096 {
		return ""
	}
	msg := make([]byte, length)
	if _, err := io.ReadFull(s.br, msg); err != nil {
		return ""
	}
	return strings.TrimSpace(string(msg))
}

// vncAuthResponse answers a challenge with DES, as the protocol specifies.
//
// The scheme is weak and has been since 1998: the key is eight bytes of
// password with every byte's bits reversed, and the cipher is single DES. It
// is implemented here because it is what VNC servers ask for, not because it
// protects anything. What protects this session is that the bridge runs on
// loopback, on the same machine as the server.
func vncAuthResponse(challenge []byte, password string) ([]byte, error) {
	key := make([]byte, 8)
	copy(key, password)
	for i, b := range key {
		key[i] = reverseBits(b)
	}
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 16)
	block.Encrypt(out[0:8], challenge[0:8])
	block.Encrypt(out[8:16], challenge[8:16])
	return out, nil
}

func reverseBits(b byte) byte {
	var out byte
	for i := 0; i < 8; i++ {
		out <<= 1
		out |= b & 1
		b >>= 1
	}
	return out
}

func contains(haystack []byte, needle byte) bool {
	for _, b := range haystack {
		if b == needle {
			return true
		}
	}
	return false
}

// serverInit reads the framebuffer's size and name, then asks for the pixel
// layout and encodings we want.
func (s *vncSession) serverInit() error {
	head := make([]byte, 24)
	if _, err := io.ReadFull(s.br, head); err != nil {
		return err
	}
	w := int(binary.BigEndian.Uint16(head[0:]))
	h := int(binary.BigEndian.Uint16(head[2:]))
	nameLen := binary.BigEndian.Uint32(head[20:])
	if nameLen > 0 && nameLen < 4096 {
		name := make([]byte, nameLen)
		if _, err := io.ReadFull(s.br, name); err != nil {
			return err
		}
		s.name = string(name)
	}
	if w <= 0 || h <= 0 || w > 16384 || h > 16384 {
		return unsupported("the VNC server reports a %dx%d screen, which cannot be right", w, h)
	}
	s.resize(w, h)

	// Ask for exactly the layout the rest of this package already speaks:
	// 32 bits, little-endian, blue in the low byte. That makes the reply
	// bytes B,G,R,X, which is what both X11 and GDI hand us.
	pf := []byte{
		msgSetPixelFormat, 0, 0, 0,
		32,     // bits per pixel
		24,     // depth
		0,      // big-endian flag: no
		1,      // true colour
		0, 255, // red max
		0, 255, // green max
		0, 255, // blue max
		16, 8, 0, // red, green, blue shift
		0, 0, 0, // padding
	}
	if _, err := s.conn.Write(pf); err != nil {
		return err
	}

	enc := make([]byte, 4+4*len(vncEncodings))
	enc[0] = msgSetEncodings
	binary.BigEndian.PutUint16(enc[2:], uint16(len(vncEncodings)))
	for i, e := range vncEncodings {
		binary.BigEndian.PutUint32(enc[4+i*4:], uint32(e))
	}
	_, err := s.conn.Write(enc)
	return err
}

func (s *vncSession) resize(w, h int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fb = image.NewRGBA(image.Rect(0, 0, w, h))
	s.out = image.NewRGBA(image.Rect(0, 0, w, h))
}

// ------------------------------------------------------------- reading

// requestUpdate asks for the next frame. Incremental means "only what changed",
// which is every request after the first.
func (s *vncSession) requestUpdate(incremental bool) error {
	s.mu.Lock()
	fb := s.fb
	s.mu.Unlock()
	if fb == nil {
		return fmt.Errorf("vnc: no framebuffer yet")
	}
	req := make([]byte, 10)
	req[0] = msgFramebufferUpdateRequest
	if incremental {
		req[1] = 1
	}
	binary.BigEndian.PutUint16(req[6:], uint16(fb.Rect.Dx()))
	binary.BigEndian.PutUint16(req[8:], uint16(fb.Rect.Dy()))

	s.wmu.Lock()
	defer s.wmu.Unlock()
	_, err := s.conn.Write(req)
	return err
}

// readLoop owns every read on the connection for the life of the session.
func (s *vncSession) readLoop() {
	defer s.Close()
	for {
		select {
		case <-s.closed:
			return
		default:
		}

		kind, err := s.br.ReadByte()
		if err != nil {
			s.fail(err)
			return
		}
		switch kind {
		case msgFramebufferUpdate:
			if err := s.readUpdate(); err != nil {
				s.fail(err)
				return
			}
			// Ask for the next one straight away. The server holds the
			// request until something changes, so this is a long poll and
			// not a busy loop.
			if err := s.requestUpdate(true); err != nil {
				s.fail(err)
				return
			}
		case msgSetColourMapEntries:
			if err := s.skipColourMap(); err != nil {
				s.fail(err)
				return
			}
		case msgBell:
			// Nothing sensible to do with a bell in a browser tab.
		case msgServerCutText:
			if err := s.skipCutText(); err != nil {
				s.fail(err)
				return
			}
		default:
			// An unknown message means the stream is no longer parseable:
			// there is no length to skip by. Better to stop than to
			// misinterpret everything after it.
			s.fail(fmt.Errorf("vnc: unexpected message type %d", kind))
			return
		}
	}
}

func (s *vncSession) readUpdate() error {
	head := make([]byte, 3)
	if _, err := io.ReadFull(s.br, head); err != nil {
		return err
	}
	rects := int(binary.BigEndian.Uint16(head[1:]))

	for i := 0; i < rects; i++ {
		var rh [12]byte
		if _, err := io.ReadFull(s.br, rh[:]); err != nil {
			return err
		}
		x := int(binary.BigEndian.Uint16(rh[0:]))
		y := int(binary.BigEndian.Uint16(rh[2:]))
		w := int(binary.BigEndian.Uint16(rh[4:]))
		h := int(binary.BigEndian.Uint16(rh[6:]))
		enc := int32(binary.BigEndian.Uint32(rh[8:]))

		switch enc {
		case 0:
			if err := s.readRaw(x, y, w, h); err != nil {
				return err
			}
		case 1:
			if err := s.readCopyRect(x, y, w, h); err != nil {
				return err
			}
		case -223: // DesktopSize
			s.resize(w, h)
			// The new framebuffer is empty, so the next request has to be
			// for all of it rather than for what changed.
			if err := s.requestUpdate(false); err != nil {
				return err
			}
		default:
			return fmt.Errorf("vnc: the server used encoding %d, which was not offered", enc)
		}
	}
	return nil
}

func (s *vncSession) readRaw(x, y, w, h int) error {
	if w <= 0 || h <= 0 {
		return nil
	}
	// The whole rectangle is read before any of it is painted, so that a
	// caller capturing at the same moment sees the frame before or the frame
	// after and never a rectangle half filled in. The buffer is kept between
	// updates: a full-screen refresh is eight megabytes and allocating that
	// per frame would be the most expensive thing in the session.
	need := w * h * 4
	if cap(s.raw) < need {
		s.raw = make([]byte, need)
	}
	buf := s.raw[:need]
	if _, err := io.ReadFull(s.br, buf); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	fb := s.fb
	if fb == nil {
		return nil
	}
	for j := 0; j < h; j++ {
		dy := y + j
		if dy < 0 || dy >= fb.Rect.Dy() {
			continue
		}
		src := buf[j*w*4:]
		off := fb.PixOffset(0, dy)
		for i := 0; i < w; i++ {
			dx := x + i
			if dx < 0 || dx >= fb.Rect.Dx() {
				continue
			}
			p := off + dx*4
			// Little-endian 32-bit with blue in the low byte: B,G,R,X.
			fb.Pix[p+0] = src[i*4+2]
			fb.Pix[p+1] = src[i*4+1]
			fb.Pix[p+2] = src[i*4+0]
			fb.Pix[p+3] = 0xff
		}
	}
	return nil
}

func (s *vncSession) readCopyRect(x, y, w, h int) error {
	var src [4]byte
	if _, err := io.ReadFull(s.br, src[:]); err != nil {
		return err
	}
	sx := int(binary.BigEndian.Uint16(src[0:]))
	sy := int(binary.BigEndian.Uint16(src[2:]))

	s.mu.Lock()
	defer s.mu.Unlock()
	fb := s.fb
	if fb == nil {
		return nil
	}
	// Copy row by row, and downwards or upwards depending on which way the
	// rectangle moved, so an overlapping copy does not smear itself.
	rows := make([]int, 0, h)
	if sy < y {
		for j := h - 1; j >= 0; j-- {
			rows = append(rows, j)
		}
	} else {
		for j := 0; j < h; j++ {
			rows = append(rows, j)
		}
	}
	for _, j := range rows {
		if sy+j < 0 || sy+j >= fb.Rect.Dy() || y+j < 0 || y+j >= fb.Rect.Dy() {
			continue
		}
		n := min(w, min(fb.Rect.Dx()-sx, fb.Rect.Dx()-x))
		if n <= 0 {
			continue
		}
		from := fb.PixOffset(sx, sy+j)
		to := fb.PixOffset(x, y+j)
		copy(fb.Pix[to:to+n*4], fb.Pix[from:from+n*4])
	}
	return nil
}

func (s *vncSession) skipColourMap() error {
	var head [5]byte
	if _, err := io.ReadFull(s.br, head[:]); err != nil {
		return err
	}
	n := int(binary.BigEndian.Uint16(head[3:]))
	_, err := io.CopyN(io.Discard, s.br, int64(n)*6)
	return err
}

func (s *vncSession) skipCutText() error {
	var head [7]byte
	if _, err := io.ReadFull(s.br, head[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(head[3:])
	if n > 1<<20 {
		return fmt.Errorf("vnc: clipboard message of %d bytes is out of hand", n)
	}
	_, err := io.CopyN(io.Discard, s.br, int64(n))
	return err
}

func (s *vncSession) fail(err error) {
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.mu.Unlock()
}

// ------------------------------------------------------------- Session

func (s *vncSession) Capture() (*image.RGBA, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, fmt.Errorf("the VNC connection ended: %w", s.err)
	}
	if s.fb == nil {
		return nil, fmt.Errorf("vnc: no frame yet")
	}
	// A copy, because the reader goroutine keeps painting into the
	// framebuffer while the caller is compressing what it was handed.
	if s.out == nil || s.out.Rect != s.fb.Rect {
		s.out = image.NewRGBA(s.fb.Rect)
	}
	copy(s.out.Pix, s.fb.Pix)
	return s.out, nil
}

// Pointer returns nothing: RFB has no message for "where is the server's
// pointer". The viewer draws no remote cursor over a bridged screen, and the
// one the far machine draws itself is in the picture anyway.
func (s *vncSession) Pointer() (image.Point, bool) { return image.Point{}, false }

func (s *vncSession) Controllable() bool { return true }

func (s *vncSession) Input(ev Event) error {
	switch ev.Type {
	case "move":
		s.setPos(ev.X, ev.Y)
		return s.pointer()
	case "down", "up":
		s.setPos(ev.X, ev.Y)
		bit := buttonBit(ev.Button)
		if bit == 0 {
			return nil
		}
		s.mu.Lock()
		if ev.Type == "down" {
			s.buttons |= bit
		} else {
			s.buttons &^= bit
		}
		s.mu.Unlock()
		return s.pointer()
	case "wheel":
		return s.wheel(ev)
	case "key":
		ks := keysymFor(ev.Key, ev.Code)
		if ks == 0 {
			return nil
		}
		msg := make([]byte, 8)
		msg[0] = msgKeyEvent
		if ev.Down {
			msg[1] = 1
		}
		binary.BigEndian.PutUint32(msg[4:], ks)
		return s.send(msg)
	}
	return nil
}

// wheel is a button press and release on RFB, which has no scroll message.
func (s *vncSession) wheel(ev Event) error {
	step := func(bit uint8, n int) error {
		for i := 0; i < n && i < 10; i++ {
			s.mu.Lock()
			s.buttons |= bit
			s.mu.Unlock()
			if err := s.pointer(); err != nil {
				return err
			}
			s.mu.Lock()
			s.buttons &^= bit
			s.mu.Unlock()
			if err := s.pointer(); err != nil {
				return err
			}
		}
		return nil
	}
	switch {
	case ev.DY > 0:
		return step(1<<4, ev.DY) // wheel down
	case ev.DY < 0:
		return step(1<<3, -ev.DY) // wheel up
	case ev.DX > 0:
		return step(1<<6, ev.DX)
	case ev.DX < 0:
		return step(1<<5, -ev.DX)
	}
	return nil
}

func (s *vncSession) setPos(x, y int) {
	s.mu.Lock()
	s.lastX, s.lastY = x, y
	s.mu.Unlock()
}

func (s *vncSession) pointer() error {
	s.mu.Lock()
	msg := make([]byte, 6)
	msg[0] = msgPointerEvent
	msg[1] = s.buttons
	binary.BigEndian.PutUint16(msg[2:], uint16(clamp16(s.lastX)))
	binary.BigEndian.PutUint16(msg[4:], uint16(clamp16(s.lastY)))
	s.mu.Unlock()
	return s.send(msg)
}

func buttonBit(b int) uint8 {
	switch b {
	case 1:
		return 1 << 0
	case 2:
		return 1 << 1
	case 3:
		return 1 << 2
	}
	return 0
}

func (s *vncSession) send(msg []byte) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_, err := s.conn.Write(msg)
	return err
}

func (s *vncSession) Close() error {
	s.once.Do(func() {
		close(s.closed)
		s.conn.Close()
	})
	return nil
}
