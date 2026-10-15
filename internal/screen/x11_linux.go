//go:build linux

package screen

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"image"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// This file is an X11 client, written to the wire protocol rather than to
// Xlib, because binding Xlib means cgo and cgo means LocNet stops being one
// static binary you can copy onto a machine.
//
// It implements four requests and one extension, which is all a screen viewer
// needs: GetImage to read pixels, GetGeometry to notice the resolution
// changing, QueryPointer to draw the remote cursor, GetKeyboardMapping to turn
// a key into a keycode, and XTEST to press it.

// X11 request opcodes.
const (
	opGetGeometry           = 14
	opQueryPointer          = 38
	opGetImage              = 73
	opChangeKeyboardMapping = 100
	opGetKeyboardMapping    = 101
	opQueryExtension        = 98
)

// XTEST event types, which are the core protocol's event numbers.
const (
	xtKeyPress      = 2
	xtKeyRelease    = 3
	xtButtonPress   = 4
	xtButtonRelease = 5
	xtMotionNotify  = 6
)

type x11 struct {
	c   net.Conn
	br  *bufio.Reader
	seq uint16

	root          uint32
	width, height uint16
	depth         byte

	ridBase, ridMask uint32
	ridNext          uint32
	bpp              byte
	scanlinePad      byte
	msbFirst         bool
	minKeycode       byte
	maxKeycode       byte

	testOp byte // XTEST major opcode; 0 when the extension is absent

	raw []byte      // last GetImage payload, reused
	img *image.RGBA // converted frame, reused

	perKeycode byte
	keysyms    map[uint32]byte // keysym -> keycode
	scratch    byte            // spare keycode for keysyms the layout lacks
	scratchSym uint32

	lastGeom time.Time
}

// dialX11 opens a connection to the X server named by DISPLAY and completes
// the setup handshake.
func dialX11() (*x11, error) {
	display := os.Getenv("DISPLAY")
	if display == "" {
		return nil, unsupported("DISPLAY is not set, so this process is not attached to a graphical session")
	}
	host, dispNum, err := parseDisplay(display)
	if err != nil {
		return nil, err
	}

	var conn net.Conn
	if host == "" || host == "unix" {
		path := fmt.Sprintf("/tmp/.X11-unix/X%d", dispNum)
		conn, err = net.DialTimeout("unix", path, 5*time.Second)
		if err != nil {
			return nil, unsupported("cannot reach the X server at %s: %v", path, err)
		}
	} else {
		addr := net.JoinHostPort(host, strconv.Itoa(6000+dispNum))
		conn, err = net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			return nil, unsupported("cannot reach the X server at %s: %v", addr, err)
		}
	}

	x := &x11{c: conn, br: bufio.NewReaderSize(conn, 1<<16), keysyms: map[uint32]byte{}}
	name, data := xauth(dispNum)
	if err := x.handshake(name, data); err != nil {
		conn.Close()
		return nil, err
	}
	x.probeXTest()
	x.loadKeymap()
	if os.Getenv("LOCNET_SCREEN_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "x11: root=%#x %dx%d depth=%d bpp=%d pad=%d msb=%v xtest=%d keys=%d-%d\n",
			x.root, x.width, x.height, x.depth, x.bpp, x.scanlinePad, x.msbFirst,
			x.testOp, x.minKeycode, x.maxKeycode)
	}
	return x, nil
}

// parseDisplay splits "host:display.screen" into its host and display number.
func parseDisplay(d string) (host string, num int, err error) {
	i := strings.LastIndex(d, ":")
	if i < 0 {
		return "", 0, unsupported("DISPLAY=%q is not a display address", d)
	}
	host = d[:i]
	rest := d[i+1:]
	if j := strings.Index(rest, "."); j >= 0 {
		rest = rest[:j]
	}
	num, err = strconv.Atoi(rest)
	if err != nil {
		return "", 0, unsupported("DISPLAY=%q has no display number", d)
	}
	return host, num, nil
}

// xauth finds the cookie for this display in the Xauthority file.
//
// A missing or unreadable file is not an error: some servers are set up with
// authentication off, and the handshake will say so plainly if this one is
// not.
func xauth(dispNum int) (name, data []byte) {
	path := os.Getenv("XAUTHORITY")
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			if u, uerr := user.Current(); uerr == nil {
				home = u.HomeDir
			}
		}
		if home == "" {
			return nil, nil
		}
		path = filepath.Join(home, ".Xauthority")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil
	}
	hostname, _ := os.Hostname()
	want := strconv.Itoa(dispNum)

	var fallbackName, fallbackData []byte
	p := 0
	readChunk := func() ([]byte, bool) {
		if p+2 > len(raw) {
			return nil, false
		}
		n := int(binary.BigEndian.Uint16(raw[p:]))
		p += 2
		if p+n > len(raw) {
			return nil, false
		}
		out := raw[p : p+n]
		p += n
		return out, true
	}
	for p+2 <= len(raw) {
		p += 2 // family, which we do not filter on: a "wild" entry is common
		addr, ok := readChunk()
		if !ok {
			break
		}
		number, ok := readChunk()
		if !ok {
			break
		}
		aName, ok := readChunk()
		if !ok {
			break
		}
		aData, ok := readChunk()
		if !ok {
			break
		}
		if string(aName) != "MIT-MAGIC-COOKIE-1" {
			continue
		}
		if len(number) != 0 && string(number) != want {
			continue
		}
		if string(addr) == hostname {
			return aName, aData
		}
		if fallbackName == nil {
			fallbackName, fallbackData = aName, aData
		}
	}
	return fallbackName, fallbackData
}

// handshake sends the connection setup and parses the server's answer.
func (x *x11) handshake(authName, authData []byte) error {
	req := make([]byte, 0, 12+pad4(len(authName))+pad4(len(authData)))
	req = append(req, 'l', 0) // little-endian, one pad byte
	req = binary.LittleEndian.AppendUint16(req, 11)
	req = binary.LittleEndian.AppendUint16(req, 0)
	req = binary.LittleEndian.AppendUint16(req, uint16(len(authName)))
	req = binary.LittleEndian.AppendUint16(req, uint16(len(authData)))
	req = append(req, 0, 0)
	req = append(req, authName...)
	req = append(req, make([]byte, pad4(len(authName))-len(authName))...)
	req = append(req, authData...)
	req = append(req, make([]byte, pad4(len(authData))-len(authData))...)
	if _, err := x.c.Write(req); err != nil {
		return fmt.Errorf("x11: setup: %w", err)
	}

	head := make([]byte, 8)
	if _, err := io.ReadFull(x.br, head); err != nil {
		return fmt.Errorf("x11: setup reply: %w", err)
	}
	body := make([]byte, int(binary.LittleEndian.Uint16(head[6:]))*4)
	if _, err := io.ReadFull(x.br, body); err != nil {
		return fmt.Errorf("x11: setup reply: %w", err)
	}
	switch head[0] {
	case 0:
		reason := strings.TrimRight(string(body[:min(int(head[1]), len(body))]), "\x00")
		return unsupported("the X server refused the connection: %s", reason)
	case 2:
		return unsupported("the X server wants further authentication, which LocNet does not implement")
	}
	return x.parseSetup(body)
}

// parseSetup reads the fixed part, the pixmap formats and the first screen.
func (x *x11) parseSetup(b []byte) error {
	if len(b) < 32 {
		return fmt.Errorf("x11: setup reply is too short")
	}
	x.ridBase = binary.LittleEndian.Uint32(b[4:])
	x.ridMask = binary.LittleEndian.Uint32(b[8:])
	vendorLen := int(binary.LittleEndian.Uint16(b[16:]))
	numScreens := int(b[20])
	numFormats := int(b[21])
	x.msbFirst = b[22] == 1
	x.minKeycode = b[26]
	x.maxKeycode = b[27]

	p := 32 + pad4(vendorLen)
	formats := p
	p += numFormats * 8
	if numScreens == 0 || p+40 > len(b) {
		return fmt.Errorf("x11: setup reply has no usable screen")
	}

	// The first screen is the one a viewer means by "the screen". A machine
	// with two X screens (as opposed to two monitors on one screen, which is
	// the normal arrangement) shows the first.
	scr := b[p:]
	x.root = binary.LittleEndian.Uint32(scr[0:])
	x.width = binary.LittleEndian.Uint16(scr[20:])
	x.height = binary.LittleEndian.Uint16(scr[22:])
	x.depth = scr[38]

	for i := 0; i < numFormats; i++ {
		f := b[formats+i*8:]
		if f[0] == x.depth {
			x.bpp = f[1]
			x.scanlinePad = f[2]
			break
		}
	}
	if x.bpp == 0 {
		return fmt.Errorf("x11: the server lists no pixel format for depth %d", x.depth)
	}
	if x.bpp != 32 && x.bpp != 24 && x.bpp != 16 {
		return unsupported("this screen is %d bits per pixel, which LocNet cannot read", x.bpp)
	}
	return nil
}

// ---------------------------------------------------------------- plumbing

// request writes a complete request and returns its sequence number.
func (x *x11) request(b []byte) (uint16, error) {
	x.seq++
	if _, err := x.c.Write(b); err != nil {
		return 0, fmt.Errorf("x11: %w", err)
	}
	return x.seq, nil
}

// reply reads until the answer to seq arrives.
//
// Two things can turn up first and both are normal. Events — MappingNotify is
// broadcast to every client whenever anyone changes the keyboard layout — and
// errors belonging to earlier requests that had no reply to carry them, such
// as a rejected fake input. Neither is a reason to give up on the connection.
func (x *x11) reply(seq uint16) ([]byte, error) {
	head := make([]byte, 32)
	for {
		if _, err := io.ReadFull(x.br, head); err != nil {
			return nil, fmt.Errorf("x11: %w", err)
		}
		switch head[0] {
		case 0: // error
			got := binary.LittleEndian.Uint16(head[2:])
			if got != seq {
				continue // an earlier request's complaint
			}
			return nil, fmt.Errorf("x11: request failed with error code %d", head[1])
		case 1: // reply
			extra := int(binary.LittleEndian.Uint32(head[4:])) * 4
			out := make([]byte, 32+extra)
			copy(out, head)
			if extra > 0 {
				if _, err := io.ReadFull(x.br, out[32:]); err != nil {
					return nil, fmt.Errorf("x11: %w", err)
				}
			}
			if binary.LittleEndian.Uint16(head[2:]) != seq {
				continue // a reply we are no longer waiting for
			}
			return out, nil
		default: // event
			continue
		}
	}
}

// replyInto reads the answer to seq, using buf for the variable part so that a
// megabytes-long image does not allocate on every frame.
func (x *x11) replyInto(seq uint16, buf []byte) (head []byte, body []byte, err error) {
	head = make([]byte, 32)
	for {
		if _, err := io.ReadFull(x.br, head); err != nil {
			return nil, nil, fmt.Errorf("x11: %w", err)
		}
		switch head[0] {
		case 0:
			if binary.LittleEndian.Uint16(head[2:]) != seq {
				continue
			}
			return nil, nil, fmt.Errorf("x11: request failed with error code %d", head[1])
		case 1:
			extra := int(binary.LittleEndian.Uint32(head[4:])) * 4
			if cap(buf) < extra {
				buf = make([]byte, extra)
			}
			buf = buf[:extra]
			if extra > 0 {
				if _, err := io.ReadFull(x.br, buf); err != nil {
					return nil, nil, fmt.Errorf("x11: %w", err)
				}
			}
			if binary.LittleEndian.Uint16(head[2:]) != seq {
				continue
			}
			return head, buf, nil
		default:
			continue
		}
	}
}

func pad4(n int) int { return (n + 3) &^ 3 }

// newID allocates a resource identifier out of the range the server reserved
// for this connection at setup.
func (x *x11) newID() uint32 {
	x.ridNext++
	return x.ridBase | (x.ridNext & x.ridMask)
}

// ------------------------------------------------------------------ capture

// Capture reads the whole root window.
func (x *x11) Capture() (*image.RGBA, error) {
	// Resolutions change: someone plugs in a monitor, or a VM window is
	// resized. Checking every two seconds costs one small round trip and
	// saves sending a stream that is silently the wrong shape.
	if time.Since(x.lastGeom) > 2*time.Second {
		if w, h, err := x.geometry(); err == nil && (w != x.width || h != x.height) {
			x.width, x.height = w, h
			x.img = nil
		}
		x.lastGeom = time.Now()
	}

	req := make([]byte, 20)
	req[0] = opGetImage
	req[1] = 2 // ZPixmap
	binary.LittleEndian.PutUint16(req[2:], 5)
	binary.LittleEndian.PutUint32(req[4:], x.root)
	binary.LittleEndian.PutUint16(req[8:], 0)
	binary.LittleEndian.PutUint16(req[10:], 0)
	binary.LittleEndian.PutUint16(req[12:], x.width)
	binary.LittleEndian.PutUint16(req[14:], x.height)
	binary.LittleEndian.PutUint32(req[16:], 0xffffffff)

	seq, err := x.request(req)
	if err != nil {
		return nil, err
	}
	_, body, err := x.replyInto(seq, x.raw)
	if err != nil {
		return nil, err
	}
	x.raw = body

	w, h := int(x.width), int(x.height)
	if x.img == nil || x.img.Rect.Dx() != w || x.img.Rect.Dy() != h {
		x.img = image.NewRGBA(image.Rect(0, 0, w, h))
	}
	if err := x.convert(body, w, h); err != nil {
		return nil, err
	}
	return x.img, nil
}

// convert turns the server's pixel layout into RGBA.
func (x *x11) convert(src []byte, w, h int) error {
	unit := int(x.scanlinePad)
	if unit == 0 {
		unit = 32
	}
	rowBytes := ((w*int(x.bpp) + unit - 1) / unit) * unit / 8
	if len(src) < rowBytes*h {
		return fmt.Errorf("x11: short image: got %d bytes, wanted %d", len(src), rowBytes*h)
	}
	dst := x.img.Pix
	stride := x.img.Stride

	for y := 0; y < h; y++ {
		s := src[y*rowBytes:]
		d := dst[y*stride:]
		switch {
		case x.bpp == 32 && !x.msbFirst:
			for i, j := 0, 0; i < w*4; i, j = i+4, j+4 {
				d[j+0] = s[i+2]
				d[j+1] = s[i+1]
				d[j+2] = s[i+0]
				d[j+3] = 0xff
			}
		case x.bpp == 32 && x.msbFirst:
			for i, j := 0, 0; i < w*4; i, j = i+4, j+4 {
				d[j+0] = s[i+1]
				d[j+1] = s[i+2]
				d[j+2] = s[i+3]
				d[j+3] = 0xff
			}
		case x.bpp == 24:
			for i, j := 0, 0; i < w*3; i, j = i+3, j+4 {
				if x.msbFirst {
					d[j+0], d[j+1], d[j+2] = s[i+0], s[i+1], s[i+2]
				} else {
					d[j+0], d[j+1], d[j+2] = s[i+2], s[i+1], s[i+0]
				}
				d[j+3] = 0xff
			}
		case x.bpp == 16:
			for i, j := 0, 0; i < w*2; i, j = i+2, j+4 {
				v := binary.LittleEndian.Uint16(s[i:])
				if x.msbFirst {
					v = binary.BigEndian.Uint16(s[i:])
				}
				// 5-6-5, expanded so that full-scale stays full-scale.
				r := byte((v >> 11) & 0x1f)
				g := byte((v >> 5) & 0x3f)
				b := byte(v & 0x1f)
				d[j+0] = r<<3 | r>>2
				d[j+1] = g<<2 | g>>4
				d[j+2] = b<<3 | b>>2
				d[j+3] = 0xff
			}
		}
	}
	return nil
}

// geometry asks the server how big the root window is now.
func (x *x11) geometry() (uint16, uint16, error) {
	req := make([]byte, 8)
	req[0] = opGetGeometry
	binary.LittleEndian.PutUint16(req[2:], 2)
	binary.LittleEndian.PutUint32(req[4:], x.root)
	seq, err := x.request(req)
	if err != nil {
		return 0, 0, err
	}
	r, err := x.reply(seq)
	if err != nil {
		return 0, 0, err
	}
	return binary.LittleEndian.Uint16(r[16:]), binary.LittleEndian.Uint16(r[18:]), nil
}

// Pointer returns the mouse position on the root window.
func (x *x11) Pointer() (image.Point, bool) {
	req := make([]byte, 8)
	req[0] = opQueryPointer
	binary.LittleEndian.PutUint16(req[2:], 2)
	binary.LittleEndian.PutUint32(req[4:], x.root)
	seq, err := x.request(req)
	if err != nil {
		return image.Point{}, false
	}
	r, err := x.reply(seq)
	if err != nil {
		return image.Point{}, false
	}
	px := int(int16(binary.LittleEndian.Uint16(r[16:])))
	py := int(int16(binary.LittleEndian.Uint16(r[18:])))
	return image.Pt(px, py), true
}

// -------------------------------------------------------------------- input

// probeXTest looks for the XTEST extension, which is the only supported way to
// synthesise input into someone else's session.
func (x *x11) probeXTest() {
	const name = "XTEST"
	req := make([]byte, 8+pad4(len(name)))
	req[0] = opQueryExtension
	binary.LittleEndian.PutUint16(req[2:], uint16(len(req)/4))
	binary.LittleEndian.PutUint16(req[4:], uint16(len(name)))
	copy(req[8:], name)
	seq, err := x.request(req)
	if err != nil {
		return
	}
	r, err := x.reply(seq)
	if err != nil || r[8] == 0 {
		return
	}
	major := r[9]

	// XTestGetVersion first, as the extension's specification asks. Servers
	// do not enforce it, but a client that skips it is relying on that.
	ver := make([]byte, 8)
	ver[0] = major
	ver[1] = 0
	binary.LittleEndian.PutUint16(ver[2:], 2)
	ver[4] = 2
	binary.LittleEndian.PutUint16(ver[6:], 2)
	seq, err = x.request(ver)
	if err != nil {
		return
	}
	if _, err := x.reply(seq); err != nil {
		return
	}
	x.testOp = major
}

// loadKeymap builds the keysym-to-keycode lookup that turns a key a browser
// reported into something XTEST can press.
func (x *x11) loadKeymap() {
	count := int(x.maxKeycode) - int(x.minKeycode) + 1
	if count <= 0 || count > 255 {
		return
	}
	req := make([]byte, 8)
	req[0] = opGetKeyboardMapping
	binary.LittleEndian.PutUint16(req[2:], 2)
	req[4] = x.minKeycode
	req[5] = byte(count)
	seq, err := x.request(req)
	if err != nil {
		return
	}
	r, err := x.reply(seq)
	if err != nil {
		return
	}
	per := int(r[1])
	if per == 0 {
		return
	}
	x.perKeycode = byte(per)
	syms := r[32:]

	clear(x.keysyms)
	x.scratch = 0
	for i := 0; i < count; i++ {
		code := byte(int(x.minKeycode) + i)
		empty := true
		for j := 0; j < per; j++ {
			off := (i*per + j) * 4
			if off+4 > len(syms) {
				break
			}
			ks := binary.LittleEndian.Uint32(syms[off:])
			if ks == 0 {
				continue
			}
			empty = false
			// First writer wins, so the lowest keycode carrying a keysym is
			// the one pressed. That matters for duplicated symbols like the
			// numeric keypad, where the main row is the safer choice.
			if _, seen := x.keysyms[ks]; !seen {
				x.keysyms[ks] = code
			}
		}
		if empty && x.scratch == 0 {
			x.scratch = code
		}
	}
}

// Input performs one event.
func (x *x11) Input(ev Event) error {
	if x.testOp == 0 {
		return fmt.Errorf("this X server has no XTEST extension, so it cannot be driven remotely")
	}
	switch ev.Type {
	case "move":
		return x.fake(xtMotionNotify, 0, ev.X, ev.Y)
	case "down", "up":
		b := ev.Button
		if b < 1 || b > 9 {
			return nil
		}
		// Position first: a click that lands where the pointer used to be is
		// worse than no click at all.
		if err := x.fake(xtMotionNotify, 0, ev.X, ev.Y); err != nil {
			return err
		}
		t := byte(xtButtonPress)
		if ev.Type == "up" {
			t = xtButtonRelease
		}
		return x.fake(t, byte(b), 0, 0)
	case "wheel":
		return x.wheel(ev)
	case "key":
		return x.key(ev)
	}
	return nil
}

func (x *x11) wheel(ev Event) error {
	press := func(b byte, n int) error {
		for i := 0; i < n && i < 10; i++ {
			if err := x.fake(xtButtonPress, b, 0, 0); err != nil {
				return err
			}
			if err := x.fake(xtButtonRelease, b, 0, 0); err != nil {
				return err
			}
		}
		return nil
	}
	if ev.DY > 0 {
		return press(5, ev.DY)
	}
	if ev.DY < 0 {
		return press(4, -ev.DY)
	}
	if ev.DX > 0 {
		return press(7, ev.DX)
	}
	if ev.DX < 0 {
		return press(6, -ev.DX)
	}
	return nil
}

func (x *x11) key(ev Event) error {
	ks := keysymFor(ev.Key, ev.Code)
	if ks == 0 {
		return nil
	}
	code, ok := x.keysyms[ks]
	if !ok {
		var err error
		code, err = x.mapScratch(ks)
		if err != nil {
			return err
		}
	}
	t := byte(xtKeyPress)
	if !ev.Down {
		t = xtKeyRelease
	}
	return x.fake(t, code, 0, 0)
}

// mapScratch binds a keysym the local layout does not have to a spare keycode.
//
// This is how a viewer on a British keyboard types £ into a machine set to
// US: there is no keycode for it, so one of the unused ones is temporarily
// taught the symbol. Both shift levels get the same keysym, so it types the
// same thing whether or not the viewer is holding shift.
func (x *x11) mapScratch(ks uint32) (byte, error) {
	if x.scratch == 0 {
		return 0, fmt.Errorf("the remote keyboard layout has no key for this character")
	}
	if x.scratchSym == ks {
		return x.scratch, nil
	}
	per := 2
	req := make([]byte, 8+per*4)
	req[0] = opChangeKeyboardMapping
	req[1] = 1 // one keycode
	binary.LittleEndian.PutUint16(req[2:], uint16(len(req)/4))
	req[4] = x.scratch
	req[5] = byte(per)
	binary.LittleEndian.PutUint32(req[8:], ks)
	binary.LittleEndian.PutUint32(req[12:], ks)
	if _, err := x.request(req); err != nil {
		return 0, err
	}
	// ChangeKeyboardMapping has no reply, and pressing the key before the
	// server has processed it would send the old symbol. Any request that
	// does have a reply forces the ordering.
	if _, _, err := x.geometry(); err != nil {
		return 0, err
	}
	x.scratchSym = ks
	return x.scratch, nil
}

// fake sends one XTestFakeInput.
func (x *x11) fake(typ, detail byte, px, py int) error {
	req := make([]byte, 36)
	req[0] = x.testOp
	req[1] = 2 // FakeInput
	binary.LittleEndian.PutUint16(req[2:], 9)
	req[4] = typ
	req[5] = detail
	binary.LittleEndian.PutUint32(req[8:], 0) // no delay
	binary.LittleEndian.PutUint32(req[12:], x.root)
	binary.LittleEndian.PutUint16(req[24:], uint16(int16(px)))
	binary.LittleEndian.PutUint16(req[26:], uint16(int16(py)))
	_, err := x.request(req)
	return err
}

func (x *x11) Controllable() bool { return x.testOp != 0 }

func (x *x11) Close() error { return x.c.Close() }
