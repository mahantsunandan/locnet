//go:build windows

package screen

import (
	"fmt"
	"image"
	"sync"
	"syscall"
	"unsafe"
)

// Windows capture is GDI: a device context for the whole virtual desktop, a
// device-independent bitmap to blit into, and a slice pointing straight at the
// bitmap's pixels. Input is SendInput. Both come out of DLLs Windows already
// has, so this stays one binary with nothing to install.
//
// This must run in the interactive session. A service lives in session 0,
// whose desktop is a permanently blank 1024×768 one that nobody is looking at,
// which is why locnetd starts `locnet desktop serve` in the user's session
// rather than capturing anything itself.

var (
	user32 = syscall.NewLazyDLL("user32.dll")
	gdi32  = syscall.NewLazyDLL("gdi32.dll")

	procGetDC                     = user32.NewProc("GetDC")
	procReleaseDC                 = user32.NewProc("ReleaseDC")
	procGetSystemMetrics          = user32.NewProc("GetSystemMetrics")
	procSendInput                 = user32.NewProc("SendInput")
	procGetCursorPos              = user32.NewProc("GetCursorPos")
	procSetProcessDPIAware        = user32.NewProc("SetProcessDPIAware")
	procSetProcessDpiAwarenessCtx = user32.NewProc("SetProcessDpiAwarenessContext")

	procCreateCompatibleDC = gdi32.NewProc("CreateCompatibleDC")
	procCreateDIBSection   = gdi32.NewProc("CreateDIBSection")
	procSelectObject       = gdi32.NewProc("SelectObject")
	procDeleteObject       = gdi32.NewProc("DeleteObject")
	procDeleteDC           = gdi32.NewProc("DeleteDC")
	procBitBlt             = gdi32.NewProc("BitBlt")
)

const (
	smXVirtualScreen  = 76
	smYVirtualScreen  = 77
	smCXVirtualScreen = 78
	smCYVirtualScreen = 79

	srcCopy    = 0x00CC0020
	captureBlt = 0x40000000

	inputMouse    = 0
	inputKeyboard = 1

	mouseeventfMove        = 0x0001
	mouseeventfLeftDown    = 0x0002
	mouseeventfLeftUp      = 0x0004
	mouseeventfRightDown   = 0x0008
	mouseeventfRightUp     = 0x0010
	mouseeventfMiddleDown  = 0x0020
	mouseeventfMiddleUp    = 0x0040
	mouseeventfWheel       = 0x0800
	mouseeventfHWheel      = 0x1000
	mouseeventfVirtualDesk = 0x4000
	mouseeventfAbsolute    = 0x8000

	keyeventfExtended = 0x0001
	keyeventfKeyUp    = 0x0002
	keyeventfUnicode  = 0x0004

	wheelDelta = 120
)

type bitmapInfoHeader struct {
	Size          uint32
	Width         int32
	Height        int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
}

type bitmapInfo struct {
	Header bitmapInfoHeader
	Colors [3]uint32
}

type mouseInput struct {
	dx        int32
	dy        int32
	mouseData uint32
	flags     uint32
	time      uint32
	extra     uintptr
}

type keybdInput struct {
	vk    uint16
	scan  uint16
	flags uint32
	time  uint32
	extra uintptr
}

// wInput is Windows' INPUT. The union is emulated by giving the struct the
// largest member and reinterpreting it for the keyboard case: both members
// start at the same offset and share the pointer-sized alignment that decides
// the struct's size, so unsafe.Sizeof gives the cbSize SendInput expects on
// both 32- and 64-bit builds.
type wInput struct {
	typ uint32
	mi  mouseInput
}

func (i *wInput) kbd() *keybdInput { return (*keybdInput)(unsafe.Pointer(&i.mi)) }

var dpiOnce sync.Once

type winSession struct {
	x, y, w, h int

	screenDC uintptr
	memDC    uintptr
	bitmap   uintptr
	bits     unsafe.Pointer

	img *image.RGBA

	// modsDown counts the control and alt keys the viewer is holding. A
	// character typed while one of them is down has to be sent as a virtual
	// key rather than as Unicode, or Ctrl+C arrives as the letter c.
	modsDown int
}

func open() (Session, error) {
	dpiOnce.Do(func() {
		// Per-monitor v2 if this Windows has it, so a 4K screen is captured
		// at 4K rather than at the scaled size a DPI-unaware process sees.
		if procSetProcessDpiAwarenessCtx.Find() == nil {
			const perMonitorV2 = ^uintptr(3) // (DPI_AWARENESS_CONTEXT)-4
			if r, _, _ := procSetProcessDpiAwarenessCtx.Call(perMonitorV2); r != 0 {
				return
			}
		}
		procSetProcessDPIAware.Call()
	})

	s := &winSession{}
	if err := s.reshape(); err != nil {
		return nil, err
	}
	return s, nil
}

// reshape rebuilds the capture bitmap for the current virtual desktop size.
func (s *winSession) reshape() error {
	x := int(int32(metric(smXVirtualScreen)))
	y := int(int32(metric(smYVirtualScreen)))
	w := int(int32(metric(smCXVirtualScreen)))
	h := int(int32(metric(smCYVirtualScreen)))
	if w <= 0 || h <= 0 {
		return unsupported("Windows reports no screen attached to this session")
	}
	if s.bitmap != 0 && x == s.x && y == s.y && w == s.w && h == s.h {
		return nil
	}
	s.release()
	s.x, s.y, s.w, s.h = x, y, w, h

	screenDC, _, _ := procGetDC.Call(0)
	if screenDC == 0 {
		return unsupported("cannot open a device context for this desktop — is this process running in the logged-in session?")
	}
	memDC, _, _ := procCreateCompatibleDC.Call(screenDC)
	if memDC == 0 {
		procReleaseDC.Call(0, screenDC)
		return fmt.Errorf("screen: CreateCompatibleDC failed")
	}

	bi := bitmapInfo{Header: bitmapInfoHeader{
		Size:     uint32(unsafe.Sizeof(bitmapInfoHeader{})),
		Width:    int32(w),
		Height:   int32(-h), // negative: rows top down, like everything else here
		Planes:   1,
		BitCount: 32,
	}}
	var bits unsafe.Pointer
	bmp, _, _ := procCreateDIBSection.Call(memDC, uintptr(unsafe.Pointer(&bi)), 0,
		uintptr(unsafe.Pointer(&bits)), 0, 0)
	if bmp == 0 || bits == nil {
		procDeleteDC.Call(memDC)
		procReleaseDC.Call(0, screenDC)
		return fmt.Errorf("screen: CreateDIBSection failed")
	}
	procSelectObject.Call(memDC, bmp)

	s.screenDC, s.memDC, s.bitmap, s.bits = screenDC, memDC, bmp, bits
	s.img = image.NewRGBA(image.Rect(0, 0, w, h))
	return nil
}

func (s *winSession) release() {
	if s.bitmap != 0 {
		procDeleteObject.Call(s.bitmap)
		s.bitmap = 0
	}
	if s.memDC != 0 {
		procDeleteDC.Call(s.memDC)
		s.memDC = 0
	}
	if s.screenDC != 0 {
		procReleaseDC.Call(0, s.screenDC)
		s.screenDC = 0
	}
	s.bits = nil
}

func (s *winSession) Capture() (*image.RGBA, error) {
	if err := s.reshape(); err != nil {
		return nil, err
	}
	// CAPTUREBLT includes layered windows — menus, tooltips and anything
	// drawn with transparency. Without it those are simply missing, which
	// looks like the screen has frozen halfway through opening a menu.
	r, _, _ := procBitBlt.Call(s.memDC, 0, 0, uintptr(s.w), uintptr(s.h),
		s.screenDC, uintptr(int32(s.x)), uintptr(int32(s.y)), srcCopy|captureBlt)
	if r == 0 {
		return nil, fmt.Errorf("screen: BitBlt failed — the session may be locked or switched out")
	}

	src := unsafe.Slice((*byte)(s.bits), s.w*s.h*4)
	dst := s.img.Pix
	for i := 0; i < len(src); i += 4 {
		dst[i+0] = src[i+2] // BGRX from GDI
		dst[i+1] = src[i+1]
		dst[i+2] = src[i+0]
		dst[i+3] = 0xff
	}
	return s.img, nil
}

func (s *winSession) Pointer() (image.Point, bool) {
	var pt struct{ X, Y int32 }
	r, _, _ := procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	if r == 0 {
		return image.Point{}, false
	}
	return image.Pt(int(pt.X)-s.x, int(pt.Y)-s.y), true
}

func (s *winSession) Controllable() bool { return true }

func (s *winSession) Close() error {
	s.release()
	return nil
}

func metric(i int) uintptr {
	r, _, _ := procGetSystemMetrics.Call(uintptr(i))
	return r
}

func send(in ...wInput) error {
	if len(in) == 0 {
		return nil
	}
	r, _, err := procSendInput.Call(uintptr(len(in)), uintptr(unsafe.Pointer(&in[0])),
		unsafe.Sizeof(in[0]))
	if int(r) != len(in) {
		return fmt.Errorf("screen: SendInput delivered %d of %d events: %v", r, len(in), err)
	}
	return nil
}

// absolute converts a screen coordinate to SendInput's 0..65535 scale across
// the whole virtual desktop.
func (s *winSession) absolute(x, y int) (int32, int32) {
	dx, dy := s.w-1, s.h-1
	if dx <= 0 {
		dx = 1
	}
	if dy <= 0 {
		dy = 1
	}
	return int32(x * 65535 / dx), int32(y * 65535 / dy)
}

func (s *winSession) Input(ev Event) error {
	switch ev.Type {
	case "move":
		return s.move(ev.X, ev.Y)
	case "down", "up":
		if err := s.move(ev.X, ev.Y); err != nil {
			return err
		}
		var flag uint32
		switch ev.Button {
		case 1:
			flag = mouseeventfLeftDown
			if ev.Type == "up" {
				flag = mouseeventfLeftUp
			}
		case 2:
			flag = mouseeventfMiddleDown
			if ev.Type == "up" {
				flag = mouseeventfMiddleUp
			}
		case 3:
			flag = mouseeventfRightDown
			if ev.Type == "up" {
				flag = mouseeventfRightUp
			}
		default:
			return nil
		}
		return send(wInput{typ: inputMouse, mi: mouseInput{flags: flag}})
	case "wheel":
		var evs []wInput
		if ev.DY != 0 {
			evs = append(evs, wInput{typ: inputMouse, mi: mouseInput{
				mouseData: uint32(int32(-ev.DY * wheelDelta)), flags: mouseeventfWheel}})
		}
		if ev.DX != 0 {
			evs = append(evs, wInput{typ: inputMouse, mi: mouseInput{
				mouseData: uint32(int32(ev.DX * wheelDelta)), flags: mouseeventfHWheel}})
		}
		return send(evs...)
	case "key":
		return s.key(ev)
	}
	return nil
}

func (s *winSession) move(x, y int) error {
	ax, ay := s.absolute(x, y)
	return send(wInput{typ: inputMouse, mi: mouseInput{
		dx: ax, dy: ay,
		flags: mouseeventfMove | mouseeventfAbsolute | mouseeventfVirtualDesk,
	}})
}

// vkFor is the virtual-key code for each named key, with the flag that marks
// the ones Windows considers "extended" — the arrows and the editing cluster,
// which are the same virtual keys as the numeric keypad and are told apart
// only by that bit.
var vkFor = map[namedKey]struct {
	vk       uint16
	extended bool
}{
	keyBackspace:      {0x08, false},
	keyTab:            {0x09, false},
	keyEnter:          {0x0D, false},
	keyEscape:         {0x1B, false},
	keyDelete:         {0x2E, true},
	keyInsert:         {0x2D, true},
	keyHome:           {0x24, true},
	keyEnd:            {0x23, true},
	keyPageUp:         {0x21, true},
	keyPageDown:       {0x22, true},
	keyLeft:           {0x25, true},
	keyUp:             {0x26, true},
	keyRight:          {0x27, true},
	keyDown:           {0x28, true},
	keyShiftL:         {0xA0, false},
	keyShiftR:         {0xA1, false},
	keyCtrlL:          {0xA2, false},
	keyCtrlR:          {0xA3, true},
	keyAltL:           {0xA4, false},
	keyAltR:           {0xA5, true},
	keyMetaL:          {0x5B, true},
	keyMetaR:          {0x5C, true},
	keyCapsLock:       {0x14, false},
	keyNumLock:        {0x90, true},
	keyScrollLock:     {0x91, false},
	keyPause:          {0x13, false},
	keyPrintScreen:    {0x2C, true},
	keyMenu:           {0x5D, true},
	keyF1:             {0x70, false},
	keyF2:             {0x71, false},
	keyF3:             {0x72, false},
	keyF4:             {0x73, false},
	keyF5:             {0x74, false},
	keyF6:             {0x75, false},
	keyF7:             {0x76, false},
	keyF8:             {0x77, false},
	keyF9:             {0x78, false},
	keyF10:            {0x79, false},
	keyF11:            {0x7A, false},
	keyF12:            {0x7B, false},
	keyNumpadEnter:    {0x0D, true},
	keyNumpadDivide:   {0x6F, true},
	keyNumpadMultiply: {0x6A, false},
	keyNumpadSubtract: {0x6D, false},
	keyNumpadAdd:      {0x6B, false},
	keyNumpadDecimal:  {0x6E, false},
	keyNumpad0:        {0x60, false},
	keyNumpad1:        {0x61, false},
	keyNumpad2:        {0x62, false},
	keyNumpad3:        {0x63, false},
	keyNumpad4:        {0x64, false},
	keyNumpad5:        {0x65, false},
	keyNumpad6:        {0x66, false},
	keyNumpad7:        {0x67, false},
	keyNumpad8:        {0x68, false},
	keyNumpad9:        {0x69, false},
}

func (s *winSession) key(ev Event) error {
	var in wInput
	in.typ = inputKeyboard
	k := in.kbd()

	if nk, ok := lookupNamed(ev.Key, ev.Code); ok {
		e, known := vkFor[nk]
		if !known {
			return nil
		}
		switch nk {
		case keyCtrlL, keyCtrlR, keyAltL, keyAltR:
			if ev.Down {
				s.modsDown++
			} else if s.modsDown > 0 {
				s.modsDown--
			}
		}
		k.vk = e.vk
		if e.extended {
			k.flags |= keyeventfExtended
		}
	} else {
		r := singleRune(ev.Key)
		if r == 0 || r > 0xFFFF {
			return nil
		}
		// With no modifier held, the character goes as Unicode, which types
		// the right thing whatever keyboard layout the far machine is set
		// to. With Ctrl or Alt held it has to be a virtual key instead:
		// Ctrl+C sent as a Unicode 'c' arrives at the application as the
		// letter, and nothing gets copied.
		vk, ok := plainVK(r)
		if ok && s.modsDown > 0 {
			k.vk = vk
		} else {
			k.scan = uint16(r)
			k.flags |= keyeventfUnicode
		}
	}
	if !ev.Down {
		k.flags |= keyeventfKeyUp
	}
	return send(in)
}

// plainVK returns the unshifted virtual key for a character, for the letters
// and digits where a control combination has to reach the application as a
// real key press.
func plainVK(r rune) (uint16, bool) {
	switch {
	case r >= 'a' && r <= 'z':
		return uint16(r - 'a' + 'A'), true
	case r >= 'A' && r <= 'Z':
		return uint16(r), true
	case r >= '0' && r <= '9':
		return uint16(r), true
	case r == ' ':
		return 0x20, true
	}
	return 0, false
}
