// Package screen captures the local screen and injects mouse and keyboard
// events into it, with no C compiler and no library to install.
//
// Every platform here talks to whatever the system already has: the X11 wire
// protocol over a Unix socket on Linux, GDI and SendInput through user32 and
// gdi32 on Windows, and the built-in screencapture tool on macOS. That is the
// whole reason this package exists rather than binding to an existing capture
// library — LocNet ships as one static binary per platform, and a remote
// desktop that needs a package manager first is not remote desktop that works
// when you need it.
//
// A session must run in a graphical login. See package deskserve for why that
// means it cannot live inside locnetd.
package screen

import (
	"errors"
	"fmt"
	"image"
)

// ErrUnsupported means this build cannot capture this machine's screen. The
// wrapped message says why, because "unsupported" on its own sends people
// looking for a missing package that would not have helped.
var ErrUnsupported = errors.New("screen capture is not available here")

// Event is one input action from a viewer.
//
// The field names are short because these travel one per mouse move at up to
// sixty a second, and the vocabulary is the browser's — DOM key and code
// strings — rather than any one platform's, so the same event means the same
// thing whether it lands on X11 or on Windows.
type Event struct {
	// Type is "move", "down", "up", "wheel" or "key".
	Type string `json:"t"`

	// X and Y are absolute screen coordinates for move, down and up.
	X int `json:"x,omitempty"`
	Y int `json:"y,omitempty"`

	// Button is 1 left, 2 middle, 3 right — X11's numbering, which every
	// other platform is mapped onto.
	Button int `json:"b,omitempty"`

	// DX and DY are wheel deltas in notches, positive down and right.
	DX int `json:"dx,omitempty"`
	DY int `json:"dy,omitempty"`

	// Key is the DOM KeyboardEvent.key value ("a", "A", "Enter", "F5").
	Key string `json:"k,omitempty"`
	// Code is the DOM KeyboardEvent.code value ("KeyA", "Enter"), used when
	// Key alone does not identify the key.
	Code string `json:"c,omitempty"`
	// Down is true for a press, false for a release.
	Down bool `json:"d,omitempty"`
}

// Session is one attachment to the local display.
//
// Capture returns an image that is reused between calls: the bytes are valid
// until the next Capture, and a caller that wants to keep one must copy it.
// This is deliberate — a 4K frame is 33 MB and allocating a fresh one twelve
// times a second would keep the garbage collector busier than the capture.
type Session interface {
	// Capture reads the current screen.
	Capture() (*image.RGBA, error)

	// Pointer returns where the mouse is now, so a viewer can be shown the
	// cursor without the screenshot containing one. ok is false when the
	// platform will not say.
	Pointer() (image.Point, bool)

	// Input performs one event. It returns an error only when the event
	// cannot be delivered at all; an event this platform has no equivalent
	// for is silently dropped.
	Input(ev Event) error

	// Controllable reports whether Input does anything on this platform.
	Controllable() bool

	// Close releases the display connection.
	Close() error
}

// Open attaches to the display this process is logged in to.
func Open() (Session, error) { return open() }

// unsupported builds the error for a platform or session type that cannot be
// captured, with the reason attached.
func unsupported(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrUnsupported, fmt.Sprintf(format, args...))
}
