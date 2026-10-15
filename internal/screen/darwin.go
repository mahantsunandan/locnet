//go:build darwin

package screen

import (
	"fmt"
	"image"
	"image/draw"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// macOS has no capture path that does not go through the Objective-C runtime,
// and reaching that from Go means cgo, which would cost LocNet its single
// static binary on every other platform too. So this backend shells out to
// screencapture, which ships with the system and has since 10.2.
//
// The consequences are honest ones: a frame costs a process launch, so the
// rate is low, and there is no supported way to synthesise input without the
// same runtime, so a Mac is view-only. A Mac you need to drive is still a Mac
// you drive over VNC, which macOS has built in — and `locnet vnc` opens that.
type macSession struct {
	dir string
	img *image.RGBA
}

func open() (Session, error) {
	if _, err := exec.LookPath("screencapture"); err != nil {
		return nil, unsupported("screencapture is missing, so this Mac cannot be captured")
	}
	dir, err := os.MkdirTemp("", "locnet-screen")
	if err != nil {
		return nil, err
	}
	s := &macSession{dir: dir}
	if _, err := s.Capture(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *macSession) Capture() (*image.RGBA, error) {
	path := filepath.Join(s.dir, "frame.png")
	// -x is no shutter sound, -C includes the cursor, -o drops window
	// shadows that would otherwise be captured as grey haloes.
	cmd := exec.Command("screencapture", "-x", "-C", "-o", "-t", "png", path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, unsupported("screencapture failed: %v: %s.\n"+
			"macOS 10.15 and later need Screen Recording permission for whatever launched "+
			"this — System Settings ▸ Privacy & Security ▸ Screen Recording", err, out)
	}
	defer os.Remove(path)

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	src, err := png.Decode(f)
	if err != nil {
		return nil, fmt.Errorf("screen: cannot read the captured frame: %w", err)
	}
	b := src.Bounds()
	if s.img == nil || s.img.Rect != b {
		s.img = image.NewRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
	}
	draw.Draw(s.img, s.img.Rect, src, b.Min, draw.Src)
	return s.img, nil
}

func (s *macSession) Pointer() (image.Point, bool) { return image.Point{}, false }

func (s *macSession) Controllable() bool { return false }

func (s *macSession) Input(Event) error {
	return fmt.Errorf("a Mac cannot be driven this way — use `locnet vnc` and macOS's own screen sharing")
}

func (s *macSession) Close() error {
	// Give a capture that is still running a moment to finish before the
	// directory it is writing into disappears.
	time.Sleep(50 * time.Millisecond)
	return os.RemoveAll(s.dir)
}
