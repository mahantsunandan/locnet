//go:build linux

package screen

import (
	"encoding/binary"
	"image"
	"testing"
)

// TestX11GetImageRoundTrip draws a known pattern into a pixmap and reads it
// back.
//
// It exists because the interesting half of this package cannot be tested on a
// build machine: capturing a real screen needs a real screen, and the display
// a CI runner has — if it has one at all — is a rootless Xwayland whose root
// window refuses GetImage. A pixmap is a drawable like any other, so the
// request encoding, the reply framing and the pixel conversion are all
// exercised here even though the root window is not.
func TestX11GetImageRoundTrip(t *testing.T) {
	x, err := dialX11()
	if err != nil {
		t.Skipf("no X server to test against: %v", err)
	}
	defer x.Close()

	const w, h = 64, 48
	pix := x.newID()
	gc := x.newID()

	req := make([]byte, 16)
	req[0] = 53 // CreatePixmap
	req[1] = x.depth
	binary.LittleEndian.PutUint16(req[2:], 4)
	binary.LittleEndian.PutUint32(req[4:], pix)
	binary.LittleEndian.PutUint32(req[8:], x.root)
	binary.LittleEndian.PutUint16(req[12:], w)
	binary.LittleEndian.PutUint16(req[14:], h)
	if _, err := x.request(req); err != nil {
		t.Fatal(err)
	}

	// A graphics context whose foreground is a colour with all three
	// channels different, so a red/blue swap in the conversion cannot pass.
	const want = 0x204080 // R=0x20 G=0x40 B=0x80
	req = make([]byte, 20)
	req[0] = 55 // CreateGC
	binary.LittleEndian.PutUint16(req[2:], 5)
	binary.LittleEndian.PutUint32(req[4:], gc)
	binary.LittleEndian.PutUint32(req[8:], pix)
	binary.LittleEndian.PutUint32(req[12:], 0x00000004) // foreground
	binary.LittleEndian.PutUint32(req[16:], want)
	if _, err := x.request(req); err != nil {
		t.Fatal(err)
	}

	req = make([]byte, 20)
	req[0] = 70 // PolyFillRectangle
	binary.LittleEndian.PutUint16(req[2:], 5)
	binary.LittleEndian.PutUint32(req[4:], pix)
	binary.LittleEndian.PutUint32(req[8:], gc)
	binary.LittleEndian.PutUint16(req[12:], 0)
	binary.LittleEndian.PutUint16(req[14:], 0)
	binary.LittleEndian.PutUint16(req[16:], w)
	binary.LittleEndian.PutUint16(req[18:], h)
	if _, err := x.request(req); err != nil {
		t.Fatal(err)
	}

	req = make([]byte, 20)
	req[0] = opGetImage
	req[1] = 2 // ZPixmap
	binary.LittleEndian.PutUint16(req[2:], 5)
	binary.LittleEndian.PutUint32(req[4:], pix)
	binary.LittleEndian.PutUint16(req[12:], w)
	binary.LittleEndian.PutUint16(req[14:], h)
	binary.LittleEndian.PutUint32(req[16:], 0xffffffff)
	seq, err := x.request(req)
	if err != nil {
		t.Fatal(err)
	}
	_, body, err := x.replyInto(seq, nil)
	if err != nil {
		t.Fatalf("GetImage on a pixmap: %v", err)
	}

	x.img = image.NewRGBA(image.Rect(0, 0, w, h))
	if err := x.convert(body, w, h); err != nil {
		t.Fatal(err)
	}
	for _, p := range []image.Point{{0, 0}, {w - 1, h - 1}, {w / 2, h / 2}} {
		r, g, b, a := x.img.At(p.X, p.Y).RGBA()
		if r>>8 != 0x20 || g>>8 != 0x40 || b>>8 != 0x80 || a>>8 != 0xff {
			t.Fatalf("pixel %v is %02x%02x%02x%02x, wanted 204080ff",
				p, r>>8, g>>8, b>>8, a>>8)
		}
	}

	// Tidy up: FreeGC then FreePixmap.
	for _, r := range [][2]uint32{{60, gc}, {54, pix}} {
		req = make([]byte, 8)
		req[0] = byte(r[0])
		binary.LittleEndian.PutUint16(req[2:], 2)
		binary.LittleEndian.PutUint32(req[4:], r[1])
		if _, err := x.request(req); err != nil {
			t.Fatal(err)
		}
	}
}

func TestKeysymFor(t *testing.T) {
	cases := []struct {
		key, code string
		want      uint32
	}{
		{"a", "KeyA", 0x61},
		{"A", "KeyA", 0x41},
		{" ", "Space", 0x20},
		{"Enter", "Enter", 0xFF0D},
		{"Shift", "ShiftRight", 0xFFE2},
		{"ArrowLeft", "ArrowLeft", 0xFF51},
		{"F5", "F5", 0xFFC2},
		{"£", "", 0xA3},
		{"€", "", 0x010020AC},
		{"Unidentified", "", 0},
	}
	for _, c := range cases {
		if got := keysymFor(c.key, c.code); got != c.want {
			t.Errorf("keysymFor(%q, %q) = %#x, want %#x", c.key, c.code, got, c.want)
		}
	}
}
