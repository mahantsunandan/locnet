package screen

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"image"
	"image/jpeg"
	"io"
)

// The frame format is deliberately small: a desktop is mostly still, so what
// crosses the network should be the handful of squares that changed rather
// than a new picture of the whole screen twelve times a second. A cursor
// blinking in a terminal costs about two kilobytes a second this way; the same
// screen as full JPEG frames costs two megabytes.
//
// Records are a 13-byte header and a payload:
//
//	kind   1
//	x      2   big endian
//	y      2
//	w      2
//	h      2
//	length 4
//
// which a browser can parse from a DataView with no library at all.

// Record kinds.
const (
	// RecTile is a JPEG image of one changed square.
	RecTile = 1
	// RecEnd closes a frame: everything since the last RecEnd belongs
	// together and can be presented at once.
	RecEnd = 2
	// RecSize announces the screen dimensions, at the start and whenever
	// the resolution changes.
	RecSize = 3
	// RecCursor carries the remote pointer position, which the viewer draws
	// itself because the captured pixels do not contain a cursor.
	RecCursor = 4
	// RecMessage carries a human-readable line: a capture that failed
	// halfway through a session says so here rather than by dropping the
	// connection.
	RecMessage = 5
)

// HeaderSize is the length of a record header.
const HeaderSize = 13

// DefaultTileSize is a compromise: small enough that typing in one corner does
// not resend a quarter of the screen, large enough that JPEG still has
// something to work with and the per-tile overhead stays irrelevant.
const DefaultTileSize = 128

// Encoder turns successive frames into records, sending only what moved.
type Encoder struct {
	// TileSize is the square edge in pixels. Zero means DefaultTileSize.
	TileSize int
	// Quality is the JPEG quality for tiles, 1..100.
	Quality int

	w, h    int
	cols    int
	rows    int
	hashes  []uint64
	tile    bytes.Buffer
	head    [HeaderSize]byte
	sinceKF int
}

// keyframeEvery forces a full resend now and then. Nothing should be able to
// go missing over a TCP stream, but a viewer that joined mid-scene or a bug in
// the diffing would otherwise leave a stale square on screen forever.
const keyframeEvery = 600

func (e *Encoder) tileSize() int {
	if e.TileSize > 0 {
		return e.TileSize
	}
	return DefaultTileSize
}

func (e *Encoder) quality() int {
	if e.Quality > 0 {
		return e.Quality
	}
	return 62
}

// Reset forgets what the viewer has seen, so the next frame is sent whole.
func (e *Encoder) Reset() {
	e.hashes = nil
	e.sinceKF = 0
}

// Frame writes the records for one captured image. It returns the number of
// tiles sent, which is zero when nothing on the screen changed.
func (e *Encoder) Frame(w io.Writer, img *image.RGBA) (int, error) {
	b := img.Bounds()
	iw, ih := b.Dx(), b.Dy()
	ts := e.tileSize()

	if iw != e.w || ih != e.h {
		e.w, e.h = iw, ih
		e.cols = (iw + ts - 1) / ts
		e.rows = (ih + ts - 1) / ts
		e.hashes = make([]uint64, e.cols*e.rows)
		e.sinceKF = 0
		if err := e.writeRecord(w, RecSize, 0, 0, iw, ih, nil); err != nil {
			return 0, err
		}
	}

	keyframe := e.sinceKF == 0
	e.sinceKF++
	if e.sinceKF >= keyframeEvery {
		e.sinceKF = 0
	}

	sent := 0
	for row := 0; row < e.rows; row++ {
		for col := 0; col < e.cols; col++ {
			r := image.Rect(col*ts, row*ts, min((col+1)*ts, iw), min((row+1)*ts, ih)).Add(b.Min)
			h := hashTile(img, r)
			idx := row*e.cols + col
			if !keyframe && e.hashes[idx] == h {
				continue
			}
			e.hashes[idx] = h

			e.tile.Reset()
			sub := img.SubImage(r)
			if err := jpeg.Encode(&e.tile, sub, &jpeg.Options{Quality: e.quality()}); err != nil {
				return sent, fmt.Errorf("screen: encode tile: %w", err)
			}
			if err := e.writeRecord(w, RecTile, r.Min.X-b.Min.X, r.Min.Y-b.Min.Y,
				r.Dx(), r.Dy(), e.tile.Bytes()); err != nil {
				return sent, err
			}
			sent++
		}
	}
	return sent, nil
}

// Cursor writes the pointer position.
func (e *Encoder) Cursor(w io.Writer, p image.Point) error {
	if p.X < 0 || p.Y < 0 {
		return nil
	}
	return e.writeRecord(w, RecCursor, p.X, p.Y, 0, 0, nil)
}

// End closes a frame.
func (e *Encoder) End(w io.Writer) error {
	return e.writeRecord(w, RecEnd, 0, 0, 0, 0, nil)
}

// Message sends a line of text to the viewer.
func (e *Encoder) Message(w io.Writer, text string) error {
	return e.writeRecord(w, RecMessage, 0, 0, 0, 0, []byte(text))
}

func (e *Encoder) writeRecord(w io.Writer, kind byte, x, y, tw, th int, payload []byte) error {
	e.head[0] = kind
	binary.BigEndian.PutUint16(e.head[1:], uint16(clamp16(x)))
	binary.BigEndian.PutUint16(e.head[3:], uint16(clamp16(y)))
	binary.BigEndian.PutUint16(e.head[5:], uint16(clamp16(tw)))
	binary.BigEndian.PutUint16(e.head[7:], uint16(clamp16(th)))
	binary.BigEndian.PutUint32(e.head[9:], uint32(len(payload)))
	if _, err := w.Write(e.head[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func clamp16(v int) int {
	if v < 0 {
		return 0
	}
	if v > 65535 {
		return 65535
	}
	return v
}

// hashTile fingerprints one square. FNV over the raw pixels is far cheaper
// than encoding a JPEG to find out it was identical, and a collision costs one
// stale tile until the next keyframe rather than anything worse.
func hashTile(img *image.RGBA, r image.Rectangle) uint64 {
	h := fnv.New64a()
	stride := img.Stride
	start := img.PixOffset(r.Min.X, r.Min.Y)
	width := r.Dx() * 4
	for y := 0; y < r.Dy(); y++ {
		off := start + y*stride
		h.Write(img.Pix[off : off+width])
	}
	return h.Sum64()
}
