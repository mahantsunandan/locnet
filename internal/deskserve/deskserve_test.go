package deskserve

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mahantsunandan/locnet/internal/screen"
)

// fakeSession is a display that fits in a test: a plain grey screen with one
// square that changes colour when the test says so.
type fakeSession struct {
	mu      sync.Mutex
	img     *image.RGBA
	shade   uint8
	events  []screen.Event
	control bool
}

func newFake(w, h int) *fakeSession {
	f := &fakeSession{img: image.NewRGBA(image.Rect(0, 0, w, h)), control: true}
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			f.img.Set(x, y, color.RGBA{40, 44, 52, 255})
		}
	}
	return f
}

func (f *fakeSession) Capture() (*image.RGBA, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for y := 0; y < 40; y++ {
		for x := 0; x < 40; x++ {
			f.img.Set(x, y, color.RGBA{f.shade, f.shade, f.shade, 255})
		}
	}
	return f.img, nil
}

func (f *fakeSession) Pointer() (image.Point, bool) { return image.Pt(11, 22), true }
func (f *fakeSession) Controllable() bool           { return f.control }
func (f *fakeSession) Close() error                 { return nil }

func (f *fakeSession) Input(ev screen.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
	return nil
}

func (f *fakeSession) change(v uint8) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shade = v
}

func newTestServer(t *testing.T, f *fakeSession) (*httptest.Server, string) {
	t.Helper()
	prev := openSession
	openSession = func() (screen.Session, error) { return f, nil }
	t.Cleanup(func() { openSession = prev })

	s := &Server{token: "test-token", logf: func(string, ...any) {}, g: &grabber{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /info", s.auth(s.handleInfo))
	mux.HandleFunc("GET /stream", s.auth(s.handleStream))
	mux.HandleFunc("POST /input", s.auth(s.handleInput))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, s.token
}

// record is one parsed frame-stream record.
type record struct {
	kind       byte
	x, y, w, h int
	payload    []byte
}

// readRecords pulls records off the stream until it has seen want frame ends.
func readRecords(t *testing.T, r io.Reader, wantFrames int) []record {
	t.Helper()
	var out []record
	head := make([]byte, screen.HeaderSize)
	frames := 0
	for frames < wantFrames {
		if _, err := io.ReadFull(r, head); err != nil {
			t.Fatalf("reading stream: %v", err)
		}
		rec := record{
			kind: head[0],
			x:    int(binary.BigEndian.Uint16(head[1:])),
			y:    int(binary.BigEndian.Uint16(head[3:])),
			w:    int(binary.BigEndian.Uint16(head[5:])),
			h:    int(binary.BigEndian.Uint16(head[7:])),
		}
		if n := binary.BigEndian.Uint32(head[9:]); n > 0 {
			rec.payload = make([]byte, n)
			if _, err := io.ReadFull(r, rec.payload); err != nil {
				t.Fatalf("reading payload: %v", err)
			}
		}
		if rec.kind == screen.RecEnd {
			frames++
		}
		out = append(out, rec)
	}
	return out
}

func countKind(recs []record, kind byte) int {
	n := 0
	for _, r := range recs {
		if r.kind == kind {
			n++
		}
	}
	return n
}

func TestStreamSendsOnlyWhatChanged(t *testing.T) {
	f := newFake(320, 240)
	srv, token := newTestServer(t, f)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/stream?fps=30&q=60", nil)
	req.Header.Set(TokenHeader, token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stream returned %s", resp.Status)
	}

	// The first frame has to be whole: a viewer that just connected has
	// nothing on screen yet.
	first := readRecords(t, resp.Body, 1)
	if countKind(first, screen.RecSize) != 1 {
		t.Errorf("first frame did not announce the screen size: %+v", first)
	}
	tiles := countKind(first, screen.RecTile)
	if want := 3 * 2; tiles != want { // 320x240 in 128-pixel squares
		t.Errorf("first frame sent %d tiles, wanted the whole screen (%d)", tiles, want)
	}
	if countKind(first, screen.RecCursor) != 1 {
		t.Error("no cursor position was sent")
	}

	// Nothing has moved, so the next frames should carry no pixels at all.
	quiet := readRecords(t, resp.Body, 2)
	if n := countKind(quiet, screen.RecTile); n != 0 {
		t.Errorf("a still screen sent %d tiles; it should send none", n)
	}

	// One corner changes: exactly the square containing it should come back.
	f.change(200)
	var moved []record
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		batch := readRecords(t, resp.Body, 1)
		if countKind(batch, screen.RecTile) > 0 {
			moved = batch
			break
		}
	}
	if moved == nil {
		t.Fatal("a changed square never arrived")
	}
	if n := countKind(moved, screen.RecTile); n != 1 {
		t.Errorf("a 40x40 change sent %d tiles, wanted 1", n)
	}
	for _, rec := range moved {
		if rec.kind != screen.RecTile {
			continue
		}
		if rec.x != 0 || rec.y != 0 {
			t.Errorf("changed tile reported at %d,%d, wanted 0,0", rec.x, rec.y)
		}
		if !bytes.HasPrefix(rec.payload, []byte{0xff, 0xd8}) {
			t.Error("tile payload is not a JPEG")
		}
	}
}

func TestInputReachesTheDisplay(t *testing.T) {
	f := newFake(64, 64)
	srv, token := newTestServer(t, f)

	body, _ := json.Marshal([]screen.Event{
		{Type: "move", X: 10, Y: 20},
		{Type: "down", X: 10, Y: 20, Button: 1},
		{Type: "key", Key: "a", Code: "KeyA", Down: true},
	})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/input", bytes.NewReader(body))
	req.Header.Set(TokenHeader, token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("input returned %s", resp.Status)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.events) != 3 {
		t.Fatalf("the display saw %d events, wanted 3", len(f.events))
	}
	if f.events[2].Key != "a" || !f.events[2].Down {
		t.Errorf("the key event arrived as %+v", f.events[2])
	}
}

func TestTokenIsRequired(t *testing.T) {
	f := newFake(64, 64)
	srv, token := newTestServer(t, f)

	for _, tok := range []string{"", "wrong", token} {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/info", nil)
		if tok != "" {
			req.Header.Set(TokenHeader, tok)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		want := http.StatusUnauthorized
		if tok == token {
			want = http.StatusOK
		}
		if resp.StatusCode != want {
			t.Errorf("token %q got %s, wanted %d", tok, resp.Status, want)
		}
	}
}

func TestInfoReportsTheScreen(t *testing.T) {
	f := newFake(800, 600)
	srv, token := newTestServer(t, f)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/info", nil)
	req.Header.Set(TokenHeader, token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var st struct {
		Ready   bool `json:"ready"`
		Width   int  `json:"width"`
		Height  int  `json:"height"`
		Control bool `json:"control"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if !st.Ready || st.Width != 800 || st.Height != 600 || !st.Control {
		t.Errorf("info reported %+v", st)
	}
}

// unsupportedOpener stands in for a platform that cannot be captured — a
// Wayland session, most often.
func unsupportedOpener() (screen.Session, error) {
	return nil, fmt.Errorf("%w: this is a Wayland session", screen.ErrUnsupported)
}

func TestBridgeIsNotTriedWhenTurnedOff(t *testing.T) {
	prev := openSession
	openSession = unsupportedOpener
	t.Cleanup(func() { openSession = prev })

	g := &grabber{opts: Options{VNCAddr: "off"}, logf: func(string, ...any) {}}
	st := g.probe()

	if st.Ready {
		t.Fatal("a platform that cannot be captured reported itself ready")
	}
	if !strings.Contains(st.Error, "Wayland") {
		t.Errorf("the error should be the platform's own reason, got %q", st.Error)
	}
	if strings.Contains(st.Error, "VNC") {
		t.Errorf("the bridge was mentioned although it was turned off: %q", st.Error)
	}
}

func TestBridgeFailureIsExplained(t *testing.T) {
	prev := openSession
	openSession = unsupportedOpener
	t.Cleanup(func() { openSession = prev })

	// Port 1 has nothing on it, so the bridge is tried and fails.
	g := &grabber{opts: Options{VNCAddr: "127.0.0.1:1"}, logf: func(string, ...any) {}}
	st := g.probe()

	if st.Ready {
		t.Fatal("reported ready with no display and no bridge")
	}
	if !strings.Contains(st.Error, "Wayland") {
		t.Errorf("the platform's reason went missing: %q", st.Error)
	}
	if !strings.Contains(st.Error, "VNC") {
		t.Errorf("a bridge that was tried and failed should say so: %q", st.Error)
	}
}

func TestPlatformCaptureWinsOverTheBridge(t *testing.T) {
	f := newFake(100, 100)
	prev := openSession
	openSession = func() (screen.Session, error) { return f, nil }
	t.Cleanup(func() { openSession = prev })

	// A VNC server is configured, but the platform can be captured directly,
	// so the bridge must not be used: it is a fallback, not a preference.
	g := &grabber{opts: Options{VNCAddr: "127.0.0.1:5900"}, logf: func(string, ...any) {}}
	st := g.probe()

	if !st.Ready || st.Width != 100 {
		t.Fatalf("direct capture did not happen: %+v", st)
	}
	if st.Via != "" {
		t.Errorf("the bridge was used although the platform works: %q", st.Via)
	}
}
