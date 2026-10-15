package node

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mahantsunandan/locnet/internal/resource"
)

// listenLoopback opens a port on 127.0.0.1 and returns it, closed on cleanup.
func listenLoopback(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

// freePort returns a port with nothing on it.
func freePort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	ln.Close()
	return port
}

func probeOnce(t *testing.T, remoteAddr string, body string) (*httptest.ResponseRecorder, resource.ProbeResult) {
	t.Helper()
	s := newShareServer(func(string, ...any) {})
	req := httptest.NewRequest(http.MethodPost, "/probe", strings.NewReader(body))
	req.RemoteAddr = remoteAddr
	w := httptest.NewRecorder()
	s.handleProbe(w, req, "tester")

	var got resource.ProbeResult
	if w.Code == http.StatusOK {
		if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
	return w, got
}

func TestProbeReportsOpenAndBlocked(t *testing.T) {
	open := listenLoopback(t)
	shut := freePort(t)

	body, _ := json.Marshal(resource.ProbeRequest{Ports: []uint16{open, shut}})
	w, got := probeOnce(t, "127.0.0.1:50000", string(body))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	if !got.IsOpen(open) {
		t.Errorf("port %d listening but reported blocked (open=%v blocked=%v)", open, got.Open, got.Blocked)
	}
	if got.IsOpen(shut) {
		t.Errorf("port %d has nothing on it but was reported open", shut)
	}
}

// The address probed must come from the connection, never the request. A body
// that could name a target would make every node in the network a port scanner
// aimed wherever the caller liked — including at machines outside the mesh.
func TestProbeIgnoresAddressInBody(t *testing.T) {
	open := listenLoopback(t)

	// A body carrying an address field alongside the ports. The type has no
	// such field, so this is exactly what an attacker would try: extra JSON
	// that a laxer implementation might honour.
	body := `{"ports":[` + itoa(open) + `],"addr":"10.0.0.1","target":"10.0.0.1","host":"example.com"}`

	// Source address is loopback, so the listener above is reachable. If the
	// handler honoured any of those fields it would dial elsewhere and report
	// the port blocked.
	w, got := probeOnce(t, "127.0.0.1:50000", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !got.IsOpen(open) {
		t.Fatalf("handler did not probe the connection's source address (open=%v blocked=%v)", got.Open, got.Blocked)
	}
}

func TestProbeRejectsEmptyAndUnparseable(t *testing.T) {
	if w, _ := probeOnce(t, "127.0.0.1:50000", `{"ports":[]}`); w.Code != http.StatusBadRequest {
		t.Errorf("empty port list: status = %d, want 400", w.Code)
	}
	if w, _ := probeOnce(t, "127.0.0.1:50000", `not json`); w.Code != http.StatusBadRequest {
		t.Errorf("bad json: status = %d, want 400", w.Code)
	}
	if w, _ := probeOnce(t, "garbage", `{"ports":[22]}`); w.Code != http.StatusBadRequest {
		t.Errorf("bad remote addr: status = %d, want 400", w.Code)
	}
}

// A caller must not be able to spend a peer's time on an unbounded port list.
func TestProbeCapsPortCount(t *testing.T) {
	shut := freePort(t)
	ports := make([]uint16, resource.MaxProbePorts+20)
	for i := range ports {
		ports[i] = shut
	}
	body, _ := json.Marshal(resource.ProbeRequest{Ports: ports})

	w, got := probeOnce(t, "127.0.0.1:50000", string(body))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if n := len(got.Open) + len(got.Blocked); n > resource.MaxProbePorts {
		t.Errorf("probed %d ports, want at most %d", n, resource.MaxProbePorts)
	}
}

func itoa(v uint16) string {
	if v == 0 {
		return "0"
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte('0' + v%10)}, b...)
		v /= 10
	}
	return string(b)
}
