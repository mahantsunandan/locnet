package hub

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mahantsunandan/locnet/internal/hubapi"
	"github.com/mahantsunandan/locnet/internal/key"
)

// plainFrom makes an unencrypted request arriving from addr.
func plainFrom(method, path, addr string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = addr
	return req
}

func serveRec(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestPlainHTTPOnlyFromThisMachine: the control plane leaves the hub machine
// only inside TLS. Plain HTTP is answered on loopback (the hub's own admin
// commands, a standby on the same host) and on /healthz, and nowhere else —
// least of all the snapshot, which is the hub's signing key.
func TestPlainHTTPOnlyFromThisMachine(t *testing.T) {
	f := newHubFixture(t)
	remote := "198.51.100.7:40000"
	withToken := func(req *http.Request) *http.Request {
		req.Header.Set("Authorization", "Bearer "+f.store.AdminToken())
		return req
	}
	overTLS := func(req *http.Request) *http.Request {
		req.TLS = &tls.ConnectionState{}
		return req
	}
	info := hubapi.APIVersion + "/info"
	snap := hubapi.APIVersion + "/admin/snapshot"

	for _, c := range []struct {
		name string
		req  *http.Request
		want int
	}{
		{"info, plain, from elsewhere", plainFrom("GET", info, remote), http.StatusUpgradeRequired},
		{"snapshot, plain, from elsewhere", withToken(plainFrom("GET", snap, remote)), http.StatusUpgradeRequired},
		{"healthz, plain, from elsewhere", plainFrom("GET", "/healthz", remote), http.StatusOK},
		{"info, plain, loopback", plainFrom("GET", info, "127.0.0.1:5000"), http.StatusOK},
		{"snapshot, plain, loopback", withToken(plainFrom("GET", snap, "[::ffff:127.0.0.1]:5000")), http.StatusOK},
		{"info, TLS", overTLS(plainFrom("GET", info, remote)), http.StatusOK},
		{"snapshot, TLS", overTLS(withToken(plainFrom("GET", snap, remote))), http.StatusOK},
	} {
		rec := serveRec(f.handler, c.req)
		if rec.Code != c.want {
			t.Errorf("%s: %d, want %d (%s)", c.name, rec.Code, c.want, rec.Body)
		}
		if c.want == http.StatusUpgradeRequired && !strings.Contains(rec.Body.String(), "TLS") {
			t.Errorf("%s: the refusal does not say what to do: %s", c.name, rec.Body)
		}
	}
}

// tlsPrimary runs a primary hub behind the real TLS listener.
func tlsPrimary(t *testing.T) (*Store, string) {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "hub.json"), "testnet", DefaultPrefix)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(store, nil, []string{"127.0.0.1:8420"}, t.Logf)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tl, err := srv.TLSListener(ln)
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go hs.Serve(tl)
	t.Cleanup(func() { hs.Close() })
	return store, ln.Addr().String()
}

// TestMirrorOverPinnedTLS: a standby copies the signing key only from the
// hub it is pinned to.
func TestMirrorOverPinnedTLS(t *testing.T) {
	primary, addr := tlsPrimary(t)
	fp := primary.HubKey().Public().Fingerprint()

	path := filepath.Join(t.TempDir(), "hub.json")
	m := &Mirror{From: addr, Fingerprint: fp, Token: primary.AdminToken(), Path: path, Logf: t.Logf}
	if err := m.once(context.Background()); err != nil {
		t.Fatalf("mirroring over pinned TLS: %v", err)
	}

	_, otherPub, _ := key.NewMachine()
	wrong := &Mirror{From: addr, Fingerprint: otherPub.Fingerprint(), Token: primary.AdminToken(),
		Path: filepath.Join(t.TempDir(), "hub.json"), Logf: t.Logf}
	if err := wrong.once(context.Background()); err == nil {
		t.Fatal("a standby pinned to another hub copied this one")
	}
}

// TestMirrorDoesNotFallBackToPlain: a primary answering in plain HTTP —
// really an old one, or someone pretending to be — gets neither the admin
// token nor the chance to hand over a state file.
func TestMirrorDoesNotFallBackToPlain(t *testing.T) {
	sawToken := false
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			sawToken = true
		}
	}))
	defer plain.Close()
	_, pub, _ := key.NewMachine()
	m := &Mirror{From: plain.Listener.Addr().String(), Fingerprint: pub.Fingerprint(), Token: "secret",
		Path: filepath.Join(t.TempDir(), "hub.json"), Logf: t.Logf}
	err := m.once(context.Background())
	if err == nil || !strings.Contains(err.Error(), "without TLS") {
		t.Fatalf("plain-HTTP primary: %v", err)
	}
	if sawToken {
		t.Error("the admin token was sent in the clear")
	}
}

// TestMirrorRefusesAnotherHubsSnapshot: over an http:// or https:// address
// nothing pins the hub, so the snapshot's own key is checked.
func TestMirrorRefusesAnotherHubsSnapshot(t *testing.T) {
	other, err := Open(filepath.Join(t.TempDir(), "hub.json"), "testnet", DefaultPrefix)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(NewServer(other, nil, []string{"127.0.0.1:8420"}, t.Logf).Handler())
	defer srv.Close()
	_, pub, _ := key.NewMachine()
	m := &Mirror{From: srv.URL, Fingerprint: pub.Fingerprint(), Token: other.AdminToken(),
		Path: filepath.Join(t.TempDir(), "hub.json"), Logf: t.Logf}
	if err := m.once(context.Background()); err == nil {
		t.Fatal("a snapshot of a different hub was accepted")
	}
}

func TestMirrorPin(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hub.json")
	_, pub, _ := key.NewMachine()
	fp := pub.Fingerprint()

	if _, err := MirrorPin(path, ""); err == nil || !strings.Contains(err.Error(), "-follow-fingerprint") {
		t.Errorf("a new standby with no fingerprint: %v", err)
	}
	if got, err := MirrorPin(path, hex.EncodeToString(fp[:])); err != nil || got != fp {
		t.Errorf("from the flag: %x, %v", got, err)
	}
	if _, err := MirrorPin(path, "abc"); err == nil {
		t.Error("a malformed fingerprint was accepted")
	}

	// A standby that already holds a copy pins what it holds — the
	// upgrade path for one set up before 0.10.4.
	held, err := Open(path, "testnet", DefaultPrefix)
	if err != nil {
		t.Fatal(err)
	}
	heldFP := held.HubKey().Public().Fingerprint()
	if got, err := MirrorPin(path, ""); err != nil || got != heldFP {
		t.Errorf("from the existing copy: %x, %v", got, err)
	}
	if _, err := MirrorPin(path, hex.EncodeToString(fp[:])); err == nil {
		t.Error("a fingerprint contradicting the copy on disk was accepted")
	}
}
