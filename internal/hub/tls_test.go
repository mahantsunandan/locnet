package hub

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mahantsunandan/locnet/internal/hubapi"
	"github.com/mahantsunandan/locnet/internal/joincode"
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

// TestSnapshotIsNeverSentInTheClear: the snapshot is the hub's signing key.
// It goes to another machine only over TLS, whatever the transition allows
// for everything else; to this machine (a standby on the same host, or an
// operator's curl) loopback is fine.
func TestSnapshotIsNeverSentInTheClear(t *testing.T) {
	f := newHubFixture(t)
	path := hubapi.APIVersion + "/admin/snapshot"
	withToken := func(req *http.Request) *http.Request {
		req.Header.Set("Authorization", "Bearer "+f.store.AdminToken())
		return req
	}

	if rec := serveRec(f.handler, withToken(plainFrom("GET", path, "198.51.100.7:40000"))); rec.Code != http.StatusUpgradeRequired {
		t.Fatalf("snapshot over plain HTTP to another machine: %d %s", rec.Code, rec.Body)
	}
	if rec := serveRec(f.handler, withToken(plainFrom("GET", path, "[::ffff:127.0.0.1]:40000"))); rec.Code != http.StatusOK {
		t.Errorf("snapshot over loopback: %d", rec.Code)
	}
	req := withToken(plainFrom("GET", path, "198.51.100.7:40000"))
	req.TLS = &tls.ConnectionState{}
	if rec := serveRec(f.handler, req); rec.Code != http.StatusOK {
		t.Errorf("snapshot over TLS: %d", rec.Code)
	}
}

// TestRequireTLS is the end of the transition: plain HTTP from elsewhere is
// refused, with the fix in the message; loopback and /healthz still work.
func TestRequireTLS(t *testing.T) {
	f := newHubFixture(t)
	info := hubapi.APIVersion + "/info"
	remote := "198.51.100.7:40000"

	if rec := serveRec(f.handler, plainFrom("GET", info, remote)); rec.Code != http.StatusOK {
		t.Fatalf("by default an old agent's plain request must still work: %d", rec.Code)
	}

	f.srv.SetRequireTLS(true)
	rec := serveRec(f.handler, plainFrom("GET", info, remote))
	if rec.Code != http.StatusUpgradeRequired || !strings.Contains(rec.Body.String(), "upgrade") {
		t.Errorf("plain request with -require-tls: %d %s", rec.Code, rec.Body)
	}
	if rec := serveRec(f.handler, plainFrom("GET", "/healthz", remote)); rec.Code != http.StatusOK {
		t.Errorf("/healthz with -require-tls: %d", rec.Code)
	}
	if rec := serveRec(f.handler, plainFrom("GET", info, "127.0.0.1:5000")); rec.Code != http.StatusOK {
		t.Errorf("loopback with -require-tls: %d", rec.Code)
	}
	req := plainFrom("GET", info, remote)
	req.TLS = &tls.ConnectionState{}
	if rec := serveRec(f.handler, req); rec.Code != http.StatusOK {
		t.Errorf("TLS with -require-tls: %d", rec.Code)
	}
}

// TestTLSIsAnnounced: once the API is behind the TLS listener, join codes and
// netmaps say so — that is what stops a newer agent ever falling back.
func TestTLSIsAnnounced(t *testing.T) {
	f := newHubFixture(t)
	m := f.join(t, "alice")
	tok, _ := f.store.CreateToken("x", 1, 0)

	code, _ := f.srv.JoinCodeFor(tok.Token)
	if c, _ := joincode.Parse(code); c.TLS {
		t.Fatal("a hub not serving TLS minted a code saying it does")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tl, err := f.srv.TLSListener(ln)
	if err != nil {
		t.Fatal(err)
	}
	defer tl.Close()

	code, _ = f.srv.JoinCodeFor(tok.Token)
	if c, _ := joincode.Parse(code); !c.TLS {
		t.Error("the join code does not carry the TLS flag")
	}
	signed, err := f.store.NetMapFor(m.id)
	if err != nil {
		t.Fatal(err)
	}
	nm, err := signed.Open(f.store.HubKey().Public().Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	if !nm.Network.HubTLS {
		t.Error("the netmap does not say the hub serves TLS")
	}
}

// TestPlainAgentsAreListed: the operator needs to know who still has to be
// upgraded before turning plain HTTP off.
func TestPlainAgentsAreListed(t *testing.T) {
	f := newHubFixture(t)
	old := f.join(t, "old")
	upgraded := f.join(t, "upgraded")

	report := func(m member, overTLS bool) {
		raw, _ := json.Marshal(map[string]any{})
		req := httptest.NewRequest(http.MethodPost, hubapi.APIVersion+"/report", bytes.NewReader(raw))
		req.RemoteAddr = "198.51.100.7:40000"
		if overTLS {
			req.TLS = &tls.ConnectionState{}
		}
		hubapi.SignRequest(req, m.id, m.priv, raw)
		if rec := serveRec(f.handler, req); rec.Code >= 300 {
			t.Fatalf("report from %s: %d %s", m.name, rec.Code, rec.Body)
		}
	}
	report(old, false)
	report(upgraded, true)

	plain := map[string]bool{}
	for _, r := range f.srv.nodeRows() {
		plain[r.Name] = r.PlainHTTP
	}
	if !plain["old"] || plain["upgraded"] {
		t.Errorf("plain-HTTP machines listed as %v; want only old", plain)
	}

	report(old, true)
	for _, r := range f.srv.nodeRows() {
		if r.PlainHTTP {
			t.Errorf("%s is still listed as plain after switching to TLS", r.Name)
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
	if err == nil || !strings.Contains(err.Error(), "upgrade the primary first") {
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
