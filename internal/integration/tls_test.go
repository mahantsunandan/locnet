package integration

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/mahantsunandan/locnet/internal/joincode"
	"github.com/mahantsunandan/locnet/internal/node"
)

// codeFor mints a join code for h by hand, so a test can point it elsewhere.
func codeFor(t *testing.T, h *testHub) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(h.invite(t))
	if err != nil {
		t.Fatal(err)
	}
	c := joincode.Code{
		HubAddrs:       []string{h.addr},
		HubFingerprint: h.store.HubKey().Public().Fingerprint(),
		Token:          [16]byte(raw),
	}
	s, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newAgent(t *testing.T) *node.Engine {
	t.Helper()
	e, err := node.NewEngine(t.TempDir(), t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func joinCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// TestJoinIsEncrypted: a code the hub mints today is redeemed entirely over
// TLS pinned to the hub's key — the token never crosses the wire in the clear.
func TestJoinIsEncrypted(t *testing.T) {
	h := startHub(t)
	code, err := h.srv.JoinCodeFor(h.invite(t))
	if err != nil {
		t.Fatal(err)
	}

	e := newAgent(t)
	if err := e.Join(joinCtx(t), code); err != nil {
		t.Fatalf("join: %v", err)
	}
	if n := h.plainAPI.Load(); n != 0 {
		t.Errorf("%d API requests of the join went in plain HTTP", n)
	}
	if h.tlsAPI.Load() == 0 {
		t.Error("nothing arrived over TLS")
	}
	if got := e.Status().HubTransport; got != "" && got != "tls" {
		t.Errorf("transport reported as %q", got)
	}
}

// TestPlainHTTPServerGetsNothing: a server at the code's address that answers
// in plain HTTP — something in the way, standing in for the hub — receives no
// request at all, least of all the join token, and the error says why.
func TestPlainHTTPServerGetsNothing(t *testing.T) {
	h := startHubTLS(t, false)
	e := newAgent(t)
	err := e.Join(joinCtx(t), codeFor(t, h))
	if err == nil {
		t.Fatal("joined over plain HTTP")
	}
	if !strings.Contains(err.Error(), "without TLS") {
		t.Errorf("the error does not say what happened: %v", err)
	}
	if n := h.plainAPI.Load() + h.tlsAPI.Load(); n != 0 {
		t.Errorf("the plain-HTTP server received %d API requests", n)
	}
}

// TestImpostorHubGetsNothing: a TLS server at the code's address holding any
// other key fails the pinned handshake before a single request is sent.
func TestImpostorHubGetsNothing(t *testing.T) {
	real := startHub(t)
	impostor := startHub(t)
	code := codeFor(t, real)
	c, _ := joincode.Parse(code)
	c.HubAddrs = []string{impostor.addr}
	code, _ = c.Encode()

	e := newAgent(t)
	if err := e.Join(joinCtx(t), code); err == nil {
		t.Fatal("joined a hub with the wrong key")
	}
	if n := impostor.plainAPI.Load() + impostor.tlsAPI.Load(); n != 0 {
		t.Errorf("the impostor received %d API requests", n)
	}
}
