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

// codeFor mints a join code for h, with the TLS flag forced to withTLS so a
// test can stand in for a code minted before 0.10.4.
func codeFor(t *testing.T, h *testHub, withTLS bool) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(h.invite(t))
	if err != nil {
		t.Fatal(err)
	}
	c := joincode.Code{
		HubAddrs:       []string{h.addr},
		HubFingerprint: h.store.HubKey().Public().Fingerprint(),
		Token:          [16]byte(raw),
		TLS:            withTLS,
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
	if c, _ := joincode.Parse(code); !c.TLS {
		t.Fatal("the hub's own code does not ask for TLS")
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
	if !e.State().HubTLS {
		t.Error("the agent did not remember that the hub requires TLS")
	}
}

// TestOldCodeUpgradesToTLS: a code minted before 0.10.4 says nothing about
// TLS, but a new agent tries it first anyway and keeps it.
func TestOldCodeUpgradesToTLS(t *testing.T) {
	h := startHub(t)
	e := newAgent(t)
	if err := e.Join(joinCtx(t), codeFor(t, h, false)); err != nil {
		t.Fatalf("join: %v", err)
	}
	if n := h.plainAPI.Load(); n != 0 {
		t.Errorf("%d requests went in plain HTTP although the hub speaks TLS", n)
	}
	if !e.State().HubTLS {
		t.Error("a working pinned handshake was not remembered")
	}
}

// TestNewAgentStillJoinsAnOldHub: agents are upgraded before or after the
// hub, in any order, so a new agent must still work with a hub that knows
// only plain HTTP — as long as nothing told it that hub speaks TLS.
func TestNewAgentStillJoinsAnOldHub(t *testing.T) {
	h := startHubTLS(t, false)
	e := newAgent(t)
	if err := e.Join(joinCtx(t), codeFor(t, h, false)); err != nil {
		t.Fatalf("a new agent could not join a plain-HTTP hub: %v", err)
	}
	if e.State().HubTLS {
		t.Error("the agent believes a plain-HTTP hub speaks TLS")
	}
}

// TestTLSIsNeverDowngraded: a code saying the hub speaks TLS, met by a server
// answering in plain HTTP at that address, is someone in the way (or a hub
// downgraded by hand). The token must not be sent.
func TestTLSIsNeverDowngraded(t *testing.T) {
	h := startHubTLS(t, false)
	e := newAgent(t)
	err := e.Join(joinCtx(t), codeFor(t, h, true))
	if err == nil {
		t.Fatal("joined in plain HTTP with a code that requires TLS")
	}
	if !strings.Contains(err.Error(), "plain HTTP") {
		t.Errorf("the error does not say what happened: %v", err)
	}
	if n := h.registers.Load(); n != 0 {
		t.Errorf("the join token was sent in the clear %d time(s)", n)
	}
}

// TestImpostorHubGetsNothing: a TLS server at the code's address holding any
// other key fails the pinned handshake before a single request is sent.
func TestImpostorHubGetsNothing(t *testing.T) {
	real := startHub(t)
	impostor := startHub(t)
	code := codeFor(t, real, true)
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
