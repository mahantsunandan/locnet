package hubtls

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mahantsunandan/locnet/internal/key"
)

// serve runs a handler on a sniffing listener and reports, per request,
// whether it arrived over TLS.
func serve(t *testing.T, hubKey key.MachinePrivate) string {
	t.Helper()
	cfg, err := ServerConfig(hubKey)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := Listen(inner, cfg)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS != nil {
				io.WriteString(w, "tls")
			} else {
				io.WriteString(w, "plain")
			}
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return inner.Addr().String()
}

func get(t *testing.T, c *http.Client, url string) (string, error) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

func pinnedClient(fp [16]byte) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: NewTransport(fp, nil)}
}

// TestOnePortServesBoth is the transition: agents from before 0.10.4 speak
// plain HTTP to the same port newer ones reach over TLS.
func TestOnePortServesBoth(t *testing.T) {
	hubKey, hubPub, _ := key.NewMachine()
	addr := serve(t, hubKey)

	got, err := get(t, &http.Client{Timeout: 5 * time.Second}, "http://"+addr+"/")
	if err != nil || got != "plain" {
		t.Fatalf("plain HTTP: %q, %v", got, err)
	}
	got, err = get(t, pinnedClient(hubPub.Fingerprint()), "https://"+addr+"/")
	if err != nil || got != "tls" {
		t.Fatalf("pinned TLS: %q, %v", got, err)
	}
}

// TestWrongHubIsRefused: a server with any other key — someone on the path
// answering in the hub's place — fails the handshake, whatever it presents.
func TestWrongHubIsRefused(t *testing.T) {
	impostor, _, _ := key.NewMachine()
	_, realPub, _ := key.NewMachine()
	addr := serve(t, impostor)

	_, err := get(t, pinnedClient(realPub.Fingerprint()), "https://"+addr+"/")
	var wrong *WrongHubError
	if !errors.As(err, &wrong) {
		t.Fatalf("an impostor's certificate was not refused as the wrong hub: %v", err)
	}
	if wrong.Want != realPub.Fingerprint() || wrong.Got != impostor.Public().Fingerprint() {
		t.Errorf("the error names the wrong keys: %+v", wrong)
	}
}

// TestCAIssuedCertificateIsNotEnough: a certificate any CA would vouch for
// is still not the hub. httptest's certificate is RSA and signed by its own
// root; the pin refuses it before trust in any root is even considered.
func TestCAIssuedCertificateIsNotEnough(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	_, pub, _ := key.NewMachine()
	c := pinnedClient(pub.Fingerprint())
	if _, err := get(t, c, srv.URL); err == nil {
		t.Fatal("a server not holding the hub's key was accepted")
	}
}

// TestPlainServerIsRecognised: the client must be able to tell "this hub is
// too old for TLS" from "something is wrong", because only the first is a
// reason to fall back to plain HTTP.
func TestPlainServerIsRecognised(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer plain.Close()
	_, pub, _ := key.NewMachine()
	_, err := get(t, pinnedClient(pub.Fingerprint()), "https://"+plain.Listener.Addr().String()+"/")
	if !IsPlainServer(err) {
		t.Fatalf("a plain-HTTP server was not recognised as one: %v", err)
	}

	impostor, _, _ := key.NewMachine()
	addr := serve(t, impostor)
	_, err = get(t, pinnedClient(pub.Fingerprint()), "https://"+addr+"/")
	if IsPlainServer(err) {
		t.Fatal("a wrong-key TLS server was taken for a plain one — that would let an impostor force plain HTTP")
	}
}

// TestTLS12IsRefused: in TLS 1.2 the server signs bytes the client chose.
func TestTLS12IsRefused(t *testing.T) {
	hubKey, hubPub, _ := key.NewMachine()
	addr := serve(t, hubKey)
	cfg := ClientConfig(hubPub.Fingerprint())
	cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	c, err := tls.Dial("tcp", addr, cfg)
	if err == nil {
		c.Close()
		t.Fatal("the hub completed a TLS 1.2 handshake")
	}
}

// TestSilentClientDoesNotBlockOthers: the first byte is read off the accept
// path, so a connection that sends nothing holds up nobody else.
func TestSilentClientDoesNotBlockOthers(t *testing.T) {
	hubKey, _, _ := key.NewMachine()
	addr := serve(t, hubKey)
	silent, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()

	c := &http.Client{Timeout: 2 * time.Second}
	got, err := get(t, c, "http://"+addr+"/")
	if err != nil || !strings.Contains(got, "plain") {
		t.Fatalf("a silent connection blocked the next client: %q, %v", got, err)
	}
}

// TestCloseStopsAccept: http.Server.Close must be able to end Serve.
func TestCloseStopsAccept(t *testing.T) {
	hubKey, _, _ := key.NewMachine()
	cfg, _ := ServerConfig(hubKey)
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := Listen(inner, cfg)
	done := make(chan error, 1)
	go func() { _, err := ln.Accept(); done <- err }()
	ln.Close()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept after Close returned %v, want net.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not return after Close")
	}
}
