// Package hubtls makes the hub's control plane confidential without a
// certificate authority.
//
// Every response that matters on the control plane was already signed by the
// hub's identity key, and every request by the sending machine's, so plain
// HTTP was authentic — but not private. Join codes minted through the API,
// every machine's endpoints and LAN addresses, and a standby's copy of the
// hub's signing key all crossed the network readable by anyone on the path.
//
// The fix needs no CA and no Let's Encrypt, because every client already pins
// the hub: a join code carries the first 16 bytes of SHA-256 over the hub's
// Ed25519 identity key. So the hub's TLS certificate is self-signed with that
// same key, and a client accepts the handshake only if the certificate's key
// hashes to the fingerprint it already trusts. TLS 1.3 then proves the hub
// holds the private half (CertificateVerify), and the rest is ordinary TLS.
//
// Using the identity key itself, rather than a separate key it certifies, is
// safe because of what else that key signs and how: netmaps, which are JSON
// objects starting with '{'. A TLS 1.3 CertificateVerify signature covers 64
// spaces, a context string and a transcript hash — never valid JSON, never a
// netmap. TLS 1.2 is refused on both sides: there the server signs the
// client's random bytes first, which would make the hub sign 32 bytes of the
// client's choosing.
//
// The hub also answers plain HTTP on the same port, but only to its own
// loopback address, where its admin commands run. A TLS connection's first
// byte is always 0x16 (a handshake record) and an HTTP request's is a letter,
// so one look tells them apart; see Listen.
package hubtls

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/mahantsunandan/locnet/internal/key"
)

// handshakeRecord is the first byte of every TLS connection: the record type
// of a ClientHello.
const handshakeRecord = 0x16

// sniffTimeout bounds how long an accepted connection may take to send its
// first byte before it is dropped. It matches the hub's ReadHeaderTimeout.
const sniffTimeout = 10 * time.Second

// ServerConfig returns the hub's TLS configuration: a self-signed certificate
// whose key is the hub's identity key.
//
// The certificate is made fresh each time the hub starts. Nothing in it but
// the key is checked by anyone — clients pin the key, not the certificate —
// so there is nothing to renew and no expiry to forget.
func ServerConfig(hubKey key.MachinePrivate) (*tls.Config, error) {
	signer := hubKey.Signer()
	if signer == nil {
		return nil, errors.New("hubtls: the hub has no identity key")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, err
	}
	fp := hubKey.Public().Fingerprint()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: fmt.Sprintf("locnet-hub %x", fp)},
		NotBefore:    time.Now().Add(-time.Hour),
		// Far enough out never to matter: clients do not check it, but a
		// browser or curl pointed at the port shows something sensible.
		NotAfter:    time.Now().AddDate(30, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("hubtls: certificate: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: signer}},
		// HTTP/1.1 only. The long poll and the plain-HTTP twin on the same
		// port are both simpler without HTTP/2, and nothing here is
		// latency-bound enough to want it.
		NextProtos: []string{"http/1.1"},
	}, nil
}

// WrongHubError is returned when the server's key is not the pinned one.
type WrongHubError struct {
	Want, Got [16]byte
}

func (e *WrongHubError) Error() string {
	return fmt.Sprintf("the hub presented identity %x, but this machine trusts %x — "+
		"either something is impersonating the hub, or the hub's key was regenerated "+
		"(then rejoin with a new code: locnet join <code>)", e.Got, e.Want)
}

// ClientConfig returns a TLS configuration that accepts only a server whose
// certificate key hashes to fp.
//
// The usual chain-of-trust check is switched off because there is no chain:
// the certificate is self-signed and the trust comes from the fingerprint.
// VerifyConnection, not VerifyPeerCertificate, does the pinning, because it
// runs on every handshake including a resumed one, which the other does not.
func ClientConfig(fp [16]byte) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // replaced by the pin below
		NextProtos:         []string{"http/1.1"},
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyPin(cs.PeerCertificates, fp)
		},
	}
}

func verifyPin(certs []*x509.Certificate, fp [16]byte) error {
	if len(certs) == 0 {
		return errors.New("hubtls: the hub presented no certificate")
	}
	pub, ok := certs[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("hubtls: the hub's certificate key is %T, not Ed25519 — this is not a LocNet hub", certs[0].PublicKey)
	}
	mp, err := key.MachinePublicFromBytes(pub)
	if err != nil {
		return err
	}
	if got := mp.Fingerprint(); got != fp {
		return &WrongHubError{Want: fp, Got: got}
	}
	return nil
}

// ErrPlainServer is a TLS client meeting a server that answered in plain
// HTTP — not a LocNet hub, or something in the way pretending to be one.
var ErrPlainServer = errors.New("the server answered in plain HTTP, not TLS — it is not a LocNet hub")

// IsPlainServer reports whether err came from a server that does not speak
// TLS, so callers can say so plainly instead of reporting a handshake error.
// It is never a reason to retry without TLS.
func IsPlainServer(err error) bool { return errors.Is(err, ErrPlainServer) }

// handshakeTimeout bounds a TLS handshake with the hub, as the dial is.
const handshakeTimeout = 5 * time.Second

// DialFunc is the shape of net.Dialer.DialContext.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Dialer returns a DialTLSContext for http.Transport that pins fp.
//
// It does the handshake itself rather than leaving it to the transport,
// because net/http turns "the server answered in plain HTTP" into an
// untyped error string; here it becomes ErrPlainServer, which a caller can
// test for without matching text.
func Dialer(fp [16]byte, dial DialFunc) DialFunc {
	if dial == nil {
		dial = (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}
	cfg := ClientConfig(fp)
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		raw, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		tc := tls.Client(raw, cfg)
		hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
		defer cancel()
		if err := tc.HandshakeContext(hctx); err != nil {
			raw.Close()
			var rh tls.RecordHeaderError
			if errors.As(err, &rh) {
				return nil, fmt.Errorf("%s: %w", addr, ErrPlainServer)
			}
			return nil, err
		}
		return tc, nil
	}
}

// NewTransport returns an http.Transport whose https:// requests reach only
// the hub pinned by fp. base, if not nil, supplies the other settings (its
// DialContext is used under TLS too).
func NewTransport(fp [16]byte, base *http.Transport) *http.Transport {
	var t *http.Transport
	if base != nil {
		t = base.Clone()
	} else {
		t = &http.Transport{IdleConnTimeout: 60 * time.Second}
	}
	t.DialTLSContext = Dialer(fp, t.DialContext)
	return t
}

// Listen wraps a TCP listener so that it hands out TLS connections to
// clients that start a TLS handshake and plain connections to everyone else.
//
// The first byte is read off each connection in its own goroutine, never in
// Accept: a client that connects and says nothing would otherwise stop the
// hub accepting anyone for the length of the timeout.
//
// net/http tells the two apart by type: a *tls.Conn is handshaken and its
// requests carry r.TLS; anything else is served as plain HTTP with r.TLS nil.
func Listen(inner net.Listener, cfg *tls.Config) net.Listener {
	l := &listener{
		Listener: inner,
		cfg:      cfg,
		conns:    make(chan net.Conn),
		errs:     make(chan error, 1),
		done:     make(chan struct{}),
	}
	go l.acceptLoop()
	return l
}

type listener struct {
	net.Listener
	cfg   *tls.Config
	conns chan net.Conn
	errs  chan error
	done  chan struct{}
	once  sync.Once
}

func (l *listener) acceptLoop() {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				select {
				case l.errs <- err:
				default:
				}
				return
			}
			// A transient failure — out of file descriptors, a connection
			// reset between SYN and accept. Pause rather than spin.
			select {
			case <-l.done:
				return
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}
		go l.sniff(c)
	}
}

func (l *listener) sniff(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(sniffTimeout))
	br := bufio.NewReaderSize(c, 1)
	first, err := br.Peek(1)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		c.Close()
		return
	}
	var out net.Conn = &peekedConn{Conn: c, r: br}
	if first[0] == handshakeRecord {
		out = tls.Server(out, l.cfg)
	}
	select {
	case l.conns <- out:
	case <-l.done:
		c.Close()
	}
}

func (l *listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case err := <-l.errs:
		// Keep reporting closure to every later caller too.
		select {
		case l.errs <- err:
		default:
		}
		return nil, err
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *listener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}

// peekedConn replays the byte the listener looked at before handing the
// connection on.
type peekedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *peekedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
