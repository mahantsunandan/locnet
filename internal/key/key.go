// Package key holds the three kinds of key material LocNet uses.
//
//	Machine   Ed25519      identity — signs control-plane requests and netmaps,
//	                       and is the hub's TLS certificate key
//	WireGuard Curve25519   data plane — the tunnel's own keys
//	Disco     Curve25519   control — seals NAT-traversal probes between peers
//
// They are separate named types on purpose. Handing a disco key to something
// that wanted a WireGuard key is a real bug class, and the compiler catches it
// here rather than leaving you to debug a tunnel that never handshakes.
//
// A node's WireGuard private key never leaves the machine that generated it.
// The hub only ever sees public keys.
package key

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// Size is the length of every Curve25519 key in bytes.
const Size = 32

var errBadLen = errors.New("key: wrong length")

func encode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func decode(s string, out []byte) error {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return fmt.Errorf("key: %w", err)
	}
	if len(raw) != len(out) {
		return fmt.Errorf("%w: got %d, want %d", errBadLen, len(raw), len(out))
	}
	copy(out, raw)
	return nil
}

// ---------------------------------------------------------------- WireGuard

// WGPrivate is a WireGuard Curve25519 private key.
type WGPrivate [Size]byte

// WGPublic is a WireGuard Curve25519 public key.
type WGPublic [Size]byte

// NewWG generates a fresh WireGuard keypair.
func NewWG() (WGPrivate, WGPublic, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return WGPrivate{}, WGPublic{}, err
	}
	return WGPrivate(*priv), WGPublic(*pub), nil
}

// Public derives the public half of k.
func (k WGPrivate) Public() WGPublic {
	var pub [Size]byte
	priv := [Size]byte(k)
	curve25519.ScalarBaseMult(&pub, &priv)
	return WGPublic(pub)
}

// Hex returns the lowercase hex form wireguard-go's UAPI expects.
func (k WGPrivate) Hex() string { return fmt.Sprintf("%x", k[:]) }

// Hex returns the lowercase hex form wireguard-go's UAPI expects.
func (k WGPublic) Hex() string { return fmt.Sprintf("%x", k[:]) }

func (k WGPrivate) String() string { return "wgpriv:[redacted]" }

// String returns a short, human-recognisable prefix. Use MarshalText for the
// full value.
func (k WGPublic) String() string { return encode(k[:])[:8] }

func (k WGPrivate) MarshalText() ([]byte, error)  { return []byte(encode(k[:])), nil }
func (k *WGPrivate) UnmarshalText(b []byte) error { return decode(string(b), k[:]) }
func (k WGPublic) MarshalText() ([]byte, error)   { return []byte(encode(k[:])), nil }
func (k *WGPublic) UnmarshalText(b []byte) error  { return decode(string(b), k[:]) }

// IsZero reports whether k has never been set.
func (k WGPublic) IsZero() bool { return k == WGPublic{} }

// -------------------------------------------------------------------- Disco

// DiscoPrivate is the Curve25519 private key used to seal NAT-traversal
// probes. It is separate from the WireGuard key so that a compromised probe
// path can never expose tunnel key material.
type DiscoPrivate [Size]byte

// DiscoPublic is the public half of a DiscoPrivate.
type DiscoPublic [Size]byte

// NewDisco generates a fresh disco keypair.
func NewDisco() (DiscoPrivate, DiscoPublic, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return DiscoPrivate{}, DiscoPublic{}, err
	}
	return DiscoPrivate(*priv), DiscoPublic(*pub), nil
}

// Public derives the public half of k.
func (k DiscoPrivate) Public() DiscoPublic {
	var pub [Size]byte
	priv := [Size]byte(k)
	curve25519.ScalarBaseMult(&pub, &priv)
	return DiscoPublic(pub)
}

// Seal encrypts msg to peer using NaCl box. The 24-byte nonce is prepended to
// the returned ciphertext.
func (k DiscoPrivate) Seal(peer DiscoPublic, msg []byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	priv, pub := [Size]byte(k), [Size]byte(peer)
	return box.Seal(nonce[:], msg, &nonce, &pub, &priv), nil
}

// Open reverses Seal. It returns false if the box does not authenticate, which
// is the normal outcome for a stray or spoofed packet.
func (k DiscoPrivate) Open(peer DiscoPublic, sealed []byte) ([]byte, bool) {
	if len(sealed) < 24 {
		return nil, false
	}
	var nonce [24]byte
	copy(nonce[:], sealed[:24])
	priv, pub := [Size]byte(k), [Size]byte(peer)
	return box.Open(nil, sealed[24:], &nonce, &pub, &priv)
}

func (k DiscoPrivate) String() string { return "discopriv:[redacted]" }
func (k DiscoPublic) String() string  { return encode(k[:])[:8] }

func (k DiscoPrivate) MarshalText() ([]byte, error)  { return []byte(encode(k[:])), nil }
func (k *DiscoPrivate) UnmarshalText(b []byte) error { return decode(string(b), k[:]) }
func (k DiscoPublic) MarshalText() ([]byte, error)   { return []byte(encode(k[:])), nil }
func (k *DiscoPublic) UnmarshalText(b []byte) error  { return decode(string(b), k[:]) }

// IsZero reports whether k has never been set.
func (k DiscoPublic) IsZero() bool { return k == DiscoPublic{} }

// ------------------------------------------------------------------ Machine

// MachinePrivate is an Ed25519 signing key identifying a node or a hub.
type MachinePrivate struct{ k ed25519.PrivateKey }

// MachinePublic is the verifying half of a MachinePrivate.
type MachinePublic struct{ k ed25519.PublicKey }

// NewMachine generates a fresh identity keypair.
func NewMachine() (MachinePrivate, MachinePublic, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return MachinePrivate{}, MachinePublic{}, err
	}
	return MachinePrivate{priv}, MachinePublic{pub}, nil
}

// IsZero reports whether k was never initialised. Useful for checking that
// something claiming to be a key actually carries one.
func (k MachinePrivate) IsZero() bool { return len(k.k) != ed25519.PrivateKeySize }

// Public derives the public half of k.
func (k MachinePrivate) Public() MachinePublic {
	return MachinePublic{k.k.Public().(ed25519.PublicKey)}
}

// Sign signs msg. It panics on a zero key, which would otherwise produce a
// signature that silently fails to verify everywhere.
func (k MachinePrivate) Sign(msg []byte) []byte {
	if len(k.k) != ed25519.PrivateKeySize {
		panic("key: sign with uninitialised machine key")
	}
	return ed25519.Sign(k.k, msg)
}

// Signer returns k as a crypto.Signer, for the one place the standard library
// needs to hold the key itself: the hub's TLS certificate, whose key is the
// hub's identity key so that the fingerprint a join code pins is also what the
// TLS handshake proves (see package hubtls). It returns nil for a zero key.
func (k MachinePrivate) Signer() crypto.Signer {
	if len(k.k) != ed25519.PrivateKeySize {
		return nil
	}
	return append(ed25519.PrivateKey(nil), k.k...)
}

// Verify reports whether sig is a valid signature of msg by k.
func (k MachinePublic) Verify(msg, sig []byte) bool {
	if len(k.k) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(k.k, msg, sig)
}

// Fingerprint returns the first 16 bytes of SHA-256 over the public key. This
// is what a join code carries: 128 bits is ample to pin a hub, and it keeps
// the code short enough to paste into a chat window.
func (k MachinePublic) Fingerprint() [16]byte {
	sum := sha256.Sum256(k.k)
	return [16]byte(sum[:16])
}

func (k MachinePrivate) String() string { return "machinepriv:[redacted]" }

func (k MachinePublic) String() string {
	if len(k.k) == 0 {
		return "machine:[unset]"
	}
	return encode(k.k)[:8]
}

// IsZero reports whether k has never been set.
func (k MachinePublic) IsZero() bool { return len(k.k) == 0 }

func (k MachinePrivate) MarshalText() ([]byte, error) { return []byte(encode(k.k)), nil }

func (k *MachinePrivate) UnmarshalText(b []byte) error {
	raw := make([]byte, ed25519.PrivateKeySize)
	if err := decode(string(b), raw); err != nil {
		return err
	}
	k.k = raw
	return nil
}

func (k MachinePublic) MarshalText() ([]byte, error) { return []byte(encode(k.k)), nil }

func (k *MachinePublic) UnmarshalText(b []byte) error {
	raw := make([]byte, ed25519.PublicKeySize)
	if err := decode(string(b), raw); err != nil {
		return err
	}
	k.k = raw
	return nil
}

// Bytes returns the raw public key.
func (k MachinePublic) Bytes() []byte { return append([]byte(nil), k.k...) }

// MachinePublicFromBytes rebuilds a public key from its raw form.
func MachinePublicFromBytes(b []byte) (MachinePublic, error) {
	if len(b) != ed25519.PublicKeySize {
		return MachinePublic{}, fmt.Errorf("%w: machine public key is %d bytes", errBadLen, len(b))
	}
	return MachinePublic{append(ed25519.PublicKey(nil), b...)}, nil
}
