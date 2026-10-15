// Package joincode encodes everything a new machine needs to join a network
// into one pasteable string.
//
// A join code looks like this:
//
//	locnet1_qkzgeaaaaaaqbcdefghijklmnopqrstuvwxyz234567abcdefghijklmnop...
//
// and carries three things:
//
//   - where the hub is — one address or several, tried in order
//   - a 16-byte fingerprint of the hub's identity key
//   - a 16-byte auth token the hub will recognise
//
// plus a flag saying the hub must be reached over TLS (see package hubtls).
//
// Several addresses matter more than it sounds. A hub behind NAT has a LAN
// address its neighbours use and a public address everyone else uses, and no
// single one works from both sides — a router that will not hairpin means the
// hub cannot even reach itself through its own public address. One code
// carrying both lets the same code work at home, on a hotspot, and remotely,
// and lets a laptop move between them without rejoining anything.
//
// The fingerprint is the part that matters for security. Without it, the first
// contact with a hub would be trust-on-first-use and a machine on the same
// network could answer in the hub's place. With it, locnetd refuses to talk to
// anything whose identity key does not hash to the expected value, so the code
// is safe to send over a channel you do not fully trust — the token alone is
// useless against the real hub, and the fingerprint alone cannot be forged.
//
// Treat a join code like a password anyway: anyone holding one can add a
// machine to your network until the token is spent or revoked.
package joincode

import (
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"strings"
)

// Prefix marks a v1 join code.
const Prefix = "locnet1_"

const (
	magic0, magic1 = 'L', 'N'
	// version1 carried exactly one address. version2 carries a counted list.
	// Both are still accepted, so codes handed out before the upgrade keep
	// working.
	version1 = 1
	version2 = 2

	fpLen    = 16
	tokenLen = 16
	// magic(2) version(1) flags(1) fingerprint(16) token(16) count(1) crc(4)
	fixedLen = 2 + 1 + 1 + fpLen + tokenLen + 1 + 4
	// flagTLS says the hub serves TLS pinned to the fingerprint, so a
	// joining machine never sends the token in the clear. The flags byte was
	// reserved and is ignored by older parsers, which keep using plain HTTP
	// against a hub that still accepts it.
	flagTLS = 1 << 0
	// maxAddrs bounds a code. More than a handful is a configuration
	// mistake, and every one of them is an address a joining machine will
	// sit and wait on.
	maxAddrs = 8
)

// enc is lowercase base32 without padding: no ambiguous characters, no "="
// tail, and safe to paste into a URL, a shell, or a chat message.
var enc = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// ErrMalformed is returned for anything that is not a well-formed join code.
var ErrMalformed = errors.New("joincode: malformed")

// Code is the decoded content of a join code.
type Code struct {
	// HubAddrs are host:port candidates, most specific first. A joining
	// machine tries them in order and remembers which one answered.
	HubAddrs []string
	// HubFingerprint pins the hub's identity key. See key.MachinePublic.Fingerprint.
	HubFingerprint [fpLen]byte
	// Token authenticates the join request to the hub.
	Token [tokenLen]byte
	// TLS is set by hubs from 0.10.4 on: bare host:port addresses must be
	// reached over TLS pinned to HubFingerprint, never plain HTTP.
	TLS bool
}

// Primary is the first address, for messages that need to name just one.
func (c Code) Primary() string {
	if len(c.HubAddrs) == 0 {
		return ""
	}
	return c.HubAddrs[0]
}

// Encode renders c as a pasteable string.
func (c Code) Encode() (string, error) {
	if len(c.HubAddrs) == 0 {
		return "", fmt.Errorf("joincode: at least one hub address is required")
	}
	if len(c.HubAddrs) > maxAddrs {
		return "", fmt.Errorf("joincode: %d hub addresses is too many (max %d)", len(c.HubAddrs), maxAddrs)
	}
	for _, a := range c.HubAddrs {
		if a == "" {
			return "", fmt.Errorf("joincode: a hub address is empty")
		}
		if len(a) > 255 {
			return "", fmt.Errorf("joincode: hub address %q is too long (%d bytes, max 255)", a, len(a))
		}
	}

	buf := make([]byte, 0, fixedLen+64)
	var flags byte
	if c.TLS {
		flags |= flagTLS
	}
	buf = append(buf, magic0, magic1, version2, flags)
	buf = append(buf, c.HubFingerprint[:]...)
	buf = append(buf, c.Token[:]...)
	buf = append(buf, byte(len(c.HubAddrs)))
	for _, a := range c.HubAddrs {
		buf = append(buf, byte(len(a)))
		buf = append(buf, a...)
	}

	buf = binary.BigEndian.AppendUint32(buf, crc32.ChecksumIEEE(buf))
	return Prefix + enc.EncodeToString(buf), nil
}

// Parse decodes a join code. It tolerates the mangling a code picks up in
// transit: surrounding whitespace, a mixed-case paste, and the dashes or
// spaces people add when reading one aloud.
func Parse(s string) (Code, error) {
	var c Code

	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, s)
	s = strings.ToLower(s)

	body, ok := strings.CutPrefix(s, Prefix)
	if !ok {
		return c, fmt.Errorf("%w: expected a code starting with %q", ErrMalformed, Prefix)
	}

	buf, err := enc.DecodeString(body)
	if err != nil {
		return c, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if len(buf) < fixedLen {
		return c, fmt.Errorf("%w: too short (%d bytes)", ErrMalformed, len(buf))
	}

	payload, want := buf[:len(buf)-4], binary.BigEndian.Uint32(buf[len(buf)-4:])
	if got := crc32.ChecksumIEEE(payload); got != want {
		return c, fmt.Errorf("%w: checksum mismatch — the code was copied incompletely", ErrMalformed)
	}
	if payload[0] != magic0 || payload[1] != magic1 {
		return c, fmt.Errorf("%w: not a LocNet code", ErrMalformed)
	}
	c.TLS = payload[3]&flagTLS != 0
	p := payload[4:]
	c.HubFingerprint = [fpLen]byte(p[:fpLen])
	p = p[fpLen:]
	c.Token = [tokenLen]byte(p[:tokenLen])
	p = p[tokenLen:]

	switch payload[2] {
	case version1:
		// One length-prefixed address.
		hostLen := int(p[0])
		p = p[1:]
		if len(p) != hostLen {
			return c, fmt.Errorf("%w: hub address length does not match", ErrMalformed)
		}
		c.HubAddrs = []string{string(p)}

	case version2:
		count := int(p[0])
		p = p[1:]
		if count == 0 || count > maxAddrs {
			return c, fmt.Errorf("%w: %d hub addresses", ErrMalformed, count)
		}
		for i := 0; i < count; i++ {
			if len(p) < 1 {
				return c, fmt.Errorf("%w: truncated address list", ErrMalformed)
			}
			n := int(p[0])
			p = p[1:]
			if len(p) < n {
				return c, fmt.Errorf("%w: truncated address", ErrMalformed)
			}
			c.HubAddrs = append(c.HubAddrs, string(p[:n]))
			p = p[n:]
		}
		if len(p) != 0 {
			return c, fmt.Errorf("%w: trailing bytes after the address list", ErrMalformed)
		}

	default:
		return c, fmt.Errorf("joincode: this code is version %d, but this build understands 1 and 2 — upgrade locnet", payload[2])
	}

	for _, a := range c.HubAddrs {
		if a == "" {
			return c, fmt.Errorf("%w: empty hub address", ErrMalformed)
		}
	}
	return c, nil
}

// Redact returns a code with its middle removed, for logs and status output.
// Enough remains to tell two codes apart; not enough to use one.
func Redact(s string) string {
	if len(s) < len(Prefix)+16 {
		return "locnet1_…"
	}
	return s[:len(Prefix)+6] + "…" + s[len(s)-4:]
}
