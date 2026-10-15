// Package disco is the NAT-traversal and relay protocol.
//
// Disco packets share a UDP port with WireGuard traffic. That sharing is the
// whole trick: a NAT mapping is created for a (source port, destination)
// pair, so a hole punched by a probe is only useful to WireGuard if WireGuard
// sends from the same port. Running discovery on a second socket would punch a
// hole nothing could use.
//
// Telling the two apart is easy and unambiguous. A WireGuard packet begins
// with a little-endian uint32 message type of 1 to 4, so its first byte is
// 0x01–0x04 and the next three are zero. Every disco packet begins with the
// four bytes "LNd1". No valid WireGuard packet can start that way.
//
// Peer-to-peer messages (ping, pong) are sealed with NaCl box between disco
// keys, so a relay forwards them without being able to read them and an
// off-path attacker cannot forge one. Node-to-relay messages are signed with
// the node's identity key instead — the relay has to read those to do its job.
package disco

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/mahantsunandan/locnet/internal/key"
)

// Magic prefixes every disco packet.
var Magic = [4]byte{'L', 'N', 'd', '1'}

// MessageType identifies a disco packet.
type MessageType byte

const (
	// TypeBind registers a node's current source address with a relay. It
	// doubles as this project's STUN: the reply reports what the relay saw.
	TypeBind MessageType = 1
	// TypeBindReply answers a TypeBind.
	TypeBindReply MessageType = 2
	// TypeForward asks a relay to pass a payload to another node.
	TypeForward MessageType = 3
	// TypeForwarded delivers a relayed payload.
	TypeForwarded MessageType = 4
	// TypePing probes a candidate direct path.
	TypePing MessageType = 5
	// TypePong answers a TypePing and reports the observed source address.
	TypePong MessageType = 6
)

func (t MessageType) String() string {
	switch t {
	case TypeBind:
		return "bind"
	case TypeBindReply:
		return "bind-reply"
	case TypeForward:
		return "forward"
	case TypeForwarded:
		return "forwarded"
	case TypePing:
		return "ping"
	case TypePong:
		return "pong"
	}
	return fmt.Sprintf("disco(%d)", byte(t))
}

const (
	headerLen = 5 // magic(4) + type(1)
	// AddrPortLen is the encoded size of a netip.AddrPort: a 16-byte
	// v4-mapped address followed by a big-endian port.
	AddrPortLen = 18
	// MaxPacketSize bounds a disco or relayed packet. A relayed WireGuard
	// packet is the largest thing here: tunnel MTU plus WireGuard's own
	// overhead plus the relay header.
	MaxPacketSize = 1500
)

// ErrNotDisco means the packet is not ours — almost always because it is a
// WireGuard packet, which is the expected case on a shared port.
var ErrNotDisco = errors.New("disco: not a disco packet")

// ErrShort means the packet is disco but truncated.
var ErrShort = errors.New("disco: packet too short")

// Type reports the message type of a raw packet, or ErrNotDisco.
func Type(pkt []byte) (MessageType, []byte, error) {
	if len(pkt) < headerLen {
		return 0, nil, ErrNotDisco
	}
	if [4]byte(pkt[:4]) != Magic {
		return 0, nil, ErrNotDisco
	}
	return MessageType(pkt[4]), pkt[headerLen:], nil
}

// IsDisco reports whether pkt carries the disco magic. Cheap enough to call on
// every inbound packet.
func IsDisco(pkt []byte) bool {
	return len(pkt) >= headerLen && [4]byte(pkt[:4]) == Magic
}

func header(t MessageType) []byte {
	return []byte{Magic[0], Magic[1], Magic[2], Magic[3], byte(t)}
}

// AppendAddrPort encodes ap as 18 bytes. The zero value encodes as all zeroes
// and decodes back to the zero value.
func AppendAddrPort(b []byte, ap netip.AddrPort) []byte {
	var ip [16]byte
	if ap.IsValid() {
		ip = ap.Addr().As16()
	}
	b = append(b, ip[:]...)
	return binary.BigEndian.AppendUint16(b, ap.Port())
}

// ParseAddrPort decodes 18 bytes written by AppendAddrPort.
func ParseAddrPort(b []byte) (netip.AddrPort, error) {
	if len(b) < AddrPortLen {
		return netip.AddrPort{}, ErrShort
	}
	addr := netip.AddrFrom16([16]byte(b[:16]))
	port := binary.BigEndian.Uint16(b[16:18])
	if addr.IsUnspecified() && port == 0 {
		return netip.AddrPort{}, nil
	}
	return netip.AddrPortFrom(addr.Unmap(), port), nil
}

// ---------------------------------------------------------------- bind

// Bind is a node announcing itself to a relay.
type Bind struct {
	NodeID string
	WGKey  key.WGPublic
	Nonce  uint64 // echoed in the reply, so a node can match request to answer
}

// signingBytes is the exact content a Bind's signature covers.
func (b *Bind) signingBytes() []byte {
	out := make([]byte, 0, 64+len(b.NodeID))
	out = append(out, Magic[:]...)
	out = append(out, byte(TypeBind))
	out = binary.BigEndian.AppendUint16(out, uint16(len(b.NodeID)))
	out = append(out, b.NodeID...)
	out = append(out, b.WGKey[:]...)
	return binary.BigEndian.AppendUint64(out, b.Nonce)
}

// Encode renders a signed bind packet.
func (b *Bind) Encode(mk key.MachinePrivate) ([]byte, error) {
	if len(b.NodeID) > 255 {
		return nil, fmt.Errorf("disco: node ID too long")
	}
	signed := b.signingBytes()
	sig := mk.Sign(signed)

	out := make([]byte, 0, len(signed)+len(sig))
	out = append(out, signed...)
	return append(out, sig...), nil
}

// ParseBind decodes and verifies a bind packet. lookup resolves a node ID to
// its registered identity key.
func ParseBind(body []byte, lookup func(nodeID string) (key.MachinePublic, bool)) (*Bind, error) {
	// body starts after the 5-byte header, but the signature covers the
	// header too, so rebuild the full signed range.
	if len(body) < 2 {
		return nil, ErrShort
	}
	nameLen := int(binary.BigEndian.Uint16(body[:2]))
	need := 2 + nameLen + key.Size + 8 + 64
	if len(body) < need {
		return nil, ErrShort
	}
	p := body[2:]
	b := &Bind{NodeID: string(p[:nameLen])}
	p = p[nameLen:]
	b.WGKey = key.WGPublic(p[:key.Size])
	p = p[key.Size:]
	b.Nonce = binary.BigEndian.Uint64(p[:8])
	sig := p[8 : 8+64]

	pub, ok := lookup(b.NodeID)
	if !ok {
		return nil, fmt.Errorf("disco: bind from unknown node %q", b.NodeID)
	}
	if !pub.Verify(b.signingBytes(), sig) {
		return nil, fmt.Errorf("disco: bind signature does not verify")
	}
	return b, nil
}

// BindReply tells a node how the relay sees it.
type BindReply struct {
	Nonce    uint64
	Observed netip.AddrPort
}

// Encode renders a bind reply.
func (r *BindReply) Encode() []byte {
	out := header(TypeBindReply)
	out = binary.BigEndian.AppendUint64(out, r.Nonce)
	return AppendAddrPort(out, r.Observed)
}

// ParseBindReply decodes a bind reply body.
func ParseBindReply(body []byte) (*BindReply, error) {
	if len(body) < 8+AddrPortLen {
		return nil, ErrShort
	}
	r := &BindReply{Nonce: binary.BigEndian.Uint64(body[:8])}
	ap, err := ParseAddrPort(body[8:])
	if err != nil {
		return nil, err
	}
	r.Observed = ap
	return r, nil
}

// ---------------------------------------------------------------- forward

// EncodeForward wraps payload for delivery to dst through a relay.
func EncodeForward(dst, src key.WGPublic, payload []byte) []byte {
	out := make([]byte, 0, headerLen+2*key.Size+len(payload))
	out = append(out, header(TypeForward)...)
	out = append(out, dst[:]...)
	out = append(out, src[:]...)
	return append(out, payload...)
}

// ParseForward splits a forward body into its parts. The returned payload
// aliases body.
func ParseForward(body []byte) (dst, src key.WGPublic, payload []byte, err error) {
	if len(body) < 2*key.Size {
		return dst, src, nil, ErrShort
	}
	dst = key.WGPublic(body[:key.Size])
	src = key.WGPublic(body[key.Size : 2*key.Size])
	return dst, src, body[2*key.Size:], nil
}

// EncodeForwarded is what the relay sends on to the destination.
func EncodeForwarded(src key.WGPublic, payload []byte) []byte {
	out := make([]byte, 0, headerLen+key.Size+len(payload))
	out = append(out, header(TypeForwarded)...)
	out = append(out, src[:]...)
	return append(out, payload...)
}

// ParseForwarded splits a forwarded body. The returned payload aliases body.
func ParseForwarded(body []byte) (src key.WGPublic, payload []byte, err error) {
	if len(body) < key.Size {
		return src, nil, ErrShort
	}
	return key.WGPublic(body[:key.Size]), body[key.Size:], nil
}

// ---------------------------------------------------------------- ping/pong

// Ping probes one candidate path to a peer.
type Ping struct {
	TxID  uint64
	WGKey key.WGPublic // the sender's, so the receiver can identify the path
}

// Pong answers a Ping.
type Pong struct {
	TxID uint64
	// WGKey is the responder's.
	WGKey key.WGPublic
	// Src is where the responder saw the ping come from. This is how a node
	// learns its own public address from a peer rather than from the relay.
	Src netip.AddrPort
}

// EncodePing seals p to peer. The sender's disco public key travels in the
// clear so the receiver knows which key to open the box with.
func EncodePing(p *Ping, priv key.DiscoPrivate, peer key.DiscoPublic) ([]byte, error) {
	inner := binary.BigEndian.AppendUint64(nil, p.TxID)
	inner = append(inner, p.WGKey[:]...)
	return sealMsg(TypePing, inner, priv, peer)
}

// EncodePong seals p to peer.
func EncodePong(p *Pong, priv key.DiscoPrivate, peer key.DiscoPublic) ([]byte, error) {
	inner := binary.BigEndian.AppendUint64(nil, p.TxID)
	inner = append(inner, p.WGKey[:]...)
	inner = AppendAddrPort(inner, p.Src)
	return sealMsg(TypePong, inner, priv, peer)
}

func sealMsg(t MessageType, inner []byte, priv key.DiscoPrivate, peer key.DiscoPublic) ([]byte, error) {
	sealed, err := priv.Seal(peer, inner)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, headerLen+key.Size+len(sealed))
	out = append(out, header(t)...)
	senderPub := priv.Public()
	out = append(out, senderPub[:]...)
	return append(out, sealed...), nil
}

// SenderDiscoKey reads the cleartext sender key from a ping or pong body.
func SenderDiscoKey(body []byte) (key.DiscoPublic, error) {
	if len(body) < key.Size {
		return key.DiscoPublic{}, ErrShort
	}
	return key.DiscoPublic(body[:key.Size]), nil
}

// OpenPing unseals a ping body.
func OpenPing(body []byte, priv key.DiscoPrivate) (*Ping, error) {
	inner, sender, err := openMsg(body, priv)
	if err != nil {
		return nil, err
	}
	_ = sender
	if len(inner) < 8+key.Size {
		return nil, ErrShort
	}
	return &Ping{
		TxID:  binary.BigEndian.Uint64(inner[:8]),
		WGKey: key.WGPublic(inner[8 : 8+key.Size]),
	}, nil
}

// OpenPong unseals a pong body.
func OpenPong(body []byte, priv key.DiscoPrivate) (*Pong, error) {
	inner, _, err := openMsg(body, priv)
	if err != nil {
		return nil, err
	}
	if len(inner) < 8+key.Size+AddrPortLen {
		return nil, ErrShort
	}
	p := &Pong{
		TxID:  binary.BigEndian.Uint64(inner[:8]),
		WGKey: key.WGPublic(inner[8 : 8+key.Size]),
	}
	src, err := ParseAddrPort(inner[8+key.Size:])
	if err != nil {
		return nil, err
	}
	p.Src = src
	return p, nil
}

func openMsg(body []byte, priv key.DiscoPrivate) ([]byte, key.DiscoPublic, error) {
	sender, err := SenderDiscoKey(body)
	if err != nil {
		return nil, sender, err
	}
	inner, ok := priv.Open(sender, body[key.Size:])
	if !ok {
		return nil, sender, fmt.Errorf("disco: box does not authenticate")
	}
	return inner, sender, nil
}
