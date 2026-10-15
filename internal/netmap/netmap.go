// Package netmap defines the network map — the hub's answer to "who else is on
// this network, and how do I reach them".
//
// The map is signed by the hub's identity key and verified by every node
// against the fingerprint baked into its join code. The map travels inside
// TLS pinned to the same key, but the signature does not depend on that: an
// attacker who could read or rewrite the wire still could not add a peer,
// move a peer's address, or hand a node a WireGuard key it will trust.
package netmap

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"github.com/mahantsunandan/locnet/internal/key"
	"github.com/mahantsunandan/locnet/internal/policy"
	"github.com/mahantsunandan/locnet/internal/resource"
)

// Node describes one machine on the network. Everything here is public by
// design — no private key material ever reaches the hub.
type Node struct {
	ID string `json:"id"`
	// Name is the DNS label for this node, derived from its hostname and
	// unique within the network.
	Name string `json:"name"`
	// OS is "linux", "darwin" or "windows", reported by the node. Cosmetic.
	OS string `json:"os"`

	MachineKey key.MachinePublic `json:"machine_key"`
	WGKey      key.WGPublic      `json:"wg_key"`
	DiscoKey   key.DiscoPublic   `json:"disco_key"`

	// IP is the node's address inside the overlay.
	IP netip.Addr `json:"ip"`

	// Endpoints are candidate paths to this node, best-guess first: its LAN
	// addresses, plus whatever the relay observed as its public address. A
	// peer probes all of them and keeps whichever answers.
	Endpoints []netip.AddrPort `json:"endpoints,omitempty"`

	// Routes are subnets this node offers to forward for. Reserved for the
	// subnet-router feature; carried through the map but not yet programmed.
	Routes []netip.Prefix `json:"routes,omitempty"`

	// LAN describes this node's real network interfaces: hardware addresses
	// and the subnets they are on. It is what makes it possible to wake a
	// machine that is switched off — the facts have to be collected while it
	// is still awake, and kept somewhere that stays awake.
	LAN []resource.LANIface `json:"lan,omitempty"`

	// Services are listening ports found on this node.
	Services []resource.Service `json:"services,omitempty"`

	// SSH are this node's public SSH keys: its host keys, so peers can
	// recognise it without the trust-on-first-use prompt, and its operator's
	// public key, so peers that have opted in can let it log in.
	SSH resource.SSHKeys `json:"ssh,omitzero"`

	// Shares are the resources this node offers to *the recipient of this
	// map*. The hub filters them per recipient, so a node is never told the
	// name of a share it may not use.
	Shares []resource.Advert `json:"shares,omitempty"`

	// Stats is a rough description of the hardware. Best-effort; zero
	// fields mean "not measured on that platform".
	Stats resource.Stats `json:"stats,omitzero"`

	// InboundPorts are the ports this peer may reach on the node receiving
	// this map. Nil means every port; [policy.NoPorts] means none (a peer
	// present only because this node may reach it). The hub resolves the
	// policy so the agent's packet filter never has to, and so a node is
	// never handed rules about machines it cannot see. Replies to
	// connections this node opened pass the filter regardless.
	InboundPorts []policy.PortRange `json:"inbound_ports,omitempty"`

	// Groups this node belongs to, for display.
	Groups []string `json:"groups,omitempty"`

	// Sites is how this node's WebShare sites stand. Only in a node's own
	// Self entry: which sites a machine publishes, and whether the hub has
	// approved them, is nobody else's business.
	Sites []resource.SiteStatus `json:"sites,omitempty"`

	// Hub is true for the node running on the same machine as the hub
	// itself. Purely informational, but worth showing: that machine is the
	// one everything else depends on to find each other, so knowing which
	// one it is matters when deciding what to reboot.
	Hub bool `json:"hub,omitempty"`

	// Admin is true when the hub accepts administration signed by this node:
	// minting join codes, admitting and removing machines. Set only in a
	// node's own Self entry; who else administers the network is not
	// something peers need to know.
	Admin bool `json:"admin,omitempty"`

	// Compute is set only when this node accepts work from the recipient of
	// this map. A machine that will not run your jobs does not advertise
	// that it runs anyone's.
	Compute *resource.ComputeOffer `json:"compute,omitempty"`

	// Desktop is set only when this node shares its screen with the
	// recipient of this map, on the same principle as Compute.
	Desktop *resource.DesktopOffer `json:"desktop,omitempty"`

	LastSeen time.Time `json:"last_seen"`
	Online   bool      `json:"online"`
}

// Relay is a rendezvous and fallback path. In a single-hub deployment there is
// exactly one, running inside locnet-hub.
type Relay struct {
	ID   string `json:"id"`
	Addr string `json:"addr"` // host:port, UDP
}

// Network is the network-wide configuration every node shares.
type Network struct {
	ID string `json:"id"`
	// Name is what the operator called this network.
	Name string `json:"name"`
	// Prefix is the overlay address range, e.g. 10.99.0.0/16.
	Prefix netip.Prefix `json:"prefix"`
	// Domain is the MagicDNS-style suffix, e.g. "locnet.private".
	Domain string `json:"domain"`
	// MTU for the tunnel interface.
	MTU int `json:"mtu"`
	// Health are the alert thresholds. They are network-wide configuration
	// rather than a secret, so every node carries them and can flag a peer
	// that is running out of disk without asking the hub anything.
	Health resource.HealthRules `json:"health,omitzero"`

	// Hubs are every address a node should try when it needs the hub,
	// including any standby. It travels in the signed map so that adding a
	// spare reaches machines that joined long before the spare existed —
	// otherwise the addresses a node knows are frozen at the moment it
	// pasted its join code, which is exactly when a backup hub is least
	// likely to have existed yet.
	Hubs []string `json:"hubs,omitempty"`
}

// NetMap is one node's view of the network. Version increases every time the
// hub changes anything; a node polls with the version it last saw and the hub
// holds the request open until there is something newer.
type NetMap struct {
	Version  uint64    `json:"version"`
	IssuedAt time.Time `json:"issued_at"`
	Network  Network   `json:"network"`
	Self     Node      `json:"self"`
	Peers    []Node    `json:"peers"`
	Relays   []Relay   `json:"relays"`
}

// PeerByWGKey finds a peer by its WireGuard public key.
func (m *NetMap) PeerByWGKey(k key.WGPublic) (Node, bool) {
	for _, p := range m.Peers {
		if p.WGKey == k {
			return p, true
		}
	}
	return Node{}, false
}

// Signed is a NetMap plus the hub's signature over it.
//
// The payload travels as opaque bytes rather than a nested object so that the
// exact bytes that were signed are the exact bytes that get verified. Re-
// encoding a decoded struct to check a signature is a classic way to produce a
// verifier that disagrees with the signer over field ordering or numeric
// formatting.
type Signed struct {
	Payload []byte            `json:"payload"`
	Sig     []byte            `json:"sig"`
	HubKey  key.MachinePublic `json:"hub_key"`
}

// Sign serialises m and signs it with the hub's identity key.
func Sign(m *NetMap, hubKey key.MachinePrivate) (*Signed, error) {
	payload, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("netmap: marshal: %w", err)
	}
	return &Signed{
		Payload: payload,
		Sig:     hubKey.Sign(payload),
		HubKey:  hubKey.Public(),
	}, nil
}

// Open verifies s against a pinned hub fingerprint and returns the map.
//
// Both checks matter and neither is redundant. The fingerprint check says
// "this is the hub my join code named"; the signature check says "and it
// really signed this". Skipping the first would let any hub sign a map for us.
func (s *Signed) Open(wantFingerprint [16]byte) (*NetMap, error) {
	if s.HubKey.IsZero() {
		return nil, fmt.Errorf("netmap: response carried no hub key")
	}
	if got := s.HubKey.Fingerprint(); got != wantFingerprint {
		return nil, fmt.Errorf("netmap: hub identity mismatch — expected fingerprint %x, got %x. "+
			"Either you are talking to a different hub than your join code named, or the hub's identity key was regenerated", wantFingerprint, got)
	}
	if !s.HubKey.Verify(s.Payload, s.Sig) {
		return nil, fmt.Errorf("netmap: signature does not verify")
	}
	var m NetMap
	if err := json.Unmarshal(s.Payload, &m); err != nil {
		return nil, fmt.Errorf("netmap: unmarshal: %w", err)
	}
	return &m, nil
}
