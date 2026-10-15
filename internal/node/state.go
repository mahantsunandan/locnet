// Package node is the agent that runs on every machine: it holds the keys,
// talks to the hub, and drives a WireGuard device through magicsock.
package node

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/mahantsunandan/locnet/internal/key"
	"github.com/mahantsunandan/locnet/internal/paths"
	"github.com/mahantsunandan/locnet/internal/resource"
)

// StateFile is the name of the agent's state file inside the state directory.
const StateFile = "node.json"

// State is everything the agent persists across restarts.
//
// This file contains the machine's private keys. It is written 0600 into a
// 0700 directory, and there is no reason for it ever to be copied to another
// machine — a clone would have two nodes fighting over one identity and one
// address.
type State struct {
	MachineKey key.MachinePrivate `json:"machine_key"`
	WGKey      key.WGPrivate      `json:"wg_key"`
	DiscoKey   key.DiscoPrivate   `json:"disco_key"`

	// HubAddrs are the candidate hub addresses from the join code, tried in
	// order. A hub behind NAT needs at least two — the address its
	// neighbours use and the one everyone else uses — because no single
	// address works from both sides.
	HubAddrs []string `json:"hub_addrs,omitempty"`
	// HubAddr is the pre-0.4 single address. Kept only so an existing
	// installation migrates instead of losing its network on upgrade.
	HubAddr        string `json:"hub_addr,omitempty"`
	HubFingerprint string `json:"hub_fingerprint,omitempty"` // base64 of 16 bytes
	JoinToken      string `json:"join_token,omitempty"`
	// HubTLS is set once this machine knows the hub serves TLS pinned to
	// HubFingerprint — from the join code, a verified netmap, or a pinned
	// handshake that worked. From then on bare hub addresses are never
	// spoken to in plain HTTP, so nobody on the path can switch the
	// encryption off by pretending the hub is too old for it.
	HubTLS bool `json:"hub_tls,omitempty"`

	// SSHUserKey is the operator's *public* SSH key, offered through
	// `locnet ssh-keys publish` so peers that accept it can let this person
	// log in without a password. Only ever a public key: the private half
	// stays in the home directory it was generated in and is never read here.
	SSHUserKey string `json:"ssh_user_key,omitempty"`

	// SSHAcceptFrom lists the peers whose operator keys this machine installs
	// into its own authorized_keys. Empty means none, which is the default:
	// being on the same mesh and being allowed a shell are different
	// permissions, and conflating them would mean joining a network silently
	// handed every member an account here.
	SSHAcceptFrom []string `json:"ssh_accept_from,omitempty"`

	// Assigned by the hub at registration.
	NodeID string     `json:"node_id,omitempty"`
	Name   string     `json:"name,omitempty"`
	IP     netip.Addr `json:"ip,omitempty"`

	// ListenPort is the UDP port WireGuard and discovery share. Kept stable
	// across restarts so a port forward, if there is one, keeps working.
	ListenPort uint16 `json:"listen_port,omitempty"`

	// CachedNetMap is the last signed map the hub sent. It lets a node come
	// up with working peers when the hub is unreachable at boot — which is
	// the normal case when the hub is one of the machines being rebooted.
	CachedNetMap json.RawMessage `json:"cached_netmap,omitempty"`

	// Shares are the resources this machine offers. They live here rather
	// than on the hub because the machine that owns a resource is the one
	// that enforces access to it.
	Shares []resource.Share `json:"shares,omitempty"`

	// Compute is this machine's offer to run work for peers. Off by default.
	Compute resource.ComputeConfig `json:"compute,omitzero"`

	// Desktop is this machine's offer to show its screen. Off by default,
	// and view-only even when on.
	Desktop resource.DesktopConfig `json:"desktop,omitzero"`

	// ManageHosts opts into the hosts-file block. Off by default: editing a
	// system file is not something an agent should do uninvited.
	ManageHosts bool `json:"manage_hosts"`
}

// Registered reports whether this machine has joined a network.
func (s *State) Registered() bool {
	return s.NodeID != "" && len(s.Hubs()) > 0 && s.IP.IsValid()
}

// Hubs returns the candidate hub addresses, migrating a pre-0.4 state file
// that only knew one.
func (s *State) Hubs() []string {
	if len(s.HubAddrs) > 0 {
		return s.HubAddrs
	}
	if s.HubAddr != "" {
		return []string{s.HubAddr}
	}
	return nil
}

// SetHubs replaces the candidate list and clears the legacy field so the two
// cannot drift apart.
func (s *State) SetHubs(addrs []string) {
	s.HubAddrs = append(s.HubAddrs[:0], addrs...)
	s.HubAddr = ""
}

// Fingerprint decodes the pinned hub fingerprint.
func (s *State) Fingerprint() ([16]byte, error) {
	var fp [16]byte
	raw, err := base64.StdEncoding.DecodeString(s.HubFingerprint)
	if err != nil {
		return fp, fmt.Errorf("node: bad stored hub fingerprint: %w", err)
	}
	if len(raw) != 16 {
		return fp, fmt.Errorf("node: stored hub fingerprint is %d bytes, want 16", len(raw))
	}
	return [16]byte(raw), nil
}

// SetFingerprint stores the pinned hub fingerprint.
func (s *State) SetFingerprint(fp [16]byte) {
	s.HubFingerprint = base64.StdEncoding.EncodeToString(fp[:])
}

// LoadState reads the agent state from dir, generating fresh keys the first
// time. The returned state is not yet registered with any hub.
func LoadState(dir string) (*State, error) {
	if err := paths.EnsureDir(dir); err != nil {
		return nil, fmt.Errorf("node: create %s: %w", dir, err)
	}
	path := filepath.Join(dir, StateFile)

	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		var st State
		if err := json.Unmarshal(raw, &st); err != nil {
			return nil, fmt.Errorf("node: %s is not valid state: %w", path, err)
		}
		return &st, nil
	case !os.IsNotExist(err):
		return nil, fmt.Errorf("node: read %s: %w", path, err)
	}

	st, err := newState()
	if err != nil {
		return nil, err
	}
	if err := SaveState(dir, st); err != nil {
		return nil, err
	}
	return st, nil
}

func newState() (*State, error) {
	machinePriv, _, err := key.NewMachine()
	if err != nil {
		return nil, err
	}
	wgPriv, _, err := key.NewWG()
	if err != nil {
		return nil, err
	}
	discoPriv, _, err := key.NewDisco()
	if err != nil {
		return nil, err
	}
	return &State{
		MachineKey: machinePriv,
		WGKey:      wgPriv,
		DiscoKey:   discoPriv,
		ListenPort: DefaultListenPort,
	}, nil
}

// SaveState writes state atomically.
func SaveState(dir string, st *State) error {
	if err := paths.EnsureDir(dir); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, StateFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Reset clears everything tying this machine to a network but keeps its
// identity keys, so rejoining the same hub reuses the same node record and the
// same address.
func (s *State) Reset() {
	s.HubAddrs = nil
	s.HubAddr = ""
	s.HubFingerprint = ""
	s.HubTLS = false
	s.JoinToken = ""
	s.NodeID = ""
	s.Name = ""
	s.IP = netip.Addr{}
	s.CachedNetMap = nil
}
