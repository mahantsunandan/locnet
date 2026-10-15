// Package resource is what a machine offers to the rest of the network:
// folders, services, ports, and a description of the hardware itself.
//
// The access rules live here too, and one decision shapes the whole design:
// a share is enforced by the machine that owns it, never by the hub. The hub
// distributes what each node has declared, but a node that is told "peer X may
// read /data" is the one that checks it. A compromised hub can therefore
// mislead you about what is on offer, but it cannot grant itself access to a
// folder on your machine.
//
// The authenticator is the overlay source address. That is not the usual weak
// "trust the source IP" — inside the tunnel, WireGuard's allowed-IP check
// means a packet from 10.99.0.3 provably came from the holder of that node's
// private key. Nothing else can forge it.
package resource

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"time"
)

// Kind is what sort of thing is being shared.
type Kind string

const (
	// KindFiles is a directory served over the overlay.
	KindFiles Kind = "files"
	// KindPort forwards an overlay port to a local one, which is how a
	// service bound to 127.0.0.1 is published without rebinding it.
	KindPort Kind = "port"
)

// Valid reports whether k is a kind this build understands.
func (k Kind) Valid() bool { return k == KindFiles || k == KindPort }

// Share is one offered resource.
type Share struct {
	// Name identifies the share within its node, e.g. "data".
	Name string `json:"name"`
	Kind Kind   `json:"kind"`

	// Target is the local path for a files share, or the local "host:port"
	// (or bare port) for a port share.
	Target string `json:"target"`

	// Port is the overlay port a port share listens on. Ignored for files,
	// which are all served by the one share server.
	Port uint16 `json:"port,omitempty"`

	// ReadOnly applies to files shares. Uploads are refused when set.
	ReadOnly bool `json:"read_only"`

	// Allow lists the peer names that may use this share. The single entry
	// "*" means every member of the network. An empty list denies everyone,
	// which is deliberate: a share created without an explicit audience
	// should do nothing until someone says who it is for.
	Allow []string `json:"allow,omitempty"`

	// Description is free text shown in the console.
	Description string `json:"description,omitempty"`

	// Web asks the hub to publish this port share to the internet over
	// HTTPS, as <Web>.<the hub's domain>. It only asks: nothing is public
	// until an administrator approves the name on the hub. See WebShare in
	// docs/OPERATIONS.md.
	Web string `json:"web,omitempty"`
}

// SiteStatus is how one of this machine's WebShare sites stands, as the hub
// tells it in the machine's own netmap entry.
type SiteStatus struct {
	Name  string `json:"name"`
	URL   string `json:"url,omitempty"`
	State string `json:"state"`
	// Live is true when the site answers the internet right now.
	Live bool `json:"live,omitempty"`
}

// ValidSiteName reports whether name works as the first label of a public
// host name: lower-case letters, digits and inner hyphens, at most 63.
func ValidSiteName(name string) error {
	if name == "" || len(name) > 63 {
		return fmt.Errorf("a site name needs 1 to 63 characters")
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-' && i > 0 && i < len(name)-1:
		default:
			return fmt.Errorf("site name %q may use only lower-case letters, digits and inner hyphens", name)
		}
	}
	return nil
}

// Validate checks a share before it is accepted.
func (s *Share) Validate() error {
	if s.Name == "" {
		return fmt.Errorf("a share needs a name")
	}
	if strings.ContainsAny(s.Name, `/\:`) {
		return fmt.Errorf("share name %q cannot contain / \\ or :", s.Name)
	}
	if !s.Kind.Valid() {
		return fmt.Errorf("unknown share kind %q (use %q or %q)", s.Kind, KindFiles, KindPort)
	}
	if s.Target == "" {
		return fmt.Errorf("share %q has no target", s.Name)
	}

	switch s.Kind {
	case KindFiles:
		if !filepath.IsAbs(s.Target) {
			return fmt.Errorf("files share %q needs an absolute path, got %q", s.Name, s.Target)
		}
	case KindPort:
		if s.Port == 0 {
			return fmt.Errorf("port share %q needs an overlay port", s.Name)
		}
		if s.Port < 1024 {
			return fmt.Errorf("port share %q: overlay port %d is privileged; pick one above 1024", s.Name, s.Port)
		}
	}
	if s.Web != "" {
		if s.Kind != KindPort {
			return fmt.Errorf("share %q: only a port share can be published to the web", s.Name)
		}
		if err := ValidSiteName(s.Web); err != nil {
			return err
		}
	}
	return nil
}

// AllowsPeer reports whether the named peer may use this share.
func (s *Share) AllowsPeer(peerName string) bool {
	for _, a := range s.Allow {
		if a == "*" || a == peerName {
			return true
		}
	}
	return false
}

// AllowText renders the audience for display.
func (s *Share) AllowText() string {
	switch {
	case len(s.Allow) == 0:
		return "nobody"
	case len(s.Allow) == 1 && s.Allow[0] == "*":
		return "everyone"
	default:
		return strings.Join(s.Allow, ", ")
	}
}

// Advert is the public description of a share: what peers are told exists,
// without the local path, which is nobody else's business.
type Advert struct {
	Name        string `json:"name"`
	Kind        Kind   `json:"kind"`
	Port        uint16 `json:"port,omitempty"`
	ReadOnly    bool   `json:"read_only"`
	Description string `json:"description,omitempty"`
}

// Advertise renders the shares visible to one peer. A peer is never told
// about a share it may not use — an access list that leaks the names of the
// things it is protecting is only half a control.
func Advertise(shares []Share, peerName string) []Advert {
	out := make([]Advert, 0, len(shares))
	for i := range shares {
		s := &shares[i]
		if !s.AllowsPeer(peerName) {
			continue
		}
		out = append(out, Advert{
			Name:        s.Name,
			Kind:        s.Kind,
			Port:        s.Port,
			ReadOnly:    s.ReadOnly,
			Description: s.Description,
		})
	}
	return out
}

// Service is a listening port found on a node, as opposed to something the
// operator deliberately shared.
type Service struct {
	Name string `json:"name"` // "ssh", "rdp", "vnc", …
	Port uint16 `json:"port"`
	// Verified means a *peer* connected to this port, not merely that the
	// machine reached it on its own overlay address.
	//
	// The distinction is the difference between a true entry and a false one.
	// A machine dialling itself does not cross its own firewall — on Windows,
	// explicitly so — which is how a node with sshd running behind a closed
	// firewall told the whole network it offered SSH. Every peer that believed
	// it timed out.
	//
	// Unverified is not the same as broken: it is what every service looks
	// like before anyone has had occasion to check, including on a healthy
	// machine that is briefly alone on the network. Callers should show the
	// difference rather than hide it, and must not drop unverified services —
	// a transient failure to ask is not evidence of absence.
	Verified bool `json:"verified,omitempty"`
	// Problem is set when the port answers but the service behind it will not
	// let anyone in — an RDP server that hangs up before login, say. It says
	// what is wrong and how to fix it. Empty means the protocol answered the
	// way a working server does, or LocNet does not check this protocol.
	Problem string `json:"problem,omitempty"`
}

// Stats is a rough description of a machine, for deciding where to run
// something or noticing that a disk is filling up.
//
// Every field is best-effort. A zero means "not measured on this platform"
// rather than "zero", and callers must treat it that way.
type Stats struct {
	CPUs        int     `json:"cpus,omitempty"`
	LoadPercent float64 `json:"load_percent,omitempty"`
	MemTotalMB  uint64  `json:"mem_total_mb,omitempty"`
	MemFreeMB   uint64  `json:"mem_free_mb,omitempty"`
	DiskTotalGB uint64  `json:"disk_total_gb,omitempty"`
	DiskFreeGB  uint64  `json:"disk_free_gb,omitempty"`
	UptimeHours uint64  `json:"uptime_hours,omitempty"`

	// GPUs found on the machine. Empty means none were detected, which
	// includes the case where the vendor tools are not installed.
	GPUs []GPU `json:"gpus,omitempty"`
}

// GPUMemFreeMB is the free memory on the largest card, which is what decides
// whether a model fits. Summing across cards would be wrong: two 8 GB cards
// do not hold a 12 GB model without work that most software will not do for
// you.
func (s Stats) GPUMemFreeMB() uint64 {
	var best uint64
	for _, g := range s.GPUs {
		if f := g.Free(); f > best {
			best = f
		}
	}
	return best
}

// GPUSummary is a short human description, e.g. "2× NVIDIA RTX 4090".
func (s Stats) GPUSummary() string {
	if len(s.GPUs) == 0 {
		return ""
	}
	name := s.GPUs[0].Name
	if len(s.GPUs) > 1 {
		return fmt.Sprintf("%d× %s", len(s.GPUs), name)
	}
	return name
}

// MemUsedPercent returns memory pressure, or -1 when it was not measured.
func (s Stats) MemUsedPercent() float64 {
	if s.MemTotalMB == 0 {
		return -1
	}
	return float64(s.MemTotalMB-s.MemFreeMB) / float64(s.MemTotalMB) * 100
}

// DiskUsedPercent returns disk pressure, or -1 when it was not measured.
func (s Stats) DiskUsedPercent() float64 {
	if s.DiskTotalGB == 0 {
		return -1
	}
	return float64(s.DiskTotalGB-s.DiskFreeGB) / float64(s.DiskTotalGB) * 100
}

// FileEntry is one row of a directory listing from a files share.
type FileEntry struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	IsDir   bool      `json:"is_dir"`
	ModTime time.Time `json:"mod_time"`
}

// PeerLookup resolves an overlay address to a peer name. The share server
// uses it to turn a connection into an identity.
type PeerLookup func(netip.Addr) (name string, ok bool)
