package resource

// Reachability is asked of a peer, about the machine doing the asking.
//
// It exists because a machine cannot answer the question about itself, and for
// a long time LocNet assumed it could. DetectServices dials the node's own
// overlay address on the theory that this is what a peer would experience. On
// Windows it is not: traffic a machine sends to one of its own addresses is
// exempt from firewall evaluation, so the probe connects to a port that every
// other machine on the network is blocked from. A node with sshd installed,
// running, and firewalled off advertised SSH to the whole network and nobody
// could get in — every local check agreeing, all of them meaningless.
//
// The only honest test is a connection that crosses the boundary being tested,
// which means somebody else has to make it.

// ProbeRequest asks a peer to connect back to the requester on these ports.
//
// Deliberately absent: an address. The peer probes whoever asked, using the
// source address of the request, which the tunnel has already authenticated.
// Letting a caller name a target would turn every node in the network into a
// port scanner pointed wherever the caller liked.
type ProbeRequest struct {
	Ports []uint16 `json:"ports"`
}

// ProbeResult is what the peer found when it connected back.
type ProbeResult struct {
	// From is the peer that did the probing — the vantage point the result is
	// true from. Reachability is a property of a pair, not of a machine, so a
	// result without its viewpoint is not a fact anybody can act on.
	//
	// Filled in by the caller from the peer it asked, not by the responder.
	From string `json:"from,omitempty"`
	// Open accepted a connection; Blocked did not.
	Open    []uint16 `json:"open,omitempty"`
	Blocked []uint16 `json:"blocked,omitempty"`
}

// IsOpen reports whether the probe reached the port.
func (r ProbeResult) IsOpen(port uint16) bool {
	for _, p := range r.Open {
		if p == port {
			return true
		}
	}
	return false
}

// MaxProbePorts caps one request. Generous next to the catalog, small enough
// that a peer cannot be talked into a long piece of work.
const MaxProbePorts = 16
