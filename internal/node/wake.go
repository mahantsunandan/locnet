package node

import (
	"encoding/json"
	"net/http"

	"github.com/mahantsunandan/locnet/internal/resource"
	"github.com/mahantsunandan/locnet/internal/wake"
)

// handleWake asks this machine to shout at a switched-off neighbour.
//
// There is no access list on this one, unlike shares, compute and the desktop.
// Those all hand out something — files, execution, a view of the screen — and
// the question is who should get it. This hands out nothing: the most a peer
// can achieve is that a computer turns on. Being a member of the network,
// which the tunnel has already proved, is the right bar for that.
func (s *shareServer) handleWake(w http.ResponseWriter, r *http.Request, peer string) {
	var req struct {
		MACs []string `json:"macs"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		http.Error(w, "malformed request", http.StatusBadRequest)
		return
	}
	if len(req.MACs) == 0 {
		http.Error(w, "no hardware address to wake", http.StatusBadRequest)
		return
	}

	sent, err := wake.Send(req.MACs, resource.LocalInterfaces())
	if err != nil {
		s.logf("wake: %s asked us to wake %v, and we could not: %v", peer, req.MACs, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	s.logf("wake: sent %d magic packet(s) for %v at %s's request", sent, req.MACs, peer)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int{"sent": sent})
}
