package node

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/mahantsunandan/locnet/internal/resource"
)

// probeDialTimeout is per port. Everything probed is a peer on the overlay,
// often over the relay, so this is looser than the local scan's budget — but
// still short enough that a full request finishes well inside a join.
const probeDialTimeout = 3 * time.Second

// handleProbe connects back to the caller and reports which ports answered.
//
// This is the other half of the reachability question. A node scanning its own
// overlay address learns only that its own kernel will talk to itself; on
// Windows that succeeds even when the host firewall blocks every peer. A
// connection from another machine is the only evidence that the path a user
// will actually take is open.
//
// The target is the caller's own address, taken from the connection rather than
// from the request body, and that is a security property rather than a
// convenience. If the body could name a host, any member of the network could
// use every other member as a port scanner — against machines outside the mesh
// entirely. As written, a node will only ever dial the peer that asked it to,
// and the tunnel has already proved who that is.
func (s *shareServer) handleProbe(w http.ResponseWriter, r *http.Request, peer string) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "cannot read source address", http.StatusBadRequest)
		return
	}
	target := ap.Addr()

	var req resource.ProbeRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if len(req.Ports) == 0 {
		http.Error(w, "no ports to probe", http.StatusBadRequest)
		return
	}
	if len(req.Ports) > resource.MaxProbePorts {
		req.Ports = req.Ports[:resource.MaxProbePorts]
	}

	// From is left empty and filled in by the caller, which already knows which
	// peer it asked. Teaching the share server its own name, purely to say it
	// back to someone who just addressed it, would be plumbing for nothing.
	var (
		mu     sync.Mutex
		result resource.ProbeResult
		wg     sync.WaitGroup
	)
	for _, port := range req.Ports {
		wg.Add(1)
		go func(port uint16) {
			defer wg.Done()
			d := net.Dialer{Timeout: probeDialTimeout}
			conn, err := d.Dial("tcp", netip.AddrPortFrom(target, port).String())

			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				result.Blocked = append(result.Blocked, port)
				return
			}
			conn.Close()
			result.Open = append(result.Open, port)
		}(port)
	}
	wg.Wait()

	sort.Slice(result.Open, func(i, j int) bool { return result.Open[i] < result.Open[j] })
	sort.Slice(result.Blocked, func(i, j int) bool { return result.Blocked[i] < result.Blocked[j] })

	line := fmt.Sprintf("share server: probed %s (%s) back on %v: open %v, blocked %v",
		peer, target, req.Ports, result.Open, result.Blocked)
	s.mu.Lock()
	if s.lastProbe == nil {
		s.lastProbe = map[string]string{}
	}
	repeat := s.lastProbe[peer] == line
	s.lastProbe[peer] = line
	s.mu.Unlock()
	if !repeat {
		s.logf("%s", line)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}
