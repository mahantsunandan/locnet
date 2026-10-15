package console

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mahantsunandan/locnet/internal/launch"
	"github.com/mahantsunandan/locnet/internal/node"
	"github.com/mahantsunandan/locnet/internal/resource"
	"github.com/mahantsunandan/locnet/internal/shareclient"
	"github.com/mahantsunandan/locnet/internal/wake"
)

// Version is the CLI's version, set by its main package, so the page can say
// which build it belongs to.
var Version string

// The console's control of this machine and, where the hub allows it, of the
// network. Every one of these is a call the CLI can already make; the page is
// only another way of making it. Nothing here decides anything the daemon or
// the hub would not decide for the CLI.

// handleInfo describes the console itself: who it runs as and where downloads
// land, which the page needs to fill in sensible defaults.
func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	host, _ := os.Hostname()
	writeJSON(w, map[string]string{
		"user":      launch.InvokingUser(),
		"downloads": s.download,
		"version":   Version,
		"os":        runtime.GOOS,
		"hostname":  host,
	})
}

// handleTunnel brings the tunnel up or down.
func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Up bool `json:"up"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	path := "/down"
	if req.Up {
		path = "/up"
	}
	var st node.Status
	if err := s.daemon.Post(path, struct{}{}, &st); err != nil {
		writeErr(w, http.StatusBadGateway, "%v", err)
		return
	}
	writeJSON(w, st)
}

// handleHosts turns the hosts-file block on or off.
func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	if err := s.daemon.Post("/hosts", req, nil); err != nil {
		writeErr(w, http.StatusBadGateway, "%v", err)
		return
	}
	writeJSON(w, req)
}

// handleShareAdd publishes a folder or a port.
func (s *Server) handleShareAdd(w http.ResponseWriter, r *http.Request) {
	var sh resource.Share
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&sh); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed share")
		return
	}
	sh.Name = strings.TrimSpace(sh.Name)
	sh.Target = strings.TrimSpace(sh.Target)
	if sh.Kind == resource.KindFiles {
		if strings.HasPrefix(sh.Target, "~") {
			if home, err := os.UserHomeDir(); err == nil {
				sh.Target = home + sh.Target[1:]
			}
		}
		if !filepath.IsAbs(sh.Target) {
			writeErr(w, http.StatusBadRequest, "give the folder as a full path, like /home/you/Projects")
			return
		}
		sh.Target = filepath.Clean(sh.Target)
	}
	var shares []resource.Share
	if err := s.daemon.Post("/share/add", sh, &shares); err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	writeJSON(w, shares)
}

// handleShareRemove stops publishing a share.
func (s *Server) handleShareRemove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		writeErr(w, http.StatusBadRequest, "which share?")
		return
	}
	var shares []resource.Share
	if err := s.daemon.Post("/share/remove", req, &shares); err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	writeJSON(w, shares)
}

// handleCompute replaces this machine's compute offer.
//
// An offer switched on from the page runs jobs as the person running the
// page unless told otherwise — the same account `locnet compute enable` would
// suggest, and never root by accident: the daemon still refuses that without
// the explicit flag.
func (s *Server) handleCompute(w http.ResponseWriter, r *http.Request) {
	var cfg resource.ComputeConfig
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&cfg); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	if cfg.Enabled && cfg.RunAs == "" && !cfg.AllowPrivileged && runtime.GOOS != "windows" {
		cfg.RunAs = launch.InvokingUser()
	}
	if err := s.daemon.Post("/compute", cfg, nil); err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	writeJSON(w, cfg)
}

// handleDesktopStop withdraws this machine's screen from LocNet's own
// screen-sharing protocol. There is no viewer for that protocol any more, so
// an old setting is only an offer nobody can take up — and, worse, one made by
// name to machines that may no longer exist.
func (s *Server) handleDesktopStop(w http.ResponseWriter, r *http.Request) {
	if err := s.daemon.Post("/desktop", resource.DesktopConfig{}, nil); err != nil {
		writeErr(w, http.StatusBadGateway, "%v", err)
		return
	}
	writeJSON(w, map[string]bool{"stopped": true})
}

// handleManage forwards a network-administration request to the daemon, which
// signs it with this machine's key. Whether this machine may is the hub's call.
func (s *Server) handleManage(w http.ResponseWriter, r *http.Request) {
	op := r.PathValue("op")
	switch op {
	case "nodes", "invite", "invites", "revoke", "remove", "approve", "audit", "access", "webshare":
	default:
		writeErr(w, http.StatusNotFound, "unknown request")
		return
	}
	var in json.RawMessage
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&in); err != nil && err != io.EOF {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	var out json.RawMessage
	if err := s.daemon.Post("/manage/"+op, in, &out); err != nil {
		writeErr(w, http.StatusBadGateway, "%v", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

// handleQueueJob returns one job with its output, for the queue's output view.
func (s *Server) handleQueueJob(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "which job?")
		return
	}
	var jobs []json.RawMessage
	if err := s.daemon.Post("/queue/list", map[string]any{"id": id}, &jobs); err != nil {
		writeErr(w, http.StatusBadGateway, "%v", err)
		return
	}
	if len(jobs) == 0 {
		writeErr(w, http.StatusNotFound, "no job called %q", id)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jobs[0])
}

// handleWake turns a switched-off machine on, by asking something on its
// network to send the magic packet — this machine if it can, a peer if not.
func (s *Server) handleWake(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Peer string `json:"peer"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Peer == "" {
		writeErr(w, http.StatusBadRequest, "which machine?")
		return
	}
	var st node.Status
	if err := s.daemon.Get("/status", &st); err != nil {
		writeErr(w, http.StatusBadGateway, "%v", err)
		return
	}
	var target *node.PeerStatus
	for i := range st.Peers {
		if st.Peers[i].Name == req.Peer {
			target = &st.Peers[i]
		}
	}
	if target == nil {
		writeErr(w, http.StatusNotFound, "there is no machine called %q", req.Peer)
		return
	}
	if target.Online {
		writeJSON(w, map[string]string{"message": target.Name + " is already on."})
		return
	}
	macs := resource.MACs(target.LAN)
	if len(macs) == 0 {
		writeErr(w, http.StatusBadRequest, "%s has never reported a network card address, so there is "+
			"nothing to send a wake-up to. Start it by hand once and it can be woken from then on.", target.Name)
		return
	}

	candidates := map[string][]resource.LANIface{}
	for _, p := range st.Peers {
		if p.Online && p.Name != target.Name && len(p.LAN) > 0 {
			candidates[p.Name] = p.LAN
		}
	}
	who, ok := wake.Choose(target.LAN, st.LAN, candidates)
	if !ok {
		writeErr(w, http.StatusBadRequest, "nothing that is switched on shares a network with %s. "+
			"A wake-up packet does not cross a router, so a machine on %s's own network has to send it.",
			target.Name, target.Name)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	var sent int
	var err error
	via := "this machine"
	if who.Name == "" {
		sent, err = wake.Send(macs, st.LAN)
	} else {
		via = who.Name
		var ip netip.Addr
		for _, p := range st.Peers {
			if p.Name == who.Name {
				ip = p.IP
			}
		}
		sent, err = shareclient.New(ip).Wake(ctx, macs)
	}
	if err != nil {
		writeErr(w, http.StatusBadGateway, "%s could not send it: %v", via, err)
		return
	}
	writeJSON(w, map[string]string{"message": fmt.Sprintf(
		"Sent %d wake-up packet(s) for %s from %s (%s). It should appear within a minute or two, "+
			"if Wake-on-LAN is enabled in its firmware.", sent, target.Name, via, who.Reason)})
}

// ------------------------------------------------------------- diagnosis

// check is one line of the diagnosis.
type check struct {
	Level  string `json:"level"` // "ok", "warn" or "bad"
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
}

// reach is whether one peer answered through the tunnel.
type reach struct {
	Name  string  `json:"name"`
	IP    string  `json:"ip"`
	Path  string  `json:"path"`
	OK    bool    `json:"ok"`
	Ms    float64 `json:"ms,omitempty"`
	Error string  `json:"error,omitempty"`
}

// inbound is a peer's view of this machine's own ports.
type inbound struct {
	From  string     `json:"from"`
	Ports []portSeen `json:"ports,omitempty"`
	Error string     `json:"error,omitempty"`
}

type portSeen struct {
	Port uint16 `json:"port"`
	Name string `json:"name"`
	Open bool   `json:"open"`
}

// handleDiagnose is `locnet doctor` for the page: what this machine believes,
// then what actually happens when traffic is sent — because the two disagree
// in exactly the cases worth diagnosing.
func (s *Server) handleDiagnose(w http.ResponseWriter, r *http.Request) {
	var st node.Status
	if err := s.daemon.Get("/status", &st); err != nil {
		writeJSON(w, map[string]any{"checks": []check{{
			Level: "bad", Title: "locnetd is not answering",
			Detail: "Start it: sudo systemctl start locnetd",
		}}})
		return
	}

	var checks []check
	add := func(level, title, detail string) {
		checks = append(checks, check{Level: level, Title: title, Detail: detail})
	}

	switch {
	case !st.Registered:
		add("bad", "This machine has not joined a network", "Get a join code from an administrator, then: sudo locnet join <code>")
	case !st.Running:
		add("bad", "The tunnel is down", "Other machines see this one as offline. Bring it up with the switch above, or: sudo locnet up")
	default:
		add("ok", fmt.Sprintf("Joined %s as %s (%s)", st.Network, st.Name, st.IP), "")
		add("ok", "Tunnel up on "+st.Interface, fmt.Sprintf("UDP port %d", st.ListenPort))
	}
	if st.Registered && st.Running {
		switch {
		case st.LastError != "":
			add("bad", "The hub is not answering", st.LastError)
		case !st.HubOK:
			add("warn", "Waiting for the hub", "Nothing has answered yet; first to try is "+st.HubAddr)
		default:
			add("ok", "Hub answering at "+st.HubAddr, "")
			if note := node.TransportNote(st.HubTransport); st.HubTransport == "http" {
				add("warn", "Control plane not encrypted", note+". Upgrade the hub: sudo bash deploy.sh --hub")
			} else if note != "" {
				add("ok", "Control plane "+note, "")
			}
		}
		if st.Observed == "" {
			add("warn", "The relay has not reported this machine's public address",
				"UDP to the hub may be blocked. The hub's port must be open for UDP as well as TCP.")
		} else {
			add("ok", "Relay sees this machine at "+st.Observed, "")
		}
	}
	for _, c := range st.Conflicts {
		add("warn", "Address conflict", c)
	}

	var peers []node.PeerStatus
	for _, p := range st.Peers {
		if p.Online && p.IP.IsValid() {
			peers = append(peers, p)
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	// Real traffic down the tunnel to every online peer, at once.
	results := make([]reach, len(peers))
	var wg sync.WaitGroup
	for i, p := range peers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := reach{Name: p.Name, IP: p.IP.String(), Path: p.Path}
			start := time.Now()
			var d net.Dialer
			dctx, dcancel := context.WithTimeout(ctx, 5*time.Second)
			c, err := d.DialContext(dctx, "tcp", netip.AddrPortFrom(p.IP, node.SharePort).String())
			dcancel()
			if err != nil {
				res.Error = err.Error()
			} else {
				c.Close()
				res.OK = true
				res.Ms = float64(time.Since(start).Microseconds()) / 1000
			}
			results[i] = res
		}()
	}

	// And one peer's view of this machine, which is the only vantage point
	// from which a firewall here shows up.
	var in *inbound
	if len(peers) > 0 && st.Running {
		wg.Add(1)
		go func() {
			defer wg.Done()
			in = s.inboundFrom(ctx, st, peers[0])
		}()
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool { return results[i].Name < results[j].Name })
	writeJSON(w, map[string]any{"checks": checks, "peers": results, "inbound": in})
}

func (s *Server) inboundFrom(ctx context.Context, st node.Status, peer node.PeerStatus) *inbound {
	seen := map[uint16]string{node.SharePort: "locnet"}
	for _, svc := range st.Services {
		if svc.Port != 0 {
			seen[svc.Port] = svc.Name
		}
	}
	ports := make([]uint16, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	if len(ports) > resource.MaxProbePorts {
		ports = ports[:resource.MaxProbePorts]
	}

	out := &inbound{From: peer.Name}
	res, err := shareclient.New(peer.IP).Probe(ctx, peer.Name, ports)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	for _, p := range ports {
		out.Ports = append(out.Ports, portSeen{Port: p, Name: seen[p], Open: res.IsOpen(p)})
	}
	return out
}
