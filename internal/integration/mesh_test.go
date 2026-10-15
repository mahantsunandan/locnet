// Package integration runs the hub, the relay and two magicsock endpoints
// against each other in one process.
//
// It stops short of creating a TUN device, which needs root and a kernel this
// test cannot assume. Everything below the tunnel — registration, netmap
// signing, relay binding, hole punching, path promotion and relayed delivery —
// is exercised for real, over real UDP sockets.
package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mahantsunandan/locnet/internal/hub"
	"github.com/mahantsunandan/locnet/internal/hubapi"
	"github.com/mahantsunandan/locnet/internal/joincode"
	"github.com/mahantsunandan/locnet/internal/key"
	"github.com/mahantsunandan/locnet/internal/magicsock"
	"github.com/mahantsunandan/locnet/internal/netmap"
	"github.com/mahantsunandan/locnet/internal/policy"
	"github.com/mahantsunandan/locnet/internal/resource"
	"golang.zx2c4.com/wireguard/conn"
)

// testHub is a running hub: API, relay and store.
type testHub struct {
	store *hub.Store
	relay *hub.Relay
	srv   *hub.Server
	addr  string // host:port serving both TCP API and UDP relay
	// plainAPI and tlsAPI count API requests by how they arrived.
	plainAPI, tlsAPI atomic.Int32
	// registers counts /register requests, however they arrived.
	registers atomic.Int32
}

// startHub runs a hub as locnet-hub does: TLS pinned to its key and plain
// HTTP on one port. The plain-HTTP requests most tests here make are what an
// agent older than 0.10.4 sends, so they double as the compatibility check.
func startHub(t *testing.T) *testHub { return startHubTLS(t, true) }

// startHubTLS with withTLS false is a hub from before 0.10.4: plain only.
func startHubTLS(t *testing.T, withTLS bool) *testHub {
	t.Helper()

	// Claim a TCP port, then bind the same number for UDP. TCP and UDP port
	// spaces are independent, so this is the simplest way to get one number
	// that works for both — which is what a real hub advertises.
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := tcpLn.Addr().String()

	store, err := hub.Open(filepath.Join(t.TempDir(), "hub.json"), "testnet", hub.DefaultPrefix)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	relay := hub.NewRelay(store, t.Logf)
	srv := hub.NewServer(store, relay, []string{addr}, t.Logf)

	h := &testHub{store: store, relay: relay, srv: srv, addr: addr}
	var ln net.Listener = tcpLn
	if withTLS {
		if ln, err = srv.TLSListener(tcpLn); err != nil {
			t.Fatal(err)
		}
	}
	api := srv.Handler()
	counted := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, hubapi.APIVersion) {
			if r.TLS != nil {
				h.tlsAPI.Add(1)
			} else {
				h.plainAPI.Add(1)
			}
			if r.URL.Path == hubapi.APIVersion+"/register" {
				h.registers.Add(1)
			}
		}
		api.ServeHTTP(w, r)
	})

	ctx, cancel := context.WithCancel(context.Background())
	httpSrv := &http.Server{Handler: counted}
	go httpSrv.Serve(ln)
	go func() {
		if err := relay.ListenAndServe(ctx, addr); err != nil {
			t.Logf("relay stopped: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		httpSrv.Close()
	})

	waitFor(t, 3*time.Second, "hub to answer", func() bool {
		resp, err := http.Get("http://" + addr + "/healthz")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})
	return h
}

// invite mints a join token and returns it in the form register expects.
func (h *testHub) invite(t *testing.T) string {
	t.Helper()
	tok, err := h.store.CreateToken("test", 10, time.Hour)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	return tok.Token
}

// testNode is a registered node with its keys and a magicsock, but no tunnel.
type testNode struct {
	name     string
	id       string
	ip       netip.Addr
	machine  key.MachinePrivate
	wgPriv   key.WGPrivate
	discoKey key.DiscoPrivate
	ms       *magicsock.Conn
	// recv is the ReceiveFunc WireGuard would normally own, and wg is where
	// the pump goroutine delivers whatever it hands back.
	recv conn.ReceiveFunc
	wg   chan []byte
	hub  *testHub
}

func registerNode(t *testing.T, h *testHub, hostname string) *testNode {
	t.Helper()

	machine, _, err := key.NewMachine()
	if err != nil {
		t.Fatal(err)
	}
	wgPriv, wgPub, err := key.NewWG()
	if err != nil {
		t.Fatal(err)
	}
	discoPriv, discoPub, err := key.NewDisco()
	if err != nil {
		t.Fatal(err)
	}

	req := hubapi.RegisterRequest{
		Token:      h.invite(t),
		Hostname:   hostname,
		OS:         "linux",
		MachineKey: machine.Public(),
		WGKey:      wgPub,
		DiscoKey:   discoPub,
	}
	var resp hubapi.RegisterResponse
	postJSON(t, "http://"+h.addr+hubapi.APIVersion+"/register", req, &resp, nil)

	if resp.NodeID == "" || !resp.IP.IsValid() {
		t.Fatalf("registration returned nothing useful: %+v", resp)
	}
	return &testNode{
		name: resp.Name, id: resp.NodeID, ip: resp.IP,
		machine: machine, wgPriv: wgPriv, discoKey: discoPriv, hub: h,
	}
}

// openSocket starts the node's magicsock and points it at the relay.
func (n *testNode) openSocket(t *testing.T) {
	t.Helper()
	n.ms = magicsock.New(magicsock.Options{
		NodeID:     n.id,
		MachineKey: n.machine,
		WGKey:      n.wgPriv.Public(),
		DiscoKey:   n.discoKey,
		Logf:       func(f string, a ...any) { t.Logf(n.name+": "+f, a...) },
	})
	fns, port, err := n.ms.Open(0)
	if err != nil {
		t.Fatalf("%s: open socket: %v", n.name, err)
	}
	if len(fns) != 1 {
		t.Fatalf("%s: Open returned %d receive functions, want 1", n.name, len(fns))
	}
	n.recv = fns[0]
	n.wg = make(chan []byte, 8)
	t.Logf("%s bound to udp/%d", n.name, port)
	t.Cleanup(func() { n.ms.Close() })

	// Nothing in magicsock runs on its own: discovery packets are processed
	// inside the receive path, which WireGuard normally drives in a tight
	// loop. Without a pump, probes are sent but replies are never read, and
	// no path is ever discovered. This goroutine is that loop.
	go n.pump(t)

	relayAddr, err := netip.ParseAddrPort(n.hub.addr)
	if err != nil {
		t.Fatal(err)
	}
	n.ms.SetRelay(relayAddr)
}

// pump drives the receive function the way wireguard-go's device would.
func (n *testNode) pump(t *testing.T) {
	bufs := [][]byte{make([]byte, 2048)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	for {
		count, err := n.recv(bufs, sizes, eps)
		if err != nil {
			return // socket closed at the end of the test
		}
		for i := 0; i < count; i++ {
			pkt := append([]byte(nil), bufs[i][:sizes[i]]...)
			select {
			case n.wg <- pkt:
			default: // nobody is reading; a dropped packet is fine here
			}
		}
	}
}

// fetchNetMap does one authenticated netmap poll and verifies the signature.
func (n *testNode) fetchNetMap(t *testing.T, since uint64) *netmap.NetMap {
	t.Helper()
	url := fmt.Sprintf("http://%s%s/netmap?since=%d", n.hub.addr, hubapi.APIVersion, since)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	hubapi.SignRequest(req, n.id, n.machine, nil)

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("%s: netmap poll: %v", n.name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("%s: netmap poll returned %s", n.name, resp.Status)
	}
	var out hubapi.NetMapResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !out.Changed || out.NetMap == nil {
		return nil
	}
	nm, err := out.NetMap.Open(n.hub.store.HubKey().Public().Fingerprint())
	if err != nil {
		t.Fatalf("%s: netmap does not verify: %v", n.name, err)
	}
	return nm
}

// TestRegistrationAndNetMap covers the control plane: two machines join, each
// sees the other, and both maps carry a valid hub signature.
func TestRegistrationAndNetMap(t *testing.T) {
	h := startHub(t)
	a := registerNode(t, h, "alpha")
	b := registerNode(t, h, "beta")

	if a.ip == b.ip {
		t.Fatalf("both nodes got the same address %s", a.ip)
	}
	if !h.store.Network().Prefix.Contains(a.ip) {
		t.Fatalf("address %s is outside the network prefix %s", a.ip, h.store.Network().Prefix)
	}

	nm := a.fetchNetMap(t, 0)
	if nm == nil {
		t.Fatal("alpha got no netmap")
	}
	if nm.Self.Name != "alpha" {
		t.Errorf("Self.Name = %q, want alpha", nm.Self.Name)
	}
	if len(nm.Peers) != 1 || nm.Peers[0].Name != "beta" {
		t.Fatalf("alpha's peers = %+v, want just beta", nm.Peers)
	}
	if nm.Peers[0].WGKey != b.wgPriv.Public() {
		t.Error("beta's WireGuard key in the netmap does not match what beta registered")
	}
	if len(nm.Relays) != 1 || nm.Relays[0].Addr != h.addr {
		t.Errorf("netmap relays = %+v, want one entry for %s", nm.Relays, h.addr)
	}
}

// TestNetMapRejectsWrongHub is the check that makes a join code safe to send
// over an untrusted channel: a map signed by a different hub must not verify
// against the pinned fingerprint.
func TestNetMapRejectsWrongHub(t *testing.T) {
	h := startHub(t)
	a := registerNode(t, h, "alpha")

	nm := a.fetchNetMap(t, 0)
	if nm == nil {
		t.Fatal("no netmap")
	}

	// Re-sign the same map with an unrelated key, as an impostor hub would.
	impostor, _, err := key.NewMachine()
	if err != nil {
		t.Fatal(err)
	}
	forged, err := netmap.Sign(nm, impostor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := forged.Open(h.store.HubKey().Public().Fingerprint()); err == nil {
		t.Fatal("a netmap signed by the wrong hub was accepted")
	} else if !strings.Contains(err.Error(), "fingerprint") {
		t.Errorf("expected a fingerprint mismatch, got: %v", err)
	}

	// And a map from the right hub with a tampered payload must fail too.
	good, err := netmap.Sign(nm, h.store.HubKey())
	if err != nil {
		t.Fatal(err)
	}
	good.Payload = append(good.Payload, ' ')
	if _, err := good.Open(h.store.HubKey().Public().Fingerprint()); err == nil {
		t.Fatal("a tampered netmap was accepted")
	}
}

// TestDirectPathIsFound is the NAT-traversal path. Both sockets are on
// loopback, so a direct path exists; the point is that the probe machinery
// finds it and promotes the peer off the relay.
func TestDirectPathIsFound(t *testing.T) {
	h := startHub(t)
	a := registerNode(t, h, "alpha")
	b := registerNode(t, h, "beta")
	a.openSocket(t)
	b.openSocket(t)

	// The relay's bind reply is how a node learns its own public address.
	waitFor(t, 10*time.Second, "both nodes to learn their address from the relay", func() bool {
		return a.ms.Observed().IsValid() && b.ms.Observed().IsValid()
	})
	t.Logf("alpha observed at %s, beta at %s", a.ms.Observed(), b.ms.Observed())

	// Feed each side the other's address, as a real netmap would.
	a.ms.SetPeers([]magicsock.PeerConfig{{
		NodeID: b.name, WGKey: b.wgPriv.Public(), DiscoKey: b.discoKey.Public(),
		Endpoints: []netip.AddrPort{b.ms.Observed()},
	}})
	b.ms.SetPeers([]magicsock.PeerConfig{{
		NodeID: a.name, WGKey: a.wgPriv.Public(), DiscoKey: a.discoKey.Public(),
		Endpoints: []netip.AddrPort{a.ms.Observed()},
	}})

	waitFor(t, 15*time.Second, "a direct path in both directions", func() bool {
		return pathTo(a, b.wgPriv.Public()) == "direct" && pathTo(b, a.wgPriv.Public()) == "direct"
	})

	for _, st := range a.ms.Status() {
		t.Logf("alpha -> %s: %s via %s (%v)", st.NodeID, st.Path, st.Addr, st.Latency)
		if st.Latency <= 0 {
			t.Errorf("direct path to %s has no measured latency", st.NodeID)
		}
	}
}

// TestRelayCarriesTraffic checks the fallback. With no candidate addresses,
// no direct path can form, and everything must still get through.
func TestRelayCarriesTraffic(t *testing.T) {
	h := startHub(t)
	a := registerNode(t, h, "alpha")
	b := registerNode(t, h, "beta")
	a.openSocket(t)
	b.openSocket(t)

	waitFor(t, 10*time.Second, "both nodes to bind to the relay", func() bool {
		return a.ms.Observed().IsValid() && b.ms.Observed().IsValid()
	})

	// No Endpoints: the only path is through the hub.
	a.ms.SetPeers([]magicsock.PeerConfig{{
		NodeID: b.name, WGKey: b.wgPriv.Public(), DiscoKey: b.discoKey.Public(),
	}})
	b.ms.SetPeers([]magicsock.PeerConfig{{
		NodeID: a.name, WGKey: a.wgPriv.Public(), DiscoKey: a.discoKey.Public(),
	}})

	// A WireGuard handshake-initiation packet begins with 0x01: the exact
	// shape magicsock must pass through untouched rather than mistake for a
	// disco message.
	payload := append([]byte{0x01, 0x00, 0x00, 0x00}, []byte("hello over the relay")...)

	ep, err := a.ms.ParseEndpoint(base64.StdEncoding.EncodeToString(keyBytes(b.wgPriv.Public())))
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}

	deadline := time.After(15 * time.Second)
	tick := time.NewTicker(300 * time.Millisecond)
	defer tick.Stop()
	for {
		if err := a.ms.Send([][]byte{payload}, ep); err != nil {
			t.Logf("send (will retry): %v", err)
		}
		select {
		case got := <-b.wg:
			if string(got) != string(payload) {
				// Probes also cross the relay; keep waiting for ours.
				t.Logf("beta got an unrelated %d-byte packet, still waiting", len(got))
				continue
			}
			if p := pathTo(a, b.wgPriv.Public()); p == "direct" {
				t.Errorf("path is %q, but no direct candidate was ever offered", p)
			}
			t.Logf("payload crossed the relay; path is %q", pathTo(a, b.wgPriv.Public()))
			return
		case <-tick.C:
		case <-deadline:
			t.Fatalf("nothing arrived through the relay in 15s (relay has %d binding(s))", h.relay.Bindings())
		}
	}
}

// TestJoinCodeRoundTripThroughHub checks that the code the hub prints is the
// code a node can actually parse, including the pinned fingerprint.
func TestJoinCodeRoundTripThroughHub(t *testing.T) {
	h := startHub(t)
	tok := h.invite(t)

	code, err := h.srv.JoinCodeFor(tok)
	if err != nil {
		t.Fatalf("JoinCodeFor: %v", err)
	}
	parsed, err := joincode.Parse(code)
	if err != nil {
		t.Fatalf("the hub produced a code the client cannot parse: %v", err)
	}
	if parsed.Primary() != h.addr {
		t.Errorf("code points at %q, hub is at %q", parsed.Primary(), h.addr)
	}
	if parsed.HubFingerprint != h.store.HubKey().Public().Fingerprint() {
		t.Error("code carries the wrong hub fingerprint")
	}
	if base64.StdEncoding.EncodeToString(parsed.Token[:]) != tok {
		t.Error("code carries the wrong token")
	}
}

// TestSpentTokenIsRefused covers the limit on a join code's uses.
func TestSpentTokenIsRefused(t *testing.T) {
	h := startHub(t)
	tok, err := h.store.CreateToken("single use", 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	newReg := func(host string) hubapi.RegisterRequest {
		machine, _, _ := key.NewMachine()
		_, wgPub, _ := key.NewWG()
		_, discoPub, _ := key.NewDisco()
		return hubapi.RegisterRequest{
			Token: tok.Token, Hostname: host, OS: "linux",
			MachineKey: machine.Public(), WGKey: wgPub, DiscoKey: discoPub,
		}
	}

	var resp hubapi.RegisterResponse
	postJSON(t, "http://"+h.addr+hubapi.APIVersion+"/register", newReg("first"), &resp, nil)
	if resp.NodeID == "" {
		t.Fatal("first registration failed")
	}

	status := 0
	postJSON(t, "http://"+h.addr+hubapi.APIVersion+"/register", newReg("second"), nil, &status)
	if status != http.StatusForbidden {
		t.Fatalf("second use of a single-use code returned %d, want %d", status, http.StatusForbidden)
	}
}

// TestUnsignedRequestIsRefused covers the control-plane auth.
func TestUnsignedRequestIsRefused(t *testing.T) {
	h := startHub(t)
	n := registerNode(t, h, "alpha")

	url := fmt.Sprintf("http://%s%s/netmap?since=0", h.addr, hubapi.APIVersion)

	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unsigned poll returned %d, want 401", resp.StatusCode)
	}

	// A signature from the right node over the wrong path must not travel.
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	hubapi.SignRequest(req, n.id, n.machine, nil)
	req.Header.Set(hubapi.HeaderSignature, base64.StdEncoding.EncodeToString(make([]byte, 64)))
	resp2, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("poll with a bogus signature returned %d, want 401", resp2.StatusCode)
	}
}

// ------------------------------------------------------------- helpers

func pathTo(n *testNode, peer key.WGPublic) string {
	for _, st := range n.ms.Status() {
		if st.WGKey == peer {
			return st.Path
		}
	}
	return "unknown"
}

func keyBytes(k key.WGPublic) []byte { return k[:] }

func waitFor(t *testing.T, limit time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", limit, what)
}

func postJSON(t *testing.T, url string, in, out any, statusOut *int) {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(url, "application/json", strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	if statusOut != nil {
		*statusOut = resp.StatusCode
	}
	if out == nil {
		return
	}
	if resp.StatusCode != 200 && statusOut == nil {
		t.Fatalf("POST %s returned %s", url, resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatalf("decode response from %s: %v", url, err)
	}
}

// report posts a node's account of itself to the hub.
func (n *testNode) report(t *testing.T, r hubapi.ReportRequest) {
	t.Helper()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	url := "http://" + n.hub.addr + hubapi.APIVersion + "/report"
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	hubapi.SignRequest(req, n.id, n.machine, raw)

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("%s: report: %v", n.name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("%s: report returned %s", n.name, resp.Status)
	}
}

// TestSharesReachOnlyTheirAudience is the control the whole sharing feature
// rests on: a peer must not even learn the name of a share it may not use.
func TestSharesReachOnlyTheirAudience(t *testing.T) {
	h := startHub(t)
	owner := registerNode(t, h, "unit-01")
	allowed := registerNode(t, h, "workstation")
	denied := registerNode(t, h, "laptop")

	owner.report(t, hubapi.ReportRequest{
		Services: []resource.Service{{Name: "ssh", Port: 22}, {Name: "vnc", Port: 5900}},
		Stats:    resource.Stats{CPUs: 8, MemTotalMB: 16000, DiskTotalGB: 500, DiskFreeGB: 120},
		Shares: []resource.Share{
			{Name: "data", Kind: resource.KindFiles, Allow: []string{"workstation"}, ReadOnly: true},
			{Name: "everyones", Kind: resource.KindFiles, Allow: []string{"*"}},
			{Name: "nobodys", Kind: resource.KindFiles},
			{Name: "pg", Kind: resource.KindPort, Port: 15432, Allow: []string{"workstation"}},
		},
	})

	find := func(nm *netmap.NetMap, name string) netmap.Node {
		t.Helper()
		for _, p := range nm.Peers {
			if p.Name == name {
				return p
			}
		}
		t.Fatalf("%q is not in the map", name)
		return netmap.Node{}
	}

	shareNames := func(n netmap.Node) []string {
		var out []string
		for _, s := range n.Shares {
			out = append(out, s.Name)
		}
		sort.Strings(out)
		return out
	}

	seenByAllowed := find(allowed.fetchNetMap(t, 0), "unit-01")
	if got, want := shareNames(seenByAllowed), []string{"data", "everyones", "pg"}; !slicesEqual(got, want) {
		t.Errorf("workstation sees shares %v, want %v", got, want)
	}

	seenByDenied := find(denied.fetchNetMap(t, 0), "unit-01")
	if got, want := shareNames(seenByDenied), []string{"everyones"}; !slicesEqual(got, want) {
		t.Errorf("laptop sees shares %v, want %v", got, want)
	}

	// Services and stats are not access-controlled and reach everyone.
	if len(seenByDenied.Services) != 2 {
		t.Errorf("laptop sees %d services, want 2", len(seenByDenied.Services))
	}
	if seenByDenied.Stats.CPUs != 8 || seenByDenied.Stats.DiskFreeGB != 120 {
		t.Errorf("stats did not propagate: %+v", seenByDenied.Stats)
	}

	// A files share must never carry its local path off the machine.
	for _, s := range seenByAllowed.Shares {
		if s.Kind == resource.KindFiles && s.Port != 0 {
			t.Errorf("files share %q leaked a port", s.Name)
		}
	}
	raw, _ := json.Marshal(seenByAllowed)
	if strings.Contains(string(raw), "target") {
		t.Error("a share's local target reached a peer")
	}
	_ = owner
}

// TestIdleReportsDoNotChurnTheNetmap covers the filter that keeps a large
// fleet quiet: repeating the same report must not wake every long poll.
func TestIdleReportsDoNotChurnTheNetmap(t *testing.T) {
	h := startHub(t)
	n := registerNode(t, h, "unit-01")

	r := hubapi.ReportRequest{
		Services: []resource.Service{{Name: "ssh", Port: 22}},
		Stats:    resource.Stats{CPUs: 4, LoadPercent: 11, MemTotalMB: 8000, MemFreeMB: 4000, DiskTotalGB: 100, DiskFreeGB: 50},
	}
	n.report(t, r)
	settled := h.store.Version()

	// Identical, then jittered by less than the rounding buckets.
	n.report(t, r)
	r.Stats.LoadPercent = 13
	r.Stats.MemFreeMB = 3990
	n.report(t, r)
	if got := h.store.Version(); got != settled {
		t.Errorf("version moved from %d to %d on reports that changed nothing material", settled, got)
	}

	// A real change must still be noticed.
	r.Stats.LoadPercent = 85
	n.report(t, r)
	if h.store.Version() == settled {
		t.Error("version did not move when load jumped from 13%% to 85%%")
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestPolicyRemovesPeersFromTheNetmap is the strongest claim the access
// policy makes: a machine it does not connect is not merely blocked, it is
// absent — no map entry, so no WireGuard peer and no key material at all.
func TestPolicyRemovesPeersFromTheNetmap(t *testing.T) {
	h := startHub(t)
	unitA := registerNode(t, h, "unit-01")
	unitB := registerNode(t, h, "unit-02")
	ops := registerNode(t, h, "workstation")
	collector := registerNode(t, h, "collector")

	// Everything sees everything under the default policy.
	if got := len(unitA.fetchNetMap(t, 0).Peers); got != 3 {
		t.Fatalf("with the default policy unit-01 sees %d peers, want 3", got)
	}

	err := h.store.SetPolicy(&policy.Policy{
		Groups: map[string][]string{
			"field-units": {"unit-01", "unit-02"},
			"operators":   {"workstation"},
		},
		Rules: []policy.Rule{
			{Src: []string{"operators"}, Dst: []string{"field-units"}, Ports: []string{"*"}},
			{Src: []string{"collector"}, Dst: []string{"field-units"}, Ports: []string{"8421"}},
		},
	})
	if err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}

	names := func(n *netmap.NetMap) []string {
		var out []string
		for _, p := range n.Peers {
			out = append(out, p.Name)
		}
		sort.Strings(out)
		return out
	}

	// unit-01 may be reached by the operator and the collector, and must not
	// see the other field unit at all.
	unitAMap := unitA.fetchNetMap(t, 0)
	if got, want := names(unitAMap), []string{"collector", "workstation"}; !slicesEqual(got, want) {
		t.Errorf("unit-01 sees %v, want %v — unit-02 must be absent entirely", got, want)
	}
	for _, p := range unitAMap.Peers {
		if p.Name == "unit-02" {
			t.Error("unit-02's WireGuard key reached unit-01 despite the policy")
		}
	}

	if got, want := names(unitB.fetchNetMap(t, 0)), []string{"collector", "workstation"}; !slicesEqual(got, want) {
		t.Errorf("unit-02 sees %v, want %v", got, want)
	}
	if got, want := names(ops.fetchNetMap(t, 0)), []string{"unit-01", "unit-02"}; !slicesEqual(got, want) {
		t.Errorf("workstation sees %v, want %v", got, want)
	}

	// The collector is port-restricted, so its entry in a field unit's map must
	// carry the resolved range for the agent's packet filter.
	var collectorEntry *netmap.Node
	for i := range unitAMap.Peers {
		if unitAMap.Peers[i].Name == "collector" {
			collectorEntry = &unitAMap.Peers[i]
		}
	}
	if collectorEntry == nil {
		t.Fatal("the collector is missing from unit-01's map")
	}
	if len(collectorEntry.InboundPorts) != 1 || collectorEntry.InboundPorts[0].Lo != 8421 {
		t.Errorf("collector InboundPorts = %+v, want one range at 8421", collectorEntry.InboundPorts)
	}
	// The operator is unrestricted, so it carries no port list at all.
	for _, p := range unitAMap.Peers {
		if p.Name == "workstation" && len(p.InboundPorts) != 0 {
			t.Errorf("workstation carries port restrictions %+v but should be unrestricted", p.InboundPorts)
		}
	}
	_ = collector

	// The other direction: the operator may reach the field units, but no
	// rule lets a field unit reach the operator. Their entries in the
	// operator's map must say "no ports", not carry an empty list — which
	// agents read as every port, and which used to hand the field units
	// full access to the workstation.
	for _, p := range ops.fetchNetMap(t, 0).Peers {
		if len(p.InboundPorts) != 1 || p.InboundPorts[0] != policy.NoPorts {
			t.Errorf("in the operator's map %s carries %+v, want only %+v", p.Name, p.InboundPorts, policy.NoPorts)
		}
	}
}

// TestPolicyRefusesTotalIsolation stops an operator locking themselves out of
// the network they are administering.
func TestPolicyRefusesTotalIsolation(t *testing.T) {
	h := startHub(t)
	registerNode(t, h, "alpha")
	registerNode(t, h, "beta")

	err := h.store.SetPolicy(&policy.Policy{
		Rules: []policy.Rule{{Src: []string{"nobody"}, Dst: []string{"nowhere"}}},
	})
	if err == nil {
		t.Fatal("a policy that isolates every machine was accepted")
	}
	if !strings.Contains(err.Error(), "isolate") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// TestUnapprovedNodeIsInvisible covers the approval workflow.
func TestUnapprovedNodeIsInvisible(t *testing.T) {
	h := startHub(t)
	existing := registerNode(t, h, "alpha")
	if err := h.store.SetRequireApproval(true); err != nil {
		t.Fatal(err)
	}

	newcomer := registerNode(t, h, "beta")

	if got := len(existing.fetchNetMap(t, 0).Peers); got != 0 {
		t.Errorf("alpha sees %d peers; an unapproved machine must be invisible", got)
	}
	// The newcomer holds an address and can talk to the hub, but reaches
	// nobody.
	if !newcomer.ip.IsValid() {
		t.Error("the unapproved machine got no address")
	}

	var raised bool
	for _, a := range h.store.Alerts() {
		if a.Kind == "unapproved" && a.Node == "beta" {
			raised = true
		}
	}
	if !raised {
		t.Error("no alert was raised for the machine waiting on approval")
	}

	if err := h.store.ApproveNode("beta"); err != nil {
		t.Fatalf("ApproveNode: %v", err)
	}
	if got := len(existing.fetchNetMap(t, 0).Peers); got != 1 {
		t.Errorf("after approval alpha sees %d peers, want 1", got)
	}
}
