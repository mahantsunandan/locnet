package hub

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mahantsunandan/locnet/internal/hubapi"
	"github.com/mahantsunandan/locnet/internal/key"
	"github.com/mahantsunandan/locnet/internal/netmap"
	"github.com/mahantsunandan/locnet/internal/resource"
)

// member is a registered node whose private key the test holds, so it can sign
// requests the way a real agent would.
type member struct {
	id   string
	name string
	priv key.MachinePrivate
}

type hubFixture struct {
	store   *Store
	srv     *Server
	handler http.Handler
}

func newHubFixture(t *testing.T) *hubFixture {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "hub.json"), "testnet", DefaultPrefix)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(store, NewRelay(store, nil), []string{"192.0.2.10:8420"}, nil)
	return &hubFixture{store: store, srv: srv, handler: srv.Handler()}
}

func (f *hubFixture) join(t *testing.T, name string) member {
	t.Helper()
	priv, pub, err := key.NewMachine()
	if err != nil {
		t.Fatal(err)
	}
	tok, err := f.store.CreateToken("test", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	n, err := f.store.Register(tok.Token, &Node{Name: name, MachineKey: pub})
	if err != nil {
		t.Fatal(err)
	}
	return member{id: n.ID, name: n.Name, priv: priv}
}

// call makes a signed request from m, arriving over TLS from an address that
// is not the hub machine's own, and returns the status and body.
func (f *hubFixture) call(t *testing.T, m member, path string, in any) (int, []byte) {
	t.Helper()
	raw, _ := json.Marshal(in)
	raw = hubapi.WithNonce(raw) // as every agent does
	req := httptest.NewRequest(http.MethodPost, hubapi.APIVersion+path, bytes.NewReader(raw))
	req.RemoteAddr = "198.51.100.7:40000"
	req.TLS = &tls.ConnectionState{}
	hubapi.SignRequest(req, m.id, m.priv, raw)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func TestManagingNeedsAnAdministrator(t *testing.T) {
	f := newHubFixture(t)
	alice := f.join(t, "alice")
	bob := f.join(t, "bob")

	if code, body := f.call(t, alice, "/manage/nodes", map[string]string{}); code != http.StatusForbidden {
		t.Fatalf("a machine nobody made an administrator got %d: %s", code, body)
	}

	if err := f.store.SetAdmin("admin", "alice", true); err != nil {
		t.Fatal(err)
	}
	code, body := f.call(t, alice, "/manage/nodes", map[string]string{})
	if code != http.StatusOK {
		t.Fatalf("an administrator was refused: %d %s", code, body)
	}
	var rows []NodeRow
	if err := json.Unmarshal(body, &rows); err != nil || len(rows) != 2 {
		t.Fatalf("listing = %s (%v)", body, err)
	}

	// A join code made this way must be a real one: redeemable, and pinned
	// to this hub.
	code, body = f.call(t, alice, "/manage/invite", InviteRequest{Uses: 1, TTL: "1h"})
	if code != http.StatusOK {
		t.Fatalf("invite: %d %s", code, body)
	}
	var inv InviteResponse
	if err := json.Unmarshal(body, &inv); err != nil || !strings.HasPrefix(inv.Code, "locnet") {
		t.Fatalf("invite returned %s", body)
	}
	if inv.Label != "from alice" {
		t.Errorf("an unlabelled code should say who made it, got %q", inv.Label)
	}

	// The listing of codes must not hand them back out.
	_, body = f.call(t, alice, "/manage/invites", map[string]string{})
	if bytes.Contains(body, []byte(inv.Token)) {
		t.Error("the invite listing exposes whole tokens, which would let any administrator's console redeem them")
	}

	if code, _ := f.call(t, bob, "/manage/remove", nodeRequest{Node: "alice"}); code != http.StatusForbidden {
		t.Errorf("a non-administrator removed a machine: %d", code)
	}
	if code, _ := f.call(t, alice, "/manage/remove", nodeRequest{Node: "alice"}); code != http.StatusBadRequest {
		t.Errorf("an administrator removed itself: %d", code)
	}
	if code, body := f.call(t, alice, "/manage/remove", nodeRequest{Node: "bob"}); code != http.StatusOK {
		t.Fatalf("remove: %d %s", code, body)
	}
	if _, ok := f.store.NodeName(bob.id); ok {
		t.Error("bob is still registered after being removed")
	}

	audit := f.store.Audit(10)
	if len(audit) == 0 || audit[0].Actor != "alice" || audit[0].Action != "node.remove" {
		t.Errorf("the audit log should say who removed bob, got %+v", audit[0])
	}
}

func TestAdministratorsLearnItFromTheirNetmap(t *testing.T) {
	f := newHubFixture(t)
	alice := f.join(t, "alice")

	nm := openMap(t, f.store, alice.id)
	if nm.Self.Admin {
		t.Fatal("alice is an administrator before anyone said so")
	}
	v := f.store.Version()
	if err := f.store.SetAdmin("admin", "alice", true); err != nil {
		t.Fatal(err)
	}
	if f.store.Version() == v {
		t.Error("granting administration did not re-issue the map, so the console would not learn of it")
	}
	if nm := openMap(t, f.store, alice.id); !nm.Self.Admin {
		t.Error("alice's own map does not say she is an administrator")
	}

	// Removing the machine must take the right with it: the next machine to
	// join under that name is somebody else.
	if err := f.store.RemoveNode("alice"); err != nil {
		t.Fatal(err)
	}
	if names := f.store.AdminNames(); len(names) != 0 {
		t.Errorf("a removed machine is still an administrator: %v", names)
	}
}

func TestOfflineMachinesAreAnnounced(t *testing.T) {
	f := newHubFixture(t)
	alice := f.join(t, "alice")
	bob := f.join(t, "bob")

	now := time.Now()
	f.store.checkLiveness(now) // first look: records, announces nothing
	v := f.store.Version()
	f.store.checkLiveness(now)
	if f.store.Version() != v {
		t.Fatal("nothing changed, and the map was re-issued anyway")
	}

	// Bob stops talking. Nothing else happens on the network.
	later := now.Add(onlineWindow + time.Second)
	f.store.Touch(alice.id)
	f.store.mu.Lock()
	f.store.st.Nodes[alice.id].LastSeen = later
	f.store.mu.Unlock()
	f.store.checkLiveness(later)
	if f.store.Version() == v {
		t.Fatal("bob went quiet and the map was not re-issued, so everyone still sees him online")
	}

	f.store.mu.Lock()
	n := f.store.st.Nodes[bob.id]
	online := later.Sub(n.LastSeen) < onlineWindow
	f.store.mu.Unlock()
	if online {
		t.Fatal("test setup: bob should be past the online window")
	}
}

func TestPollFromANewerVersionIsAnsweredAtOnce(t *testing.T) {
	f := newHubFixture(t)
	current := f.store.Version()

	start := time.Now()
	if !f.store.WaitForChange(current+50, 5*time.Second, nil) {
		t.Fatal("a node holding a map from before a restart was left waiting")
	}
	if time.Since(start) > time.Second {
		t.Error("the answer took the whole long poll")
	}
	if f.store.WaitForChange(current, 50*time.Millisecond, nil) {
		t.Error("a node that is up to date was told something changed")
	}
}

func TestLargeJobResultsAreAccepted(t *testing.T) {
	f := newHubFixture(t)
	alice := f.join(t, "alice")
	worker := f.join(t, "worker")
	if err := f.store.Report(worker.id, Report{Stats: plainStats(),
		Compute: computeFor("alice")}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Submit(&Job{Submitter: "alice", Command: []string{"big"}}); err != nil {
		t.Fatal(err)
	}
	job, ok := f.store.Claim(worker.id)
	if !ok {
		t.Fatal("the worker was given nothing")
	}

	// A megabyte of output: far over the 64 KiB that suits every other
	// request, and well within what a worker is allowed to send.
	out := strings.Repeat("line of output\n", 70000)
	code, body := f.call(t, worker, "/queue/result", JobResult{ID: job.ID, Stdout: out})
	if code != http.StatusOK {
		t.Fatalf("a large result was refused: %d %s", code, body)
	}
	got, _ := f.store.JobByID(job.ID)
	if got.State != JobDone {
		t.Fatalf("job is %q after its result arrived", got.State)
	}
	if len(got.Stdout) > hubapi.KeepStdout+200 {
		t.Errorf("the hub kept %d bytes of output, more than its limit", len(got.Stdout))
	}
	if !strings.Contains(got.Stdout, "dropped") {
		t.Error("trimmed output does not say it was trimmed")
	}

	// A listing for the console leaves output out, and says how much there is.
	code, body = f.call(t, alice, "/queue/list", map[string]any{"brief": true})
	if code != http.StatusOK {
		t.Fatalf("list: %d %s", code, body)
	}
	var jobs []Job
	if err := json.Unmarshal(body, &jobs); err != nil || len(jobs) != 1 {
		t.Fatalf("list = %s", body)
	}
	if jobs[0].Stdout != "" || jobs[0].OutputBytes == 0 {
		t.Errorf("brief listing: stdout %d bytes, output_bytes %d", len(jobs[0].Stdout), jobs[0].OutputBytes)
	}
}

func TestSubmittingWakesAnIdleWorker(t *testing.T) {
	f := newHubFixture(t)
	f.join(t, "alice")

	woke := make(chan struct{})
	go func() {
		f.store.WaitForQueueChange(10*time.Second, nil)
		close(woke)
	}()
	time.Sleep(50 * time.Millisecond)
	if _, err := f.store.Submit(&Job{Submitter: "alice", Command: []string{"x"}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-woke:
	case <-time.After(2 * time.Second):
		t.Fatal("a worker waiting for work slept through a submission")
	}
}

func TestLocalRequestsAreRecognisedFromTheConnection(t *testing.T) {
	mk := func(remote, local string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		la, _ := net.ResolveTCPAddr("tcp", local)
		return r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, la))
	}
	// 203.0.113.0/24 is never a real interface address, so only the
	// connection-ends rule can answer these.
	if !isLocalRequest(mk("203.0.113.5:5000", "203.0.113.5:8420")) {
		t.Error("a client on this machine, dialling its own address, was not recognised")
	}
	if isLocalRequest(mk("203.0.113.9:5000", "203.0.113.5:8420")) {
		t.Error("a client on another machine was taken for this one")
	}
}

func openMap(t *testing.T, s *Store, nodeID string) *netmap.NetMap {
	t.Helper()
	signed, err := s.NetMapFor(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	nm, err := signed.Open(s.HubKey().Public().Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	return nm
}

func computeFor(allow ...string) resource.ComputeConfig {
	return resource.ComputeConfig{Enabled: true, Allow: allow, RunAs: "someone"}
}

// An administrator switches one connection off and on from a member
// machine; the change reaches the netmap the far machine enforces, the audit
// log names who made it, and nobody else may make it.
func TestAccessIsSwitchedPerPairFromAnAdminMachine(t *testing.T) {
	f := newHubFixture(t)
	admin := f.join(t, "linuxbox")
	guest := f.join(t, "winpc-01")
	hubNode := f.join(t, "hubpc")
	if err := f.store.SetAdmin("admin", "linuxbox", true); err != nil {
		t.Fatal(err)
	}

	block := AccessChange{Action: "block", Src: "winpc-01", Dst: "hubpc", Services: []string{"ssh", "vnc"}}
	if code, _ := f.call(t, guest, "/manage/access", block); code != http.StatusForbidden {
		t.Fatalf("a machine that is not an administrator changed access: %d", code)
	}
	code, body := f.call(t, admin, "/manage/access", block)
	if code != http.StatusOK {
		t.Fatalf("block: %d %s", code, body)
	}
	var view struct {
		Pairs []struct {
			Src, Dst string
			All      bool
		}
	}
	if err := json.Unmarshal(body, &view); err != nil || len(view.Pairs) != 6 {
		t.Fatalf("view = %s (%v)", body, err)
	}

	// hubpc's map is what its packet filter enforces: winpc-01 loses 22 and
	// 5900 there, and nothing else.
	var entry *netmap.Node
	for _, p := range openMap(t, f.store, hubNode.id).Peers {
		if p.Name == "winpc-01" {
			entry = &p
		}
	}
	if entry == nil {
		t.Fatal("winpc-01 vanished from hubpc's map; a partial block must not remove a peer")
	}
	allows := func(port uint16) bool {
		for _, r := range entry.InboundPorts {
			if port >= r.Lo && port <= r.Hi {
				return true
			}
		}
		return len(entry.InboundPorts) == 0
	}
	if allows(22) || allows(5900) || !allows(3389) || !allows(8421) {
		t.Errorf("winpc-01 on hubpc: ssh=%v vnc=%v rdp=%v locnet=%v; want only ssh and vnc refused",
			allows(22), allows(5900), allows(3389), allows(8421))
	}

	audit := f.store.Audit(5)
	if len(audit) == 0 || audit[0].Actor != "linuxbox" || audit[0].Action != "access.block" ||
		!strings.Contains(audit[0].Detail, "winpc-01 → hubpc") {
		t.Errorf("latest audit entry = %+v", audit[0])
	}

	// Typos are refused rather than written into the policy.
	if code, _ := f.call(t, admin, "/manage/access", AccessChange{Action: "block", Src: "fluxhwak", Dst: "hubpc"}); code != http.StatusBadRequest {
		t.Errorf("an unknown machine name was accepted: %d", code)
	}

	// And allowing them again leaves the policy as it started.
	if code, body := f.call(t, admin, "/manage/access",
		AccessChange{Action: "allow", Src: "winpc-01", Dst: "hubpc", Services: []string{"ssh", "vnc"}}); code != http.StatusOK {
		t.Fatalf("allow: %d %s", code, body)
	}
	if p := f.store.Policy(); len(p.Blocks) != 0 || len(p.Rules) != 1 {
		t.Errorf("after allowing back: %+v", p)
	}
}

func TestReplayGuardAcceptsASignatureOnce(t *testing.T) {
	var g replayGuard
	if !g.first("sig-a") {
		t.Fatal("a new signature was refused")
	}
	if g.first("sig-a") {
		t.Error("the same signature was accepted twice")
	}
	if !g.first("sig-b") {
		t.Error("a different signature was refused")
	}
}
