package hub

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/mahantsunandan/locnet/internal/key"
)

func TestMirrorCopiesTheRegister(t *testing.T) {
	primaryPath := filepath.Join(t.TempDir(), "hub.json")
	primary, err := Open(primaryPath, "testnet", DefaultPrefix)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := primary.CreateToken("for the test", 3, 0)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(NewServer(primary, nil, []string{"127.0.0.1:8420"}, t.Logf).Handler())
	defer srv.Close()

	standbyDir := t.TempDir()
	standbyPath := filepath.Join(standbyDir, "hub.json")
	m := &Mirror{From: srv.URL, Token: primary.AdminToken(), Path: standbyPath, Logf: t.Logf}
	if err := m.once(context.Background()); err != nil {
		t.Fatalf("mirroring: %v", err)
	}

	// The copy has to be a hub the network already trusts: same identity key,
	// same address range, same join tokens. A spare that signs with a
	// different key is not a spare, it is a second network.
	standby, err := Open(standbyPath, "unused", DefaultPrefix)
	if err != nil {
		t.Fatalf("opening the copy: %v", err)
	}
	if standby.HubKey().Public().Fingerprint() != primary.HubKey().Public().Fingerprint() {
		t.Error("the standby has a different identity key, so no node would believe its maps")
	}
	if standby.Network().Prefix != primary.Network().Prefix {
		t.Error("the standby has a different address range")
	}
	var found bool
	for _, got := range standby.Tokens() {
		if got.Token == tok.Token {
			found = true
		}
	}
	if !found {
		t.Error("the standby does not know the primary's join codes, so nothing could join it")
	}
	if got := m.Status(); got.LastSync.IsZero() || got.LastErr != "" {
		t.Errorf("status after a good sync is %+v", got)
	}
}

func TestMirrorRefusesRubbish(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hub.json")

	// A good copy first, so there is something worth protecting.
	good, err := Open(path, "testnet", DefaultPrefix)
	if err != nil {
		t.Fatal(err)
	}
	want := good.HubKey().Public().Fingerprint()

	for _, body := range []string{"not json at all", `{"version":9}`, "{}"} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		m := &Mirror{From: srv.URL, Token: "x", Path: path, Logf: t.Logf}
		if err := m.once(context.Background()); err == nil {
			t.Errorf("a snapshot of %q was accepted", body)
		}
		srv.Close()
	}

	// Whatever arrived, the state on disk is still the one that worked.
	after, err := Open(path, "testnet", DefaultPrefix)
	if err != nil {
		t.Fatalf("the state file was damaged: %v", err)
	}
	if after.HubKey().Public().Fingerprint() != want {
		t.Error("a bad snapshot overwrote a good register")
	}
	if _, err := os.Stat(path + ".mirror"); err == nil {
		t.Error("a partial download was left behind")
	}
}

func TestSnapshotNeedsTheAdminToken(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "hub.json"), "testnet", DefaultPrefix)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(NewServer(store, nil, []string{"127.0.0.1:8420"}, t.Logf).Handler())
	defer srv.Close()

	for _, tok := range []string{"", "wrong", store.AdminToken()} {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/admin/snapshot", nil)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		want := http.StatusUnauthorized
		if tok == store.AdminToken() {
			want = http.StatusOK
		}
		if resp.StatusCode != want {
			t.Errorf("token %q got %s, wanted %d", tok, resp.Status, want)
		}
	}
}

func TestPromotionMarkerIsConsumed(t *testing.T) {
	dir := t.TempDir()
	m := &Mirror{Path: filepath.Join(dir, "hub.json")}
	if m.promoted() {
		t.Fatal("promoted with no marker present")
	}
	if err := os.WriteFile(filepath.Join(dir, StandbyMarker), []byte("now"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !m.promoted() {
		t.Fatal("the marker was ignored")
	}
	if m.promoted() {
		t.Error("the marker was not consumed, so a demoted hub would promote itself again")
	}
}

// TestNetmapCarriesHubAddresses is what makes failover reach machines that
// joined before the spare existed.
func TestNetmapCarriesHubAddresses(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "hub.json"), "testnet", DefaultPrefix)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(store, nil, []string{"primary:8420"}, t.Logf)
	srv.SetStandbyAddrs([]string{"spare:8420"})

	_, pub, err := key.NewMachine()
	if err != nil {
		t.Fatal(err)
	}
	tok, err := store.CreateToken("test", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	n, err := store.Register(tok.Token, &Node{Name: "unit-01", MachineKey: pub})
	if err != nil {
		t.Fatal(err)
	}

	signed, err := store.NetMapFor(n.ID)
	if err != nil {
		t.Fatal(err)
	}
	m, err := signed.Open(store.HubKey().Public().Fingerprint())
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"primary:8420", "spare:8420"}
	if len(m.Network.Hubs) != len(want) {
		t.Fatalf("netmap lists hubs %v, wanted %v", m.Network.Hubs, want)
	}
	for i := range want {
		if m.Network.Hubs[i] != want[i] {
			t.Errorf("hub %d is %q, wanted %q", i, m.Network.Hubs[i], want[i])
		}
	}
}
