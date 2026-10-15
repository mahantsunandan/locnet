package hub

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/mahantsunandan/locnet/internal/key"
	"github.com/mahantsunandan/locnet/internal/policy"
	"github.com/mahantsunandan/locnet/internal/resource"
)

const testDomain = "example.duckdns.org"

// joinAs registers a machine, optionally as the one on the hub machine.
func (f *hubFixture) joinAs(t *testing.T, name string, isHub bool) member {
	t.Helper()
	priv, pub, err := key.NewMachine()
	if err != nil {
		t.Fatal(err)
	}
	tok, err := f.store.CreateToken("test", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	n, err := f.store.Register(tok.Token, &Node{Name: name, MachineKey: pub, Hub: isHub})
	if err != nil {
		t.Fatal(err)
	}
	return member{id: n.ID, name: n.Name, priv: priv}
}

func siteShare(site string) resource.Share {
	return resource.Share{Name: "web-" + site, Kind: resource.KindPort, Target: "127.0.0.1:3000",
		Port: 8430, Allow: []string{"hubpc"}, Web: site}
}

func (f *hubFixture) offer(t *testing.T, m member, shares ...resource.Share) {
	t.Helper()
	if err := f.store.Report(m.id, Report{Shares: shares}); err != nil {
		t.Fatal(err)
	}
}

func siteState(t *testing.T, s *Store, name, machine string) Site {
	t.Helper()
	for _, site := range s.WebShare().Sites {
		if site.Name == name && site.Machine == machine {
			return site
		}
	}
	t.Fatalf("no site %s on %s in %+v", name, machine, s.WebShare().Sites)
	return Site{}
}

// A site goes public only when the machine asks, an administrator approves,
// a domain is set and the policy lets the hub machine in — and every one of
// those can take it down again.
func TestWebShareNeedsEveryPartyToAgree(t *testing.T) {
	f := newHubFixture(t)
	f.joinAs(t, "hubpc", true)
	flux := f.joinAs(t, "winpc-01", false)
	f.offer(t, flux, siteShare("myapp"))
	host := "myapp." + testDomain

	if got := siteState(t, f.store, "myapp", "winpc-01").State; got != SiteWaiting {
		t.Fatalf("a fresh request is %q", got)
	}
	if _, err := f.store.ChangeSite("linuxbox", "approve", "myapp", ""); err != nil {
		t.Fatal(err)
	}
	if got := siteState(t, f.store, "myapp", "winpc-01").State; got != SiteNoDomain {
		t.Errorf("approved without a domain is %q", got)
	}
	if err := f.store.SetWebShareDomain(testDomain, "", "", false); err == nil {
		t.Error("a domain was set without agreeing to Let's Encrypt's terms")
	}
	if err := f.store.SetWebShareDomain(testDomain, "secret-token", "", true); err != nil {
		t.Fatal(err)
	}
	site := siteState(t, f.store, "myapp", "winpc-01")
	if !site.Live || site.URL != "https://"+host {
		t.Fatalf("site = %+v, want live at https://%s", site, host)
	}

	route, ok := f.store.siteRouteFor(strings.ToUpper(host))
	if !ok || route.addr.Port() != 8430 || route.addr.Addr() != f.store.st.Nodes[flux.id].IP {
		t.Errorf("route = %+v %v, want winpc-01's overlay address on 8430", route, ok)
	}
	for _, other := range []string{testDomain, "nope." + testDomain, "a.myapp." + testDomain, "myapp.elsewhere.org"} {
		if _, ok := f.store.siteRouteFor(other); ok {
			t.Errorf("%s routes somewhere", other)
		}
	}

	// The machine sees its own site, with its address and state.
	if nm := openMap(t, f.store, flux.id); len(nm.Self.Sites) != 1 || !nm.Self.Sites[0].Live {
		t.Errorf("winpc-01's own map shows %+v", nm.Self.Sites)
	}

	// The policy can take it down: the hub machine must reach the port.
	p := policy.Default()
	p.Block("hubpc", "winpc-01", []string{"8430"}, "")
	if err := f.store.SetPolicy(p); err != nil {
		t.Fatal(err)
	}
	if got := siteState(t, f.store, "myapp", "winpc-01").State; got != SiteBlocked {
		t.Errorf("with the hub machine blocked the site is %q", got)
	}
	if err := f.store.SetPolicy(policy.Default()); err != nil {
		t.Fatal(err)
	}

	// So can the administrator, and so can the machine.
	if _, err := f.store.ChangeSite("linuxbox", "off", "myapp", ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.store.siteRouteFor(host); ok {
		t.Error("a site turned off still routes")
	}
	if _, err := f.store.ChangeSite("linuxbox", "on", "myapp", ""); err != nil {
		t.Fatal(err)
	}
	f.offer(t, flux)
	if got := siteState(t, f.store, "myapp", "winpc-01").State; got != SiteGone {
		t.Errorf("after the machine withdrew it the site is %q", got)
	}
	if _, ok := f.store.siteRouteFor(host); ok {
		t.Error("a withdrawn site still routes")
	}
}

// A name belongs to the machine it was approved for. Another machine asking
// for it gets nothing until an administrator says otherwise.
func TestWebShareNamesAreNotHijacked(t *testing.T) {
	f := newHubFixture(t)
	f.joinAs(t, "hubpc", true)
	flux := f.joinAs(t, "winpc-01", false)
	other := f.joinAs(t, "linuxbox", false)
	if err := f.store.SetWebShareDomain(testDomain, "", "", true); err != nil {
		t.Fatal(err)
	}
	f.offer(t, flux, siteShare("myapp"))
	if _, err := f.store.ChangeSite("admin", "approve", "myapp", ""); err != nil {
		t.Fatal(err)
	}
	f.offer(t, other, siteShare("myapp"))

	if got := siteState(t, f.store, "myapp", "linuxbox").State; got != SiteTaken {
		t.Errorf("the second machine's request is %q", got)
	}
	route, _ := f.store.siteRouteFor("myapp." + testDomain)
	if route.addr.Addr() != f.store.st.Nodes[flux.id].IP {
		t.Error("the name moved to the machine that asked second")
	}
	if _, err := f.store.ChangeSite("admin", "approve", "myapp", ""); err == nil {
		t.Error("an ambiguous approval went through without naming the machine")
	}
}

// The domain and the DNS token are set on the hub machine only; a signed
// request from an administrator machine may run sites, not configure them.
func TestWebShareDomainOnlyFromTheHub(t *testing.T) {
	f := newHubFixture(t)
	admin := f.join(t, "linuxbox")
	if err := f.store.SetAdmin("admin", "linuxbox", true); err != nil {
		t.Fatal(err)
	}
	code, _ := f.call(t, admin, "/manage/webshare", SiteChange{Action: "domain", Domain: testDomain, AcceptTOS: true})
	if code != http.StatusForbidden {
		t.Errorf("an administrator machine set the domain: %d", code)
	}
	code, body := f.call(t, admin, "/manage/webshare", map[string]string{})
	if code != http.StatusOK {
		t.Fatalf("view: %d %s", code, body)
	}
	if err := f.store.SetWebShareDomain(testDomain, "secret-token", "", true); err != nil {
		t.Fatal(err)
	}
	_, body = f.call(t, admin, "/manage/webshare", map[string]string{})
	if strings.Contains(string(body), "secret-token") {
		t.Error("the DNS token was sent to an administrator machine")
	}
}

// The proxy passes a request to the site's machine with its public name and
// the caller's address, says nothing about names that are not sites, and
// slows down a client that floods it.
func TestWebShareProxy(t *testing.T) {
	f := newHubFixture(t)
	f.joinAs(t, "hubpc", true)
	flux := f.joinAs(t, "winpc-01", false)
	f.offer(t, flux, siteShare("myapp"))
	if _, err := f.store.ChangeSite("admin", "approve", "myapp", ""); err != nil {
		t.Fatal(err)
	}
	if err := f.store.SetWebShareDomain(testDomain, "", "", true); err != nil {
		t.Fatal(err)
	}

	var seen struct {
		sync.Mutex
		host, xff, path string
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Lock()
		seen.host, seen.xff, seen.path = r.Host, r.Header.Get("X-Forwarded-For"), r.URL.Path
		seen.Unlock()
		w.Write([]byte("hello from winpc-01"))
	}))
	defer backend.Close()

	w := NewWebServer(f.store, t.TempDir(), nil)
	var dialled string
	w.transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialled = addr // where the proxy meant to go; the test backend stands in for it
		return (&net.Dialer{}).DialContext(ctx, network, backend.Listener.Addr().String())
	}

	req := httptest.NewRequest("GET", "https://myapp."+testDomain+"/docs/index.html", nil)
	req.RemoteAddr = "203.0.113.9:51515"
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Body.String() != "hello from winpc-01" {
		t.Fatalf("proxied request: %d %q", rec.Code, rec.Body.String())
	}
	want := f.store.st.Nodes[flux.id].IP.String() + ":8430"
	if dialled != want {
		t.Errorf("proxy dialled %s, want %s", dialled, want)
	}
	if seen.host != "myapp."+testDomain || seen.xff != "203.0.113.9" || seen.path != "/docs/index.html" {
		t.Errorf("backend saw host=%q xff=%q path=%q", seen.host, seen.xff, seen.path)
	}
	if v := f.store.WebShare(); v.Sites[0].Requests != 1 {
		t.Errorf("request count = %d", v.Sites[0].Requests)
	}

	rec = httptest.NewRecorder()
	w.ServeHTTP(rec, httptest.NewRequest("GET", "https://admin."+testDomain+"/", nil))
	if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "myapp") {
		t.Errorf("unknown site answered %d %q", rec.Code, rec.Body.String())
	}

	w.limiter = newIPLimiter(1, 3)
	limited := 0
	for i := 0; i < 10; i++ {
		rec = httptest.NewRecorder()
		req := httptest.NewRequest("GET", "https://myapp."+testDomain+"/", nil)
		req.RemoteAddr = "198.51.100.7:4000"
		w.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited < 6 {
		t.Errorf("only %d of 10 rapid requests were limited", limited)
	}
}

// DuckDNS answers OK or KO; either way the token must never reach a log.
func TestDuckDNSUpdate(t *testing.T) {
	var gotDomain string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotDomain = r.URL.Query().Get("domains")
		if r.URL.Query().Get("token") != "good" {
			w.Write([]byte("KO"))
			return
		}
		w.Write([]byte("OK\n203.0.113.27\n\nUPDATED"))
	}))
	defer srv.Close()
	old := duckDNSUpdate
	duckDNSUpdate = srv.URL
	defer func() { duckDNSUpdate = old }()

	st := duckDNS(context.Background(), "yourname.duckdns.org", "good")
	if st.Error != "" || st.IP != "203.0.113.27" || gotDomain != "yourname" {
		t.Errorf("good token: %+v (asked for %q)", st, gotDomain)
	}
	if st := duckDNS(context.Background(), "yourname.duckdns.org", "bad-token-123"); st.Error == "" ||
		strings.Contains(st.Error, "bad-token-123") {
		t.Errorf("bad token: %+v", st)
	}
	if st := duckDNS(context.Background(), "example.org", "x"); st.Error == "" {
		t.Error("a non-DuckDNS domain was sent to DuckDNS")
	}

	duckDNSUpdate = "http://127.0.0.1:1" // nothing listens
	st = duckDNS(context.Background(), "yourname.duckdns.org", "never-log-me")
	if st.Error == "" || strings.Contains(st.Error, "never-log-me") {
		t.Errorf("unreachable DuckDNS: %+v", st)
	}

	b, _ := json.Marshal(WebShareView{DuckDNS: true})
	if strings.Contains(string(b), "token") {
		t.Errorf("the admin view has a token field: %s", b)
	}
}

func TestRateLimitCountsAnIPv6Slash64AsOneVisitor(t *testing.T) {
	a := limitKey("[2001:db8:1:2:aaaa::1]:4000")
	b := limitKey("[2001:db8:1:2:bbbb::9]:4001")
	if a != b {
		t.Errorf("two addresses in one /64 count separately: %s and %s", a, b)
	}
	if limitKey("[2001:db8:1:3::1]:1") == a {
		t.Error("a different /64 shares the allowance")
	}
	if got := limitKey("203.0.113.5:443"); got != "203.0.113.5" {
		t.Errorf("IPv4 key is %q", got)
	}
	if got := limitKey("[::ffff:203.0.113.5]:443"); got != "203.0.113.5" {
		t.Errorf("IPv4-mapped key is %q", got)
	}
}
