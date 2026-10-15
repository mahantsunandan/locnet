package hub

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// WebServer answers the internet for WebShare sites.
//
// Nothing listens until a domain is configured: a hub that has never been
// told to publish anything opens no port beyond its own API. Once one is, it
// takes 80 and 443. Port 80 only answers Let's Encrypt's challenges and
// redirects to HTTPS; 443 serves sites, each from its own certificate, and
// passes every request through the tunnel to the one overlay port of the one
// share the site was approved for.
type WebServer struct {
	store *Store
	logf  func(string, ...any)

	// HTTPAddr and HTTPSAddr are where to listen, ":80" and ":443" normally.
	HTTPAddr, HTTPSAddr string
	// CacheDir keeps certificates across restarts, so a restart does not
	// spend Let's Encrypt's rate limit.
	CacheDir string
	// ACMEDirectory overrides Let's Encrypt's production directory, for
	// testing against their staging one. Empty means production.
	ACMEDirectory string

	transport *http.Transport
	limiter   *ipLimiter

	mu      sync.Mutex
	started bool
	stats   map[string]*siteStat
}

type siteStat struct {
	requests uint64
	lastErr  string
}

// NewWebServer prepares the server; Run starts it when there is something to
// serve.
func NewWebServer(store *Store, stateDir string, logf func(string, ...any)) *WebServer {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	w := &WebServer{
		store: store, logf: logf,
		HTTPAddr: ":80", HTTPSAddr: ":443",
		CacheDir: filepath.Join(stateDir, "webshare-certs"),
		transport: &http.Transport{
			DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			MaxIdleConnsPerHost: 16,
			IdleConnTimeout:     90 * time.Second,
		},
		limiter: newIPLimiter(20, 100),
		stats:   map[string]*siteStat{},
	}
	store.setSiteStats(w.siteStats)
	return w
}

// Run starts listening once WebShare is configured, keeps DuckDNS current,
// and returns when ctx ends.
func (w *WebServer) Run(ctx context.Context) {
	go w.updateDNS(ctx)
	go w.limiter.prune(ctx)
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		w.maybeStart(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (w *WebServer) maybeStart(ctx context.Context) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.started {
		return
	}
	domain, email, ok := w.store.acmeConfig()
	if !ok {
		return
	}

	mgr := &autocert.Manager{
		Prompt:     autocert.AcceptTOS, // the operator agreed: SetWebShareDomain refuses otherwise
		Cache:      autocert.DirCache(w.CacheDir),
		HostPolicy: w.hostPolicy,
		Email:      email,
	}
	if w.ACMEDirectory != "" {
		mgr.Client = &acme.Client{DirectoryURL: w.ACMEDirectory}
	}

	plain := &http.Server{
		Addr:              w.HTTPAddr,
		Handler:           mgr.HTTPHandler(http.HandlerFunc(w.redirect)),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       time.Minute,
		ErrorLog:          w.serverLog(),
	}
	tlsCfg := mgr.TLSConfig()
	tlsCfg.MinVersion = tls.VersionTLS12
	secure := &http.Server{
		Addr:              w.HTTPSAddr,
		Handler:           w,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          w.serverLog(),
	}
	lnPlain, err := net.Listen("tcp", w.HTTPAddr)
	if err != nil {
		w.logf("webshare: cannot listen on %s for certificates: %v — will retry", w.HTTPAddr, err)
		return
	}
	lnSecure, err := net.Listen("tcp", w.HTTPSAddr)
	if err != nil {
		lnPlain.Close()
		w.logf("webshare: cannot listen on %s: %v — will retry", w.HTTPSAddr, err)
		return
	}
	w.started = true
	go plain.Serve(lnPlain)
	go secure.ServeTLS(lnSecure, "", "")
	go func() {
		<-ctx.Done()
		plain.Close()
		secure.Close()
	}()
	w.logf("webshare: serving sites under %s on %s and %s", domain, w.HTTPSAddr, w.HTTPAddr)
}

// serverLog is net/http's error log for the public listeners, minus the
// failed TLS handshakes. Those are the internet at work: every certificate is
// published in Certificate Transparency logs, scanners watch the logs, and
// within minutes of a site's first certificate they come knocking — for it,
// for names that were never sites, and with no name at all. Refusing them is
// the design; writing a line for each one fills the journal and buries the
// lines that matter.
func (w *WebServer) serverLog() *log.Logger {
	return log.New(logFilter{w.logf}, "", 0)
}

type logFilter struct{ logf func(string, ...any) }

func (f logFilter) Write(p []byte) (int, error) {
	line := strings.TrimSpace(string(p))
	if !strings.Contains(line, "TLS handshake error") {
		f.logf("webshare: %s", line)
	}
	return len(p), nil
}

// hostPolicy decides which names a certificate may be requested for: live
// sites only. Anything else — a scanner trying random names under the domain
// — is refused before Let's Encrypt is asked, so it cannot spend the rate
// limit.
func (w *WebServer) hostPolicy(_ context.Context, host string) error {
	if _, ok := w.store.siteRouteFor(host); ok {
		return nil
	}
	return fmt.Errorf("webshare: %q is not a live site", host)
}

func (w *WebServer) redirect(rw http.ResponseWriter, r *http.Request) {
	if _, ok := w.store.siteRouteFor(hostOnly(r.Host)); !ok {
		notFound(rw)
		return
	}
	http.Redirect(rw, r, "https://"+hostOnly(r.Host)+r.URL.RequestURI(), http.StatusPermanentRedirect)
}

// ServeHTTP is the HTTPS side: find the site, check the caller's rate, and
// pass the request to the site's machine.
func (w *WebServer) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, ok := w.store.siteRouteFor(hostOnly(r.Host))
	if !ok {
		notFound(rw)
		return
	}
	if !w.limiter.allow(limitKey(r.RemoteAddr)) {
		http.Error(rw, "Too many requests. Slow down and try again.", http.StatusTooManyRequests)
		return
	}
	w.count(route.name, "")

	target := &url.URL{Scheme: "http", Host: route.addr.String()}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host // the site may need its public name
			pr.SetXForwarded()
		},
		Transport: w.transport,
		ErrorHandler: func(rw http.ResponseWriter, r *http.Request, err error) {
			w.count(route.name, err.Error())
			w.logf("webshare: %s: the machine did not answer: %v", route.name, err)
			http.Error(rw, "The machine serving this site did not answer. Try again in a minute.", http.StatusBadGateway)
		},
	}
	proxy.ServeHTTP(rw, r)
}

func (w *WebServer) count(name, errText string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	st := w.stats[name]
	if st == nil {
		st = &siteStat{}
		w.stats[name] = st
	}
	if errText == "" {
		st.requests++
	} else {
		st.lastErr = time.Now().Format("15:04 ") + errText
	}
}

func (w *WebServer) siteStats(name string) (uint64, string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if st := w.stats[name]; st != nil {
		return st.requests, st.lastErr
	}
	return 0, ""
}

// notFound says as little as possible: which names exist under the domain
// is not something to tell a scanner.
func notFound(rw http.ResponseWriter) {
	http.Error(rw, "There is no site at this address.", http.StatusNotFound)
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(hostport)
}

func clientIP(remote string) string {
	if h, _, err := net.SplitHostPort(remote); err == nil {
		return h
	}
	return remote
}

// limitKey is what the rate limit counts against: the address for IPv4, and
// the /64 for IPv6. One IPv6 connection is normally handed a whole /64, so
// counting single addresses gave every visitor eighteen quintillion separate
// allowances, one per address it cared to send from.
func limitKey(remote string) string {
	ip, err := netip.ParseAddr(clientIP(remote))
	if err != nil {
		return clientIP(remote)
	}
	ip = ip.Unmap()
	if ip.Is4() {
		return ip.String()
	}
	return netip.PrefixFrom(ip, 64).Masked().String()
}

// ------------------------------------------------------------ dynamic DNS

// duckDNSUpdate is DuckDNS's update endpoint. An empty ip tells it to use the
// address the request came from, which for a hub at home is the house.
var duckDNSUpdate = "https://www.duckdns.org/update"

// dnsEvery is how often DuckDNS is told the address; home addresses change
// rarely, and when they do a site is down until the next update.
const dnsEvery = 5 * time.Minute

func (w *WebServer) updateDNS(ctx context.Context) {
	var lastDomain, lastToken string
	var next time.Time
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		domain, token := w.store.duckDNS()
		changed := domain != lastDomain || token != lastToken
		if token != "" && domain != "" && (changed || time.Now().After(next)) {
			st := duckDNS(ctx, domain, token)
			w.store.setDNSStatus(st)
			if st.Error != "" {
				w.logf("webshare: DuckDNS update for %s failed: %s", domain, st.Error)
			} else if changed {
				w.logf("webshare: DuckDNS points %s at %s", domain, st.IP)
			}
			next = time.Now().Add(dnsEvery)
		}
		lastDomain, lastToken = domain, token
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// duckDNS performs one update. Errors never include the request URL, because
// the token is in it and errors end up in logs.
func duckDNS(ctx context.Context, domain, token string) DNSStatus {
	st := DNSStatus{At: time.Now()}
	sub, ok := strings.CutSuffix(domain, ".duckdns.org")
	if !ok || sub == "" || strings.Contains(sub, ".") {
		st.Error = fmt.Sprintf("%s is not a DuckDNS name (yourname.duckdns.org), so there is nothing to update", domain)
		return st
	}
	q := url.Values{"domains": {sub}, "token": {token}, "verbose": {"true"}}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, duckDNSUpdate+"?"+q.Encode(), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		st.Error = "could not reach DuckDNS: " + err.Error()
		return st
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	lines := strings.Fields(string(body))
	if len(lines) == 0 || lines[0] != "OK" {
		st.Error = "DuckDNS refused the update — check the token and the name"
		return st
	}
	if len(lines) > 1 {
		st.IP = lines[1]
	}
	return st
}

// ------------------------------------------------------------ rate limit

// ipLimiter is a token bucket per client address: enough for a person
// browsing, not enough for one address to keep a home connection busy.
type ipLimiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newIPLimiter(perSecond, burst float64) *ipLimiter {
	return &ipLimiter{rate: perSecond, burst: burst, buckets: map[string]*bucket{}}
}

func (l *ipLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b := l.buckets[ip]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[ip] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// prune forgets addresses that have been quiet long enough to be full again.
func (l *ipLimiter) prune(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		l.mu.Lock()
		for ip, b := range l.buckets {
			if time.Since(b.last) > 10*time.Minute {
				delete(l.buckets, ip)
			}
		}
		l.mu.Unlock()
	}
}
