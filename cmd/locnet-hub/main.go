// Command locnet-hub is the coordination server. It runs on the one machine
// that is always on, holds the list of members, hands out addresses, and
// relays for peers that cannot reach each other directly.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/mahantsunandan/locnet/internal/hub"
	"github.com/mahantsunandan/locnet/internal/hubapi"
	"github.com/mahantsunandan/locnet/internal/hubtls"
	"github.com/mahantsunandan/locnet/internal/paths"
)

// Version is stamped at build time with -ldflags "-X main.Version=…". The hub
// package has its own default for when it is used as a library; this is the
// one the binary reports and the one /v1/info serves.
var Version = "0.3.0"

const usage = `locnet-hub — LocNet coordination server

Usage:
  Running
    locnet-hub serve   [flags]      run the hub (control plane + UDP relay)

  Membership
    locnet-hub invite  [flags]      mint a join code
    locnet-hub invites              list join codes
    locnet-hub revoke  <code-start> disable a join code
    locnet-hub nodes                list machines on the network
    locnet-hub approve <machine>    admit a machine that is waiting
    locnet-hub remove  <machine>    remove a machine from the network
    locnet-hub admins [add|remove <machine>]
                                    who may do all of the above from their
                                    own machine, with locnet admin or the console

  Access control
    locnet-hub policy               show which machines may reach which
    locnet-hub policy edit          edit it in $EDITOR
    locnet-hub policy example       print a worked example

  Publishing to the internet (WebShare)
    locnet-hub webshare             sites, their state, and the domain
    locnet-hub webshare domain <yourname.duckdns.org> -duckdns-token <t> -accept-tos
                                    turn it on (opens ports 80 and 443 here)
    locnet-hub webshare approve|off|on|remove <site>

  Backup hub
    locnet-hub serve -follow <addr> -follow-token <tok> -follow-fingerprint <fp>
                                    run as a standby: mirror a primary, serve nothing
    locnet-hub promote              promote the standby running here
    locnet-hub fingerprint          this hub's identity fingerprint, for -follow-fingerprint

  Operations
    locnet-hub alerts  [-quiet]     what is wrong right now
    locnet-hub health  [set ...]    alert thresholds and approval setting
    locnet-hub audit   [-n N]       membership and policy changes

    locnet-hub version

Run 'locnet-hub <command> -h' for the flags of one command.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(os.Args[2:])
	case "invite":
		err = cmdInvite(os.Args[2:])
	case "nodes":
		err = cmdNodes(os.Args[2:])
	case "invites":
		err = cmdInvites(os.Args[2:])
	case "revoke":
		err = cmdRevoke(os.Args[2:])
	case "remove":
		err = cmdRemove(os.Args[2:])
	case "approve":
		err = cmdApprove(os.Args[2:])
	case "admins", "admin":
		err = cmdAdmins(os.Args[2:])
	case "webshare", "web":
		err = cmdWebShare(os.Args[2:])
	case "policy":
		err = cmdPolicy(os.Args[2:])
	case "alerts":
		err = cmdAlerts(os.Args[2:])
	case "health":
		err = cmdHealth(os.Args[2:])
	case "audit":
		err = cmdAudit(os.Args[2:])
	case "promote":
		err = cmdPromote(os.Args[2:])
	case "fingerprint":
		err = cmdFingerprint(os.Args[2:])
	case "version":
		fmt.Println("locnet-hub", Version)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "locnet-hub: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "locnet-hub:", err)
		os.Exit(1)
	}
}

func statePath(dir string) string { return filepath.Join(dir, "hub.json") }

// ------------------------------------------------------------------ serve

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", ":8420", "address to listen on (TCP for the API, UDP for the relay)")
	advertise := fs.String("advertise", "", "comma-separated host:port addresses nodes should use to reach this hub, most specific first")
	stateDir := fs.String("state-dir", paths.HubStateDir(), "where to keep the network database")
	network := fs.String("network", "locnet", "network name, used on first run only")
	prefix := fs.String("prefix", hub.DefaultPrefix, "overlay address range, used on first run only")
	follow := fs.String("follow", "", "run as a standby, mirroring the primary hub at this address")
	followToken := fs.String("follow-token", "", "the primary's admin token, for -follow")
	followFP := fs.String("follow-fingerprint", "", "the primary's fingerprint (locnet-hub fingerprint on it), for -follow; "+
		"not needed once this standby holds a copy")
	followEvery := fs.Duration("follow-every", 0, "how often a standby re-copies the primary (default 1m)")
	standby := fs.String("standby", "", "comma-separated addresses of standby hubs, told to every node")
	webHTTP := fs.String("web-http", ":80", "WebShare: where to answer certificate challenges, once a domain is set")
	webHTTPS := fs.String("web-https", ":443", "WebShare: where to serve sites, once a domain is set")
	acmeDir := fs.String("acme-directory", "", "WebShare: ACME directory URL (default Let's Encrypt production)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	hub.Version = Version

	logf := func(format string, a ...any) { fmt.Printf(time.Now().Format("15:04:05 ")+format+"\n", a...) }

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// A standby does nothing but copy until it is promoted. It deliberately
	// does not answer nodes in the meantime: a spare serving an old register
	// while the primary is up and serving a current one would make which
	// answer a node gets a coin toss.
	if *follow != "" {
		if *followToken == "" {
			return fmt.Errorf("-follow needs -follow-token: the primary's admin token, " +
				"which is in admin-token inside its state directory")
		}
		m := &hub.Mirror{
			From: *follow, Token: *followToken, Path: statePath(*stateDir),
			Interval: *followEvery, Logf: logf,
		}
		if !strings.Contains(*follow, "://") {
			fp, err := hub.MirrorPin(statePath(*stateDir), *followFP)
			if err != nil {
				return err
			}
			m.Fingerprint = fp
			logf("hub: standby copies over TLS pinned to %x", fp)
		}
		logf("hub: standby for %s, copying every %s. Nothing is served until promotion.",
			*follow, followInterval(*followEvery))
		logf("hub: promote with:  locnet-hub promote -state-dir %s", *stateDir)
		if err := m.Run(ctx); err != nil {
			return nil // cancelled before promotion
		}
		logf("hub: promoted — now serving as the hub for this network")
	}

	store, err := hub.Open(statePath(*stateDir), *network, *prefix)
	if err != nil {
		return err
	}

	advAddrs, err := parseAdvertise(*advertise, *listen)
	if err != nil {
		return err
	}
	store.SetLogger(logf)
	relay := hub.NewRelay(store, logf)
	srv := hub.NewServer(store, relay, advAddrs, logf)
	if *standby != "" {
		srv.SetStandbyAddrs(splitList(*standby))
	}
	// TLS pinned to the hub's identity key, and plain HTTP on the same port
	// for this machine's own admin commands only.
	tcpLn, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("api: %w", err)
	}
	apiLn, err := srv.TLSListener(tcpLn)
	if err != nil {
		tcpLn.Close()
		return err
	}

	httpSrv := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// No WriteTimeout: netmap requests are long polls held open for
		// 25 seconds, and a write deadline would cut them short.
		IdleTimeout: 2 * time.Minute,
		ErrorLog:    log.New(quietHandshakes{os.Stderr}, "", log.LstdFlags),
	}

	errc := make(chan error, 2)
	go func() {
		if err := relay.ListenAndServe(ctx, *listen); err != nil {
			errc <- fmt.Errorf("relay: %w", err)
		}
	}()
	go func() {
		if err := httpSrv.Serve(apiLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- fmt.Errorf("api: %w", err)
		}
	}()

	net0 := store.Network()
	logf("hub: network %q on %s, advertising %s", net0.Name, net0.Prefix, strings.Join(advAddrs, ", "))
	logf("hub: fingerprint %x", store.HubKey().Public().Fingerprint())
	logf("hub: api on %s/tcp (TLS pinned to the fingerprint), relay on %s/udp", *listen, *listen)
	if *standby != "" {
		logf("hub: standby hubs advertised to every node: %s", *standby)
	}

	go checkAdvertised(ctx, advAddrs, store.HubKey().Public().Fingerprint(), logf)

	// WebShare opens nothing until a domain is configured
	// (locnet-hub webshare domain), and then 80 and 443.
	web := hub.NewWebServer(store, *stateDir, logf)
	web.HTTPAddr, web.HTTPSAddr, web.ACMEDirectory = *webHTTP, *webHTTPS, *acmeDir
	go web.Run(ctx)
	go store.WatchLiveness(ctx.Done())

	if len(store.Nodes()) == 0 {
		if err := printFirstRunInvite(srv, store); err != nil {
			logf("hub: could not mint a first join code: %v", err)
		}
	}

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		logf("hub: shutting down")
		// Every connected node is sitting in a 25-second long poll, and
		// Shutdown waits for in-flight requests to finish. Waiting for them
		// would make every restart take half a minute and risk the new
		// process finding the port still held. Give them a moment, then
		// close regardless — a node whose poll is cut short simply retries.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(shutdownCtx); err != nil {
			logf("hub: long polls still open, closing them")
			_ = httpSrv.Close()
		}
		// A clean shutdown is not a failure. Returning the deadline error
		// here made systemd log every restart as a crash.
		return nil
	}
}

// quietHandshakes drops net/http's "TLS handshake error" lines. The port is
// public, and every scanner that knocks on it, and every curl without -k,
// ends in one; a log of those buries anything worth reading.
type quietHandshakes struct{ w io.Writer }

func (q quietHandshakes) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "TLS handshake error") {
		return len(p), nil
	}
	return q.w.Write(p)
}

// checkAdvertised tries to reach the hub at each address it is telling nodes
// to use.
//
// This exists because a single mistyped digit cost an afternoon: 79.94.106.27
// instead of 203.0.113.27 is a perfectly well-formed address that no validator
// could reject, and the only symptom was joins timing out on machines
// elsewhere. The hub is in the best position to notice — it knows what it is
// claiming, and it can simply try it.
//
// A public address failing here is normal and not an error: most home routers
// will not let a machine reach its own public address from inside (no NAT
// hairpinning). What matters is that *something* answers, and that the
// operator is told which ones did not so they can check from outside.
//
// It knocks the way an agent does — TLS pinned to the hub's own fingerprint —
// so a success also proves the encrypted control plane works from there.
func checkAdvertised(ctx context.Context, addrs []string, fp [16]byte, logf func(string, ...any)) {
	// Let the listeners settle before knocking on the door.
	select {
	case <-ctx.Done():
		return
	case <-time.After(1500 * time.Millisecond):
	}

	client := &http.Client{Timeout: 4 * time.Second, Transport: hubtls.NewTransport(fp, nil)}
	var reached, missed []string

	for _, addr := range addrs {
		url := "https://" + stripScheme(addr) + "/healthz"
		if strings.Contains(addr, "://") {
			url = strings.TrimRight(addr, "/") + "/healthz"
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				reached = append(reached, addr)
				continue
			}
		}
		missed = append(missed, addr)
	}

	for _, a := range reached {
		logf("hub: reachable at %s", a)
	}
	if len(missed) == 0 {
		return
	}

	if len(reached) > 0 {
		logf("hub: could not reach itself at %s — normal if your router does not "+
			"hairpin, but check from another network that the port forward works",
			strings.Join(missed, ", "))
		return
	}
	// Nothing answered, including any LAN address. Something is actually wrong.
	logf("hub: WARNING: could not reach itself at ANY advertised address (%s).",
		strings.Join(missed, ", "))
	logf("hub: WARNING: join codes carry these addresses, so machines will fail to join.")
	logf("hub: WARNING: check LOCNET_ADVERTISE in /etc/locnet/hub.env and the firewall.")
}

// printFirstRunInvite mints a code on an empty network so the operator has
// something to paste without reading the manual first.
func printFirstRunInvite(srv *hub.Server, store *hub.Store) error {
	t, err := store.CreateToken("first run", 10, 24*time.Hour)
	if err != nil {
		return err
	}
	code, err := srv.JoinCodeFor(t.Token)
	if err != nil {
		return err
	}
	fmt.Printf(`
────────────────────────────────────────────────────────────────────────
 No machines have joined yet, so here is a join code.
 Good for 10 machines, expires in 24 hours.

   %s

 On each machine, once locnetd is installed and running:

   sudo locnet join %s

 Mint more with: locnet-hub invite
────────────────────────────────────────────────────────────────────────

`, code, code)
	return nil
}

// parseAdvertise turns the -advertise flag into the ordered list that goes
// into every join code.
//
// Several addresses are the normal case, not an edge case. A hub behind NAT
// has a LAN address its neighbours use and a public address everyone else
// uses, and a router that will not hairpin means neither works from both
// sides — including for the hub's own agent. Listing both, most specific
// first, is what lets one code work from anywhere.
func parseAdvertise(flagValue, listen string) ([]string, error) {
	if strings.TrimSpace(flagValue) == "" {
		guess, err := guessAdvertise(listen)
		if err != nil {
			return nil, fmt.Errorf("could not work out what address to advertise; pass -advertise host:port (%w)", err)
		}
		fmt.Fprintf(os.Stderr, "locnet-hub: no -advertise given, using %s\n"+
			"            If your machines are on other networks, this must be an address they can reach.\n"+
			"            You can list several, e.g. -advertise 203.0.113.9:8420,192.168.1.64:8420\n\n", guess)
		return []string{guess}, nil
	}

	var out []string
	seen := map[string]bool{}
	for _, part := range strings.Split(flagValue, ",") {
		addr := strings.TrimSpace(part)
		if addr == "" {
			continue
		}
		if err := validateAdvertise(addr); err != nil {
			return nil, err
		}
		if seen[addr] {
			continue
		}
		seen[addr] = true
		out = append(out, addr)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("-advertise is empty")
	}
	if len(out) > 8 {
		return nil, fmt.Errorf("-advertise lists %d addresses; 8 is the most a join code can carry", len(out))
	}
	return out, nil
}

// validateAdvertise refuses an address that cannot possibly work.
//
// This exists because the hub used to accept anything. An unedited placeholder
// like "<your ip>:8420" started a perfectly healthy-looking server that minted
// join codes pointing at nonsense, and the failure only surfaced later on a
// different machine as an unexplainable connection error. Better to refuse at
// the point the mistake was made.
func validateAdvertise(addr string) error {
	bad := func(why string) error {
		return fmt.Errorf("-advertise %q %s.\n"+
			"It must be the host:port your other machines will use to reach this hub, "+
			"for example 192.168.1.64:8420 or hub.example.org:8420.\n"+
			"Set LOCNET_ADVERTISE in /etc/locnet/hub.env", addr, why)
	}

	if strings.ContainsAny(addr, "<>\"' \t") {
		return bad("still contains placeholder punctuation — the angle brackets or quotes are not part of the address")
	}
	if strings.Contains(strings.ToUpper(addr), "CHANGE-ME") {
		return bad("is the unedited default")
	}

	host, port, err := net.SplitHostPort(stripScheme(addr))
	if err != nil {
		return bad("is not a host:port")
	}
	if host == "" {
		return bad("has no host part")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return bad("has no usable port")
	}

	// A loopback address is syntactically fine and useless: no other machine
	// can reach it. Warn rather than refuse — it is legitimate for a
	// single-machine smoke test.
	if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() {
		fmt.Fprintf(os.Stderr,
			"locnet-hub: warning: advertising %s, which only this machine can reach.\n"+
				"            No other computer will be able to join.\n\n", addr)
	}
	return nil
}

func stripScheme(s string) string {
	if i := strings.Index(s, "://"); i >= 0 {
		return s[i+3:]
	}
	return s
}

// guessAdvertise finds the address a node on another network would most
// plausibly use. It is a guess, and it is wrong behind NAT — which is exactly
// why -advertise exists.
func guessAdvertise(listen string) (string, error) {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", err
	}
	// Connecting a UDP socket sends nothing but makes the kernel pick the
	// source address it would use for a route off this machine.
	c, err := net.Dial("udp", "192.0.2.1:9")
	if err != nil {
		return "", err
	}
	defer c.Close()
	host, _, err := net.SplitHostPort(c.LocalAddr().String())
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(host, port), nil
}

// ------------------------------------------------------------------ admin

// adminClient talks to a running hub's admin API.
type adminClient struct {
	base  string
	token string
	hc    *http.Client
}

func newAdminClient(fs *flag.FlagSet, args []string) (*adminClient, error) {
	hubURL := fs.String("hub", "http://127.0.0.1:8420", "hub API address")
	stateDir := fs.String("state-dir", paths.HubStateDir(), "hub state directory, used to read the admin token")
	token := fs.String("token", os.Getenv("LOCNET_HUB_ADMIN_TOKEN"), "admin token (defaults to the one in the state directory)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	tok := *token
	if tok == "" {
		raw, err := os.ReadFile(statePath(*stateDir))
		if err != nil {
			return nil, fmt.Errorf("no admin token given and %s is unreadable: %w", statePath(*stateDir), err)
		}
		var st struct {
			AdminToken string `json:"admin_token"`
		}
		if err := json.Unmarshal(raw, &st); err != nil {
			return nil, fmt.Errorf("reading admin token from %s: %w", statePath(*stateDir), err)
		}
		tok = st.AdminToken
	}
	return &adminClient{
		base:  strings.TrimRight(*hubURL, "/"),
		token: tok,
		hc:    &http.Client{Timeout: 15 * time.Second},
	}, nil
}

// doWithRetry rides out a hub that is starting.
//
// The service is Type=simple, so `systemctl restart locnet-hub` returns as
// soon as the process forks — before it has bound the port. Anything chained
// after it with && would otherwise fail with "connection refused" against a
// hub that is perfectly fine a few milliseconds later.
func (c *adminClient) doWithRetry(req *http.Request, body string) (*http.Response, error) {
	const attempts = 10
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			// Requests may be replayed, so rebuild the body each time.
			req.Body = io.NopCloser(strings.NewReader(body))
		}
		resp, err := c.hc.Do(req)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if !errors.Is(err, syscall.ECONNREFUSED) {
			return nil, err
		}
		time.Sleep(300 * time.Millisecond)
	}
	return nil, lastErr
}

func (c *adminClient) call(method, path string, in, out any) error {
	body := ""
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = string(raw)
	}
	req, err := http.NewRequest(method, c.base+hubapi.APIVersion+path, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doWithRetry(req, body)
	if err != nil {
		return fmt.Errorf("cannot reach the hub at %s: %w (is `locnet-hub serve` running?)", c.base, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		var er hubapi.ErrorResponse
		if json.NewDecoder(resp.Body).Decode(&er) == nil && er.Error != "" {
			return errors.New(er.Error)
		}
		return fmt.Errorf("hub returned %s", resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func cmdInvite(args []string) error {
	fs := flag.NewFlagSet("invite", flag.ExitOnError)
	label := fs.String("label", "", "note to remember what this code was for")
	uses := fs.Int("uses", 1, "how many machines may use it; -1 for unlimited")
	ttl := fs.String("ttl", "24h", "how long it stays valid, e.g. 24h or 30m; empty for no expiry")
	c, err := newAdminClient(fs, args)
	if err != nil {
		return err
	}

	var resp hub.InviteResponse
	if err := c.call(http.MethodPost, "/admin/invite",
		hub.InviteRequest{Label: *label, Uses: *uses, TTL: *ttl}, &resp); err != nil {
		return err
	}

	fmt.Printf("\n  %s\n\n", resp.Code)
	fmt.Printf("  uses:    %s\n", usesText(resp.Uses))
	if resp.ExpiresAt.IsZero() {
		fmt.Printf("  expires: never\n")
	} else {
		fmt.Printf("  expires: %s\n", resp.ExpiresAt.Format(time.RFC1123))
	}
	fmt.Printf("\n  On the machine that should join:  sudo locnet join %s\n\n", resp.Code)
	return nil
}

func cmdNodes(args []string) error {
	fs := flag.NewFlagSet("nodes", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print raw JSON")
	c, err := newAdminClient(fs, args)
	if err != nil {
		return err
	}

	var rows []struct {
		hub.Node
		Online bool     `json:"online"`
		Groups []string `json:"groups"`
		Relay  string   `json:"relay_addr"`
	}
	if err := c.call(http.MethodGet, "/admin/nodes", nil, &rows); err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rows)
	}
	if len(rows) == 0 {
		fmt.Println("No machines have joined yet. Mint a code with: locnet-hub invite")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tADDRESS\tOS\tSTATUS\tGROUPS\tDISK\tLAST SEEN")
	waiting := 0
	for _, r := range rows {
		status := "offline"
		if r.Online {
			status = "online"
		}
		if !r.Approved {
			status = "WAITING"
			waiting++
		}
		groups := strings.Join(r.Groups, ",")
		if groups == "" {
			groups = "-"
		}
		disk := "-"
		if r.Stats.DiskTotalGB > 0 {
			disk = fmt.Sprintf("%dG free", r.Stats.DiskFreeGB)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Name, r.IP, r.OS, status, groups, disk, humanAge(r.LastSeen))
	}
	w.Flush()
	if waiting > 0 {
		fmt.Printf("\n  %d machine(s) waiting for approval. Admit one with: locnet-hub approve <name>\n", waiting)
	}
	return nil
}

func cmdInvites(args []string) error {
	fs := flag.NewFlagSet("invites", flag.ExitOnError)
	c, err := newAdminClient(fs, args)
	if err != nil {
		return err
	}
	var tokens []hub.JoinToken
	if err := c.call(http.MethodGet, "/admin/invites", nil, &tokens); err != nil {
		return err
	}
	if len(tokens) == 0 {
		fmt.Println("No join codes have been issued.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TOKEN\tLABEL\tUSES LEFT\tSTATUS\tCREATED")
	for _, t := range tokens {
		status := "active"
		if err := t.Valid(time.Now()); err != nil {
			status = "spent/revoked"
		}
		label := t.Label
		if label == "" {
			label = "-"
		}
		fmt.Fprintf(w, "%s…\t%s\t%s\t%s\t%s\n",
			t.Token[:8], label, usesText(t.Uses), status, humanAge(t.CreatedAt))
	}
	w.Flush()
	fmt.Println("\nRevoke one with: locnet-hub revoke <first characters of TOKEN>")
	return nil
}

func cmdRevoke(args []string) error {
	pos, flags := splitArgs(args)
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	c, err := newAdminClient(fs, flags)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: locnet-hub revoke <first characters of the token>")
	}
	if err := c.call(http.MethodPost, "/admin/revoke", map[string]string{"token": pos[0]}, nil); err != nil {
		return err
	}
	fmt.Println("Revoked. Machines that already joined with it are unaffected.")
	return nil
}

func cmdRemove(args []string) error {
	pos, flags := splitArgs(args)
	fs := flag.NewFlagSet("remove", flag.ExitOnError)
	c, err := newAdminClient(fs, flags)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: locnet-hub remove <node name>")
	}
	if err := c.call(http.MethodPost, "/admin/remove", map[string]string{"node": pos[0]}, nil); err != nil {
		return err
	}
	fmt.Printf("Removed %s. Its peers will drop it within a few seconds.\n", pos[0])
	return nil
}

// runInteractive hands the terminal to another program, for $EDITOR.
func runInteractive(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

func usesText(n int) string {
	if n < 0 {
		return "unlimited"
	}
	return fmt.Sprintf("%d", n)
}

func humanAge(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return t.Format("2006-01-02 15:04")
	}
}

// ---------------------------------------------------------------- promote

func cmdPromote(args []string) error {
	fs := flag.NewFlagSet("promote", flag.ExitOnError)
	stateDir := fs.String("state-dir", paths.HubStateDir(), "the standby's state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		return err
	}
	marker := filepath.Join(*stateDir, hub.StandbyMarker)
	if err := os.WriteFile(marker, []byte(time.Now().Format(time.RFC3339)+"\n"), 0o600); err != nil {
		return err
	}
	fmt.Println("Promotion requested. The standby running here takes over within a few seconds.")
	fmt.Println()
	fmt.Println("Be sure the primary is really down first. Two hubs signing maps for one")
	fmt.Println("network will disagree about who is a member, and the disagreement is not")
	fmt.Println("visible until something stops working.")
	return nil
}

// --------------------------------------------------------- fingerprint

// cmdFingerprint prints the 16-byte fingerprint every join code pins, for a
// standby's -follow-fingerprint. It reads the state file rather than asking
// the running hub, so it works with the hub stopped.
func cmdFingerprint(args []string) error {
	fs := flag.NewFlagSet("fingerprint", flag.ExitOnError)
	stateDir := fs.String("state-dir", paths.HubStateDir(), "the hub's state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	raw, err := os.ReadFile(statePath(*stateDir))
	if err != nil {
		return fmt.Errorf("%w (run as root, or pass -state-dir)", err)
	}
	var st hub.State
	if err := json.Unmarshal(raw, &st); err != nil {
		return fmt.Errorf("reading %s: %w", statePath(*stateDir), err)
	}
	if st.HubKey.IsZero() {
		return fmt.Errorf("%s holds no hub key — has the hub ever run?", statePath(*stateDir))
	}
	fmt.Printf("%x\n", st.HubKey.Public().Fingerprint())
	return nil
}

// followInterval renders the standby's copy interval for the startup banner.
func followInterval(d time.Duration) string {
	if d <= 0 {
		return "1m0s"
	}
	return d.String()
}

// splitList turns a comma-separated flag into a trimmed list.
func splitList(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
