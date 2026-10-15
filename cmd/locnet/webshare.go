package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/mahantsunandan/locnet/internal/hub"
	"github.com/mahantsunandan/locnet/internal/ipc"
	"github.com/mahantsunandan/locnet/internal/resource"
)

const webShareUsage = `Usage:
  locnet webshare                         this machine's sites and their state
  locnet webshare add <site> <port>       ask to publish http://localhost:<port>
                                          as https://<site>.<the hub's domain>
  locnet webshare remove <site>           stop publishing it

Flags for add:
  -on <port>   overlay port the hub reaches it on (default: first free from 8430)

The service keeps listening on this machine only; the hub reaches it through
the tunnel and handles HTTPS and certificates. Nothing is public until an
administrator approves the name on the hub:
  locnet admin webshare approve <site>

Only HTTPS is published, and only the one port. Visitors see the hub's public
address, not this machine's.`

func cmdWebShare(args []string) error {
	if len(args) == 0 {
		return webShareShow()
	}
	switch args[0] {
	case "add":
		return webShareAdd(args[1:])
	case "remove", "rm":
		if len(args) != 2 {
			return errors.New("usage: locnet webshare remove <site>")
		}
		return webShareRemove(args[1])
	case "-h", "--help", "help":
		fmt.Println(webShareUsage)
		return nil
	default:
		return fmt.Errorf("unknown webshare command %q\n\n%s", args[0], webShareUsage)
	}
}

const (
	sitePortFirst = 8430
	sitePortLast  = 8499
)

func siteShareName(site string) string { return "web-" + site }

func webShareAdd(args []string) error {
	fs := flag.NewFlagSet("webshare add", flag.ExitOnError)
	on := fs.Uint("on", 0, "overlay port the hub reaches the site on")
	pos, flags := splitArgs(args)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 2 {
		return errors.New("usage: locnet webshare add <site> <port>   e.g. locnet webshare add myapp 3000")
	}
	site := strings.ToLower(pos[0])
	if err := resource.ValidSiteName(site); err != nil {
		return err
	}
	target, err := siteTarget(pos[1])
	if err != nil {
		return err
	}

	st, err := status()
	if err != nil {
		return err
	}
	// The hub's proxy connects from the hub machine, so that machine — and
	// nobody else on the network — may use the share.
	hubMachine := ""
	if st.IsHub {
		hubMachine = st.Name
	}
	for _, p := range st.Peers {
		if p.Hub {
			hubMachine = p.Name
		}
	}
	if hubMachine == "" {
		return errors.New("the hub machine is not a member of this network, so it has no way to reach a site here.\n" +
			"Install LocNet on the hub machine too (deploy.sh --hub does both)")
	}

	port := uint16(*on)
	used := map[uint16]bool{}
	for _, sh := range st.Shares {
		if sh.Kind == resource.KindPort && sh.Name != siteShareName(site) {
			used[sh.Port] = true
		}
	}
	if port == 0 {
		for p := uint16(sitePortFirst); p <= sitePortLast; p++ {
			if !used[p] && portFree(st.IP.String(), p) {
				port = p
				break
			}
		}
		if port == 0 {
			return fmt.Errorf("no free overlay port between %d and %d; pick one with -on", sitePortFirst, sitePortLast)
		}
	} else if used[port] {
		return fmt.Errorf("overlay port %d is already used by another share", port)
	}

	sh := resource.Share{
		Name: siteShareName(site), Kind: resource.KindPort, Target: target, Port: port,
		Allow: []string{hubMachine}, Web: site,
		Description: "WebShare site " + site,
	}
	c, err := ipc.Dial()
	if err != nil {
		return err
	}
	if err := c.Post("/share/add", sh, nil); err != nil {
		return err
	}
	fmt.Printf("Asked the hub to publish %s (on this machine) as site %q.\n", target, site)
	fmt.Println("Nothing is public until an administrator approves it on the hub:")
	fmt.Printf("    locnet admin webshare approve %s\n", site)
	fmt.Println("Check its state with:  locnet webshare")
	return nil
}

// siteTarget accepts "3000", ":3000" or "host:3000". A bare port is this
// machine's loopback, where a development server usually listens.
func siteTarget(arg string) (string, error) {
	arg = strings.TrimPrefix(arg, ":")
	if _, err := strconv.ParseUint(arg, 10, 16); err == nil {
		return "127.0.0.1:" + arg, nil
	}
	if _, p, err := net.SplitHostPort(arg); err == nil {
		if _, err := strconv.ParseUint(p, 10, 16); err == nil {
			return arg, nil
		}
	}
	return "", fmt.Errorf("%q is not a port, or host:port", arg)
}

// portFree reports whether nothing holds the overlay port already — a server
// listening on every address would collide with the share's listener.
func portFree(ip string, port uint16) bool {
	ln, err := net.Listen("tcp", net.JoinHostPort(ip, strconv.Itoa(int(port))))
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

func webShareRemove(site string) error {
	c, err := ipc.Dial()
	if err != nil {
		return err
	}
	if err := c.Post("/share/remove", map[string]string{"name": siteShareName(strings.ToLower(site))}, nil); err != nil {
		return err
	}
	fmt.Printf("%s is no longer published. The hub stops answering for it within seconds.\n", site)
	return nil
}

func webShareShow() error {
	st, err := status()
	if err != nil {
		return err
	}
	byName := map[string]resource.SiteStatus{}
	for _, s := range st.Sites {
		byName[s.Name] = s
	}
	var rows [][]string
	for _, sh := range st.Shares {
		if sh.Web == "" {
			continue
		}
		s := byName[sh.Web]
		state, addr := s.State, s.URL
		if state == "" {
			state = "not seen by the hub yet"
		}
		if addr == "" {
			addr = "-"
		}
		rows = append(rows, []string{sh.Web, sh.Target, state, addr})
	}
	if len(rows) == 0 {
		fmt.Println("This machine publishes no sites.")
		fmt.Println("\n" + webShareUsage)
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SITE\tSERVES\tSTATE\tADDRESS")
	for _, r := range rows {
		fmt.Fprintln(tw, strings.Join(r, "\t"))
	}
	return tw.Flush()
}

// ----------------------------------------------------------------- admin

func adminWebShare(args []string) error {
	pos, flags := splitArgs(args)
	fs := flag.NewFlagSet("admin webshare", flag.ExitOnError)
	machine := fs.String("machine", "", "which machine, when several ask for the name")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	req := hub.SiteChange{Machine: *machine}
	switch {
	case len(pos) == 0:
	case len(pos) == 2 && (pos[0] == "approve" || pos[0] == "off" || pos[0] == "on" || pos[0] == "remove"):
		req.Action, req.Name = pos[0], strings.ToLower(pos[1])
	case pos[0] == "domain":
		return errors.New("the domain and DNS token are set on the hub machine itself:\n" +
			"    sudo locnet-hub webshare domain <yourname.duckdns.org> -duckdns-token <token> -accept-tos")
	default:
		return errors.New("usage: locnet admin webshare [approve|off|on|remove <site>] [-machine <m>]")
	}
	var v hub.WebShareView
	if err := manageCall("webshare", req, &v); err != nil {
		return err
	}
	hub.RenderWebShare(os.Stdout, v)
	return nil
}
