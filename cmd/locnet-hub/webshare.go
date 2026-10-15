package main

import (
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/mahantsunandan/locnet/internal/hub"
)

const webShareUsage = `Usage:
  locnet-hub webshare                       sites, their state, and the domain
  locnet-hub webshare domain <name> -accept-tos [-duckdns-token <token>] [-email <addr>]
                                            publish sites under <name>
  locnet-hub webshare domain -off           stop: forget the domain and the token
  locnet-hub webshare approve <site> [-machine <m>]
  locnet-hub webshare off|on|remove <site>

<name> is a domain that points at this machine — for a home connection, a
free dynamic DNS name such as yourname.duckdns.org. With -duckdns-token the
hub keeps that name pointing at this house itself. Sites are then
https://<site>.<name>.

Certificates come from Let's Encrypt, which needs agreement to their
subscriber agreement: https://letsencrypt.org/repository/ — -accept-tos says
you agree. The router must forward TCP 80 and 443 to this machine, and its
firewall must let them in.`

func cmdWebShare(args []string) error {
	pos, flags := splitArgs(args)
	sub := ""
	if len(pos) > 0 {
		sub, pos = pos[0], pos[1:]
	}
	fs := flag.NewFlagSet("webshare", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, webShareUsage) }
	token := fs.String("duckdns-token", "", "DuckDNS token, to keep the name pointing here")
	email := fs.String("email", "", "address Let's Encrypt may write to about certificates")
	accept := fs.Bool("accept-tos", false, "agree to Let's Encrypt's subscriber agreement")
	off := fs.Bool("off", false, "with domain: turn WebShare off")
	machine := fs.String("machine", "", "with approve: which machine, when several ask for the name")
	c, err := newAdminClient(fs, flags)
	if err != nil {
		return err
	}

	var v hub.WebShareView
	switch sub {
	case "", "show", "list":
		if err := c.call(http.MethodGet, "/admin/webshare", nil, &v); err != nil {
			return err
		}
	case "domain":
		req := hub.SiteChange{Action: "domain", DuckDNSToken: *token, Email: *email, AcceptTOS: *accept}
		switch {
		case *off:
		case len(pos) == 1:
			req.Domain = pos[0]
		default:
			return errors.New(webShareUsage)
		}
		if err := c.call(http.MethodPost, "/admin/webshare", req, &v); err != nil {
			return err
		}
		if req.Domain == "" {
			fmt.Println("WebShare is off: sites stop answering now, and ports 80 and 443 close at the hub's next restart.")
		} else {
			fmt.Printf("Sites will be published as https://<site>.%s\n", req.Domain)
			fmt.Println("Within 15 seconds the hub listens on 80 and 443. Forward both from the router to this machine.")
		}
	case "approve", "off", "on", "remove":
		if len(pos) != 1 {
			return errors.New(webShareUsage)
		}
		req := hub.SiteChange{Action: sub, Name: pos[0], Machine: *machine}
		if err := c.call(http.MethodPost, "/admin/webshare", req, &v); err != nil {
			return err
		}
	case "-h", "help":
		fmt.Println(webShareUsage)
		return nil
	default:
		return fmt.Errorf("unknown webshare command %q\n\n%s", sub, webShareUsage)
	}
	hub.RenderWebShare(os.Stdout, v)
	return nil
}
