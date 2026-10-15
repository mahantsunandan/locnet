package hub

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// RenderWebShare prints the view for people; both CLIs use it.
func RenderWebShare(out io.Writer, v WebShareView) {
	if v.Domain == "" {
		fmt.Fprintln(out, "\nWebShare is off: no domain is set, and nothing listens on 80 or 443.")
	} else {
		fmt.Fprintf(out, "\nDomain   %s\n", v.Domain)
		switch {
		case !v.DuckDNS:
			fmt.Fprintln(out, "DNS      not updated by the hub (no DuckDNS token)")
		case v.DNS.Error != "":
			fmt.Fprintf(out, "DNS      ✗ %s\n", v.DNS.Error)
		case v.DNS.IP != "":
			fmt.Fprintf(out, "DNS      ✓ points at %s (checked %s)\n", v.DNS.IP, v.DNS.At.Format("15:04"))
		default:
			fmt.Fprintln(out, "DNS      not checked yet")
		}
	}
	fmt.Fprintln(out)
	if len(v.Sites) == 0 {
		fmt.Fprintln(out, "No site has been asked for. On the machine serving it: locnet webshare add <site> <port>")
		return
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SITE\tMACHINE\tSERVES\tSTATE\tREQUESTS\tADDRESS")
	for _, s := range v.Sites {
		addr := s.URL
		if addr == "" {
			addr = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\n", s.Name, s.Machine, orDash(s.Target), s.State, s.Requests, addr)
	}
	tw.Flush()
	for _, s := range v.Sites {
		if s.LastError != "" {
			fmt.Fprintf(out, "\n%s last failed at %s\n", s.Name, s.LastError)
		}
	}
	var waiting []string
	for _, s := range v.Sites {
		if s.State == SiteWaiting {
			waiting = append(waiting, s.Name)
		}
	}
	if len(waiting) > 0 {
		fmt.Fprintf(out, "\nWaiting for approval: %s — approve with: locnet admin webshare approve <site>\n", strings.Join(waiting, ", "))
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
