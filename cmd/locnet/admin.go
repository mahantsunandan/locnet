package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/mahantsunandan/locnet/internal/hub"
	"github.com/mahantsunandan/locnet/internal/ipc"
)

const adminUsage = `Usage:
  locnet admin                         every machine on the network, as the hub sees it
  locnet admin invite [flags]          a join code for a new machine
  locnet admin invites                 join codes, and which still work
  locnet admin revoke <id>             stop a join code working
  locnet admin remove <machine>        take a machine off the network
  locnet admin approve <machine>       admit a machine that is waiting
  locnet admin audit                   who joined, left and changed what
  locnet admin access                  who may connect to whom; block or allow
                                       one machine's connections to another.
                                       locnet admin access -h
  locnet admin webshare                public sites: approve, off, on, remove

Flags for invite:
  -uses N      how many machines may use it (default 1; -1 for unlimited)
  -ttl 24h     how long it stays valid (default 24h; "0" for no expiry)
  -label text  a note to recognise it by

These are signed with this machine's own key, so they work only on a machine
the hub has made an administrator. On the hub machine:
  sudo locnet-hub admins add <this machine>`

func cmdAdmin(args []string) error {
	pos, flags := splitArgs(args)
	sub := ""
	if len(pos) > 0 {
		sub, pos = pos[0], pos[1:]
	}
	switch sub {
	case "", "nodes", "machines", "list":
		return adminNodes()
	case "invite":
		return adminInvite(flags)
	case "invites", "codes":
		return adminInvites()
	case "revoke":
		if len(pos) != 1 {
			return errors.New("usage: locnet admin revoke <id>   (the ID from locnet admin invites)")
		}
		return adminPost("revoke", map[string]string{"id": pos[0]},
			fmt.Sprintf("Join code %s no longer works. Machines that used it stay joined.", pos[0]))
	case "remove", "rm", "forget":
		return adminRemove(pos, flags)
	case "approve":
		if len(pos) != 1 {
			return errors.New("usage: locnet admin approve <machine>")
		}
		return adminPost("approve", map[string]string{"node": pos[0]},
			fmt.Sprintf("%s is now on the network.", pos[0]))
	case "audit", "log":
		return adminAudit()
	case "access":
		// Not splitArgs: service names and "*" are positional here, and
		// nothing in them is a flag.
		return cmdAccess(args[1:])
	case "webshare", "web":
		return adminWebShare(args[1:])
	case "-h", "--help", "help":
		fmt.Println(adminUsage)
		return nil
	default:
		return fmt.Errorf("unknown admin command %q\n\n%s", sub, adminUsage)
	}
}

func manageCall(op string, in, out any) error {
	c, err := ipc.Dial()
	if err != nil {
		return err
	}
	return c.Post("/manage/"+op, in, out)
}

func adminPost(op string, in any, okMsg string) error {
	if err := manageCall(op, in, nil); err != nil {
		return err
	}
	fmt.Println(okMsg)
	return nil
}

func adminNodes() error {
	var rows []hub.NodeRow
	if err := manageCall("nodes", map[string]string{}, &rows); err != nil {
		return err
	}
	if len(rows) == 0 {
		fmt.Println("No machines have joined yet. Make a code with: locnet admin invite")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "MACHINE\tADDRESS\tOS\tSTATE\tLAST SEEN\tROLE")
	waiting := 0
	for _, r := range rows {
		state := "offline"
		if r.Online {
			state = "online"
		}
		if !r.Approved {
			state = "WAITING"
			waiting++
		}
		var role []string
		if r.Hub {
			role = append(role, "hub")
		}
		if r.Admin {
			role = append(role, "admin")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", r.Name, r.IP, orDash(r.OS), state,
			ago(r.LastSeen), orDash(strings.Join(role, ",")))
	}
	w.Flush()
	if waiting > 0 {
		fmt.Printf("\n  %d machine(s) waiting. Admit one with: locnet admin approve <machine>\n", waiting)
	}
	return nil
}

func adminInvite(args []string) error {
	fs := flag.NewFlagSet("admin invite", flag.ExitOnError)
	uses := fs.Int("uses", 1, "how many machines may use it; -1 for unlimited")
	ttl := fs.String("ttl", "24h", `how long it stays valid; "0" for no expiry`)
	label := fs.String("label", "", "a note to recognise it by")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *ttl == "0" {
		*ttl = ""
	}
	var out hub.InviteResponse
	if err := manageCall("invite", hub.InviteRequest{Label: *label, Uses: *uses, TTL: *ttl}, &out); err != nil {
		return err
	}
	fmt.Printf("\n  %s\n\n", out.Code)
	fmt.Printf("  good for  %s\n", usesWord(out.Uses))
	if out.ExpiresAt.IsZero() {
		fmt.Println("  expires   never")
	} else {
		fmt.Printf("  expires   %s\n", out.ExpiresAt.Local().Format("Mon 2 Jan 15:04"))
	}
	fmt.Println("\n  On the new machine, after installing LocNet:")
	fmt.Printf("    sudo locnet join %s\n", out.Code)
	fmt.Printf("  or, from an unpacked release, in one step:\n")
	fmt.Printf("    sudo ./install.sh --join %s\n\n", out.Code)
	return nil
}

func adminInvites() error {
	var rows []hub.InviteRow
	if err := manageCall("invites", map[string]string{}, &rows); err != nil {
		return err
	}
	if len(rows) == 0 {
		fmt.Println("No join codes have been made.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tLABEL\tUSES LEFT\tSTATE\tMADE")
	for _, r := range rows {
		state, left := "works", usesWord(r.Uses)
		if !r.Active {
			state, left = "spent, expired or revoked", "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", r.ID, orDash(r.Label), left, state, ago(r.CreatedAt))
	}
	w.Flush()
	fmt.Println("\n  Stop one working with: locnet admin revoke <ID>")
	return nil
}

func adminRemove(pos, flags []string) error {
	fs := flag.NewFlagSet("admin remove", flag.ExitOnError)
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: locnet admin remove <machine> [-yes]")
	}
	name := pos[0]
	if !*yes {
		fmt.Printf("%s will be taken off the network. It keeps nothing it could rejoin with;\n"+
			"bringing it back needs a new join code. Type the machine's name to continue: ", name)
		var answer string
		fmt.Scanln(&answer)
		if strings.TrimSpace(answer) != name {
			return errors.New("cancelled")
		}
	}
	return adminPost("remove", map[string]string{"node": name},
		fmt.Sprintf("Removed %s. The other machines drop it within a few seconds.", name))
}

func adminAudit() error {
	var entries []hub.AuditEntry
	if err := manageCall("audit", map[string]int{"limit": 40}, &entries); err != nil {
		return err
	}
	if len(entries) == 0 {
		fmt.Println("Nothing has happened yet.")
		return nil
	}
	for _, e := range entries {
		fmt.Println(e.Describe())
	}
	return nil
}

func usesWord(n int) string {
	switch {
	case n < 0:
		return "any number of machines"
	case n == 1:
		return "1 machine"
	default:
		return fmt.Sprintf("%d machines", n)
	}
}

// ago renders a past moment the way a person would say it.
func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}
