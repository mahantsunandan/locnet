package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/mahantsunandan/locnet/internal/hub"
	"github.com/mahantsunandan/locnet/internal/policy"
)

// splitArgs separates positional arguments from flags.
//
// Go's flag package stops parsing at the first non-flag argument, so
// "policy set file.json -hub http://…" would silently ignore -hub and talk to
// the default hub instead. Pulling the positionals out first means the
// documented argument order actually works.
func splitArgs(args []string) (positional, flags []string) {
	for i, a := range args {
		if strings.HasPrefix(a, "-") {
			return positional, args[i:]
		}
		positional = append(positional, a)
	}
	return positional, nil
}

// ------------------------------------------------------------------ policy

const policyUsage = `Usage:
  locnet-hub policy                    show the current access policy
  locnet-hub policy edit               open it in $EDITOR and apply on save
  locnet-hub policy set <file.json>    replace it from a file
  locnet-hub policy example            print a worked example to start from

The policy names groups of machines and lists which groups may reach which.
Machines the policy does not connect never appear in each other's network map,
so the isolation is enforced by WireGuard rather than by a firewall rule.`

func cmdPolicy(args []string) error {
	if len(args) > 0 && args[0] == "example" {
		fmt.Print(policyExample)
		return nil
	}

	pos, flags := splitArgs(args)
	sub := ""
	if len(pos) > 0 {
		sub, pos = pos[0], pos[1:]
	}

	fs := flag.NewFlagSet("policy", flag.ExitOnError)
	c, err := newAdminClient(fs, flags)
	if err != nil {
		return err
	}

	switch sub {
	case "", "show":
		var p policy.Policy
		if err := c.call(http.MethodGet, "/admin/policy", nil, &p); err != nil {
			return err
		}
		fmt.Print(p.Summary())
		return nil

	case "set":
		if len(pos) != 1 {
			return errors.New("usage: locnet-hub policy set <file.json>")
		}
		raw, err := os.ReadFile(pos[0])
		if err != nil {
			return err
		}
		var p policy.Policy
		if err := json.Unmarshal(raw, &p); err != nil {
			return fmt.Errorf("%s is not valid JSON: %w", pos[0], err)
		}
		if err := p.Validate(); err != nil {
			return err
		}
		var applied policy.Policy
		if err := c.call(http.MethodPost, "/admin/policy", p, &applied); err != nil {
			return err
		}
		fmt.Print("Policy applied. Every machine picks it up within seconds.\n\n")
		fmt.Print(applied.Summary())
		return nil

	case "edit":
		return editPolicy(c)

	default:
		return fmt.Errorf("unknown policy command %q\n\n%s", sub, policyUsage)
	}
}

// editPolicy round-trips the policy through $EDITOR.
func editPolicy(c *adminClient) error {
	var p policy.Policy
	if err := c.call(http.MethodGet, "/admin/policy", nil, &p); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}

	f, err := os.CreateTemp("", "locnet-policy-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(append(raw, '\n')); err != nil {
		f.Close()
		return err
	}
	f.Close()

	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "nano"
	}
	if err := runInteractive(editor, f.Name()); err != nil {
		return fmt.Errorf("editor: %w", err)
	}

	edited, err := os.ReadFile(f.Name())
	if err != nil {
		return err
	}
	var next policy.Policy
	if err := json.Unmarshal(edited, &next); err != nil {
		return fmt.Errorf("the edited policy is not valid JSON (%w) — nothing was changed", err)
	}
	if err := next.Validate(); err != nil {
		return fmt.Errorf("%w — nothing was changed", err)
	}

	var applied policy.Policy
	if err := c.call(http.MethodPost, "/admin/policy", next, &applied); err != nil {
		return err
	}
	fmt.Print("Policy applied.\n\n")
	fmt.Print(applied.Summary())
	return nil
}

const policyExample = `{
  "groups": {
    "field-units":   ["unit-01", "unit-02", "unit-03", "unit-04"],
    "operators":  ["workstation", "laptop"],
    "monitoring": ["collector"]
  },
  "rules": [
    {
      "src": ["operators"],
      "dst": ["field-units"],
      "ports": ["*"],
      "comment": "operators get full access to every field unit"
    },
    {
      "src": ["monitoring"],
      "dst": ["field-units"],
      "ports": ["8421"],
      "comment": "the collector may read shares and nothing else"
    },
    {
      "src": ["operators"],
      "dst": ["operators"],
      "comment": "operators can reach each other"
    }
  ]
}

Note what this policy does NOT contain: any rule between two field-units. They
therefore never appear in each other's network map and cannot reach each other
at all — which is usually what you want for unattended machines, and is the
single most valuable thing a policy can do for you.

Save it to a file and apply with:  locnet-hub policy set policy.json
`

// ------------------------------------------------------------------ alerts

func cmdAlerts(args []string) error {
	fs := flag.NewFlagSet("alerts", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print raw JSON")
	quiet := fs.Bool("quiet", false, "print nothing when all is well; exit 1 when it is not")
	c, err := newAdminClient(fs, args)
	if err != nil {
		return err
	}

	var alerts []hub.Alert
	if err := c.call(http.MethodGet, "/admin/alerts", nil, &alerts); err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(alerts)
	}
	if len(alerts) == 0 {
		if !*quiet {
			fmt.Println("All machines are healthy.")
		}
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, a := range alerts {
		mark := "!"
		if a.Level == hub.LevelCritical {
			mark = "!!"
		}
		fmt.Fprintf(w, "%-2s\t%s\t%s\t%s\n", mark, a.Level, a.Kind, a.Message)
	}
	w.Flush()

	// A non-zero exit makes this usable from cron or a monitoring check
	// without anything having to parse the output.
	if *quiet {
		os.Exit(1)
	}
	return nil
}

// ------------------------------------------------------------------- audit

func cmdAudit(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	limit := fs.Int("n", 40, "how many entries to show")
	c, err := newAdminClient(fs, args)
	if err != nil {
		return err
	}
	var entries []hub.AuditEntry
	if err := c.call(http.MethodGet, fmt.Sprintf("/admin/audit?limit=%d", *limit), nil, &entries); err != nil {
		return err
	}
	if len(entries) == 0 {
		fmt.Println("Nothing has happened yet.")
		return nil
	}
	for _, e := range entries {
		fmt.Println(e.Describe())
	}
	fmt.Println("\n  Membership and policy changes only. Connections between peers never" +
		"\n  touch the hub, so they are not — and cannot be — recorded here.")
	return nil
}

// ------------------------------------------------------------------ health

const healthUsage = `Usage:
  locnet-hub health                       show thresholds and the approval setting
  locnet-hub health set [flags]

Flags:
  -disk-warn      warn below this %% free disk
  -disk-critical  alert below this %% free disk
  -load-warn      warn above this %% CPU
  -mem-warn       warn below this %% free memory
  -offline-after  alert after this long with no contact, e.g. 30m
  -mute           comma-separated machines that raise no alerts
  -require-approval=true|false`

func cmdHealth(args []string) error {
	pos, flags := splitArgs(args)
	sub := ""
	if len(pos) > 0 {
		sub = pos[0]
	}

	fs := flag.NewFlagSet("health", flag.ExitOnError)
	diskWarn := fs.Float64("disk-warn", -1, "warn below this % free disk")
	diskCrit := fs.Float64("disk-critical", -1, "alert below this % free disk")
	loadWarn := fs.Float64("load-warn", -1, "warn above this % CPU")
	memWarn := fs.Float64("mem-warn", -1, "warn below this % free memory")
	offline := fs.String("offline-after", "", "alert after this long with no contact")
	mute := fs.String("mute", "", "comma-separated machines that raise no alerts")
	approval := fs.String("require-approval", "", "true or false")
	c, err := newAdminClient(fs, flags)
	if err != nil {
		return err
	}

	type healthResponse struct {
		Rules           hub.HealthRules `json:"rules"`
		RequireApproval bool            `json:"require_approval"`
	}

	show := func() error {
		var out healthResponse
		if err := c.call(http.MethodGet, "/admin/health", nil, &out); err != nil {
			return err
		}
		r := out.Rules
		fmt.Printf("  disk free      warn below %.0f%%, alert below %.0f%%\n", r.DiskFreePercentWarn, r.DiskFreePercentCritical)
		fmt.Printf("  cpu load       warn above %.0f%%\n", r.LoadPercentWarn)
		fmt.Printf("  memory free    warn below %.0f%%\n", r.MemFreePercentWarn)
		fmt.Printf("  offline        alert after %s with no contact\n", time.Duration(r.OfflineAfter))
		if len(r.Muted) > 0 {
			fmt.Printf("  muted          %s\n", strings.Join(r.Muted, ", "))
		}
		fmt.Printf("\n  new machines   %s\n", approvalText(out.RequireApproval))
		return nil
	}

	if sub == "" || sub == "show" {
		if err := show(); err != nil {
			return err
		}
		fmt.Println("\n" + healthUsage)
		return nil
	}
	if sub != "set" {
		return fmt.Errorf("unknown health command %q\n\n%s", sub, healthUsage)
	}

	// Start from the current values so a single flag changes one thing.
	var current healthResponse
	if err := c.call(http.MethodGet, "/admin/health", nil, &current); err != nil {
		return err
	}
	r := current.Rules
	if *diskWarn >= 0 {
		r.DiskFreePercentWarn = *diskWarn
	}
	if *diskCrit >= 0 {
		r.DiskFreePercentCritical = *diskCrit
	}
	if *loadWarn >= 0 {
		r.LoadPercentWarn = *loadWarn
	}
	if *memWarn >= 0 {
		r.MemFreePercentWarn = *memWarn
	}
	if *offline != "" {
		d, err := time.ParseDuration(*offline)
		if err != nil {
			return fmt.Errorf("bad -offline-after %q: %w", *offline, err)
		}
		r.OfflineAfter = hub.Duration(d)
	}
	if *mute != "" {
		r.Muted = nil
		for _, m := range strings.Split(*mute, ",") {
			if m = strings.TrimSpace(m); m != "" {
				r.Muted = append(r.Muted, m)
			}
		}
	}

	req := map[string]any{"rules": r}
	if *approval != "" {
		want := *approval == "true"
		req["require_approval"] = want
	}
	var out healthResponse
	if err := c.call(http.MethodPost, "/admin/health", req, &out); err != nil {
		return err
	}
	fmt.Print("Updated.\n\n")
	return show()
}

func approvalText(on bool) string {
	if on {
		return "must be approved before they join the network"
	}
	return "join immediately (run `locnet-hub health set -require-approval=true` to change)"
}

func cmdApprove(args []string) error {
	pos, flags := splitArgs(args)
	fs := flag.NewFlagSet("approve", flag.ExitOnError)
	c, err := newAdminClient(fs, flags)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: locnet-hub approve <machine>")
	}
	if err := c.call(http.MethodPost, "/admin/approve", map[string]string{"node": pos[0]}, nil); err != nil {
		return err
	}
	fmt.Printf("%s is now on the network.\n", pos[0])
	return nil
}

// ------------------------------------------------------------------ admins

const adminsUsage = `Usage:
  locnet-hub admins                  list the machines that may administer this network
  locnet-hub admins add <machine>    let that machine mint join codes, admit and remove
                                     machines, with ` + "`locnet admin`" + ` or the console
  locnet-hub admins remove <machine>

The machine running the hub is always an administrator. Anyone else is one only
because somebody here said so: the authority is that machine's own identity
key, which never leaves it, and removing it here takes effect at once.`

func cmdAdmins(args []string) error {
	pos, flags := splitArgs(args)
	fs := flag.NewFlagSet("admins", flag.ExitOnError)
	c, err := newAdminClient(fs, flags)
	if err != nil {
		return err
	}

	var names []string
	switch {
	case len(pos) == 0 || pos[0] == "list":
		if err := c.call(http.MethodGet, "/admin/admins", nil, &names); err != nil {
			return err
		}
	case (pos[0] == "add" || pos[0] == "remove" || pos[0] == "rm") && len(pos) == 2:
		req := map[string]any{"node": pos[1], "remove": pos[0] != "add"}
		if err := c.call(http.MethodPost, "/admin/admins", req, &names); err != nil {
			return err
		}
		if pos[0] == "add" {
			fmt.Printf("%s may now administer this network.\n", pos[1])
			fmt.Printf("On %s:  locnet admin   (or the Network tab in locnet console)\n\n", pos[1])
		} else {
			fmt.Printf("%s may no longer administer this network.\n\n", pos[1])
		}
	default:
		return errors.New(adminsUsage)
	}

	if len(names) == 0 {
		fmt.Println("No machine administers this network yet; only the admin token on this machine does.")
		return nil
	}
	fmt.Println("Administrators:")
	for _, n := range names {
		fmt.Println("  " + n)
	}
	return nil
}
