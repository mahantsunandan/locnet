package main

import (
	"errors"
	"flag"
	"fmt"
	osuser "os/user"
	"sort"
	"strings"

	"github.com/mahantsunandan/locnet/internal/ipc"
	"github.com/mahantsunandan/locnet/internal/launch"
	"github.com/mahantsunandan/locnet/internal/sshkeys"
)

const sshKeysUsage = `Usage:
  locnet ssh-keys                 what is published and what is trusted
  locnet ssh-keys publish         offer this account's public key to the network
  locnet ssh-keys sync            install peers' host keys, and accepted peers' keys
  locnet ssh-keys accept <peer>   let that peer's operator log in here (or: all)
  locnet ssh-keys revoke <peer>   stop letting them (or: all)

Two different prompts, two different keys, both public:

  Host keys   identify the machine you connect *to*, and remove the "authenticity
              of host ... can't be established" question. Installed for every
              peer, always. A host key grants nothing.

  User keys   identify the person connecting *from* somewhere, and remove the
              password prompt. Installed only for peers you have accepted,
              because being on the same network and being allowed a shell here
              are different permissions.

Private keys are never published, never sent to the hub, and never leave this
machine.`

func cmdSSHKeys(args []string) error {
	if len(args) == 0 {
		return sshKeysShow()
	}
	switch args[0] {
	case "publish":
		return sshKeysPublish()
	case "sync":
		return sshKeysSync()
	case "accept":
		return sshKeysAccept(args[1:], true)
	case "revoke":
		return sshKeysAccept(args[1:], false)
	case "-h", "--help", "help":
		fmt.Println(sshKeysUsage)
		return nil
	default:
		fs := flag.NewFlagSet("ssh-keys", flag.ExitOnError)
		fs.Usage = func() { fmt.Println(sshKeysUsage) }
		return fmt.Errorf("unknown subcommand %q\n\n%s", args[0], sshKeysUsage)
	}
}

// operatorHome is the home directory of the human running this, not root's.
//
// `locnet ssh-keys` is normally run with sudo, because it talks to the daemon.
// Installing keys into /root/.ssh would be useless: the account somebody
// actually logs in as is the one that needs them.
func operatorHome() (string, string, error) {
	user := launch.InvokingUser()
	if user == "" {
		return "", "", errors.New("cannot tell which account you are")
	}
	u, err := lookupOperator(user)
	if err != nil {
		return "", "", fmt.Errorf("looking up %s: %w", user, err)
	}
	return user, u.HomeDir, nil
}

// lookupOperator finds the account, preferring the one running this.
//
// That is the usual answer, and on Windows the only one, and taking it as is
// avoids a Windows trap: a bare account name is resolved against the
// computer's own name first, so on a machine called "WinPC-01" with an account
// called "winpc-01" the lookup finds the computer and fails with "should be
// user account type, not 3". Machines named after their owner are common.
func lookupOperator(name string) (*osuser.User, error) {
	if cur, err := osuser.Current(); err == nil {
		short := cur.Username
		if i := strings.LastIndex(short, `\`); i >= 0 {
			short = short[i+1:]
		}
		if strings.EqualFold(short, name) {
			return cur, nil
		}
	}
	return osuser.Lookup(name)
}

func sshKeysShow() error {
	st, err := status()
	if err != nil {
		return err
	}
	user, home, err := operatorHome()
	if err != nil {
		return err
	}

	fmt.Printf("Account:   %s (%s)\n", user, home)
	pub, _ := sshkeys.UserKey(home, false)
	if pub == "" {
		fmt.Println("Published: nothing yet — run `locnet ssh-keys publish`")
	} else {
		fmt.Printf("Published: %s\n", abbreviate(pub))
	}

	accept, err := sshAcceptList()
	if err != nil {
		return err
	}
	fmt.Println()
	fmt.Println("Peers whose operators may log in here:")
	if len(accept) == 0 {
		fmt.Println("  (none — `locnet ssh-keys accept <peer>` or `accept all`)")
	} else {
		for _, p := range accept {
			fmt.Printf("  %s\n", p)
		}
	}

	fmt.Println("\nWhat the network offers:")
	for _, p := range st.Peers {
		var bits []string
		if len(p.SSH.Host) > 0 {
			bits = append(bits, fmt.Sprintf("%d host key(s)", len(p.SSH.Host)))
		}
		if p.SSH.User != "" {
			bits = append(bits, "an operator key")
		}
		if len(bits) == 0 {
			bits = append(bits, "nothing published yet")
		}
		fmt.Printf("  %-16s %s\n", p.Name, strings.Join(bits, ", "))
	}
	return nil
}

func sshKeysPublish() error {
	_, home, err := operatorHome()
	if err != nil {
		return err
	}
	pub, err := sshkeys.UserKey(home, true)
	if err != nil {
		return err
	}
	if pub == "" {
		return errors.New("no public key to publish")
	}

	c, err := ipc.Dial()
	if err != nil {
		return err
	}
	if err := c.Post("/sshkeys", map[string]any{"user_key": pub}, nil); err != nil {
		return err
	}
	fmt.Printf("Published %s\n", abbreviate(pub))
	fmt.Println("Peers that accept this machine can now let you in without a password.")
	fmt.Println("On each of those machines:  locnet ssh-keys accept " + thisMachineName())
	return nil
}

// sshKeysSync installs what the network has published.
func sshKeysSync() error {
	st, err := status()
	if err != nil {
		return err
	}
	user, home, err := operatorHome()
	if err != nil {
		return err
	}

	// Host keys for everybody. These authenticate the machine being connected
	// to and grant nothing, so there is no decision to make about them.
	var hosts []sshkeys.KnownHost
	for _, p := range st.Peers {
		if len(p.SSH.Host) == 0 {
			continue
		}
		hosts = append(hosts, sshkeys.KnownHost{Name: p.Name, IP: p.IP, Keys: p.SSH.Host})
	}
	n, err := sshkeys.SyncKnownHosts(sshkeys.KnownHostsPath(home), hosts)
	if err != nil {
		return fmt.Errorf("known_hosts: %w", err)
	}
	switch {
	case n > 0:
		fmt.Printf("known_hosts: %d entries for %d peer(s)\n", n, len(hosts))
	default:
		fmt.Println("known_hosts: already up to date")
	}

	// Operator keys only for accepted peers.
	accept, err := sshAcceptList()
	if err != nil {
		return err
	}
	allowed := map[string]bool{}
	all := false
	for _, a := range accept {
		if a == "all" {
			all = true
		}
		allowed[a] = true
	}

	var want []sshkeys.Entry
	for _, p := range st.Peers {
		if p.SSH.User == "" || !(all || allowed[p.Name]) {
			continue
		}
		want = append(want, sshkeys.Entry{Peer: p.Name, PublicKey: p.SSH.User})
	}

	target, err := sshkeys.TargetFor(user)
	if err != nil {
		return err
	}
	added, removed, err := sshkeys.Sync(target, want)
	if err != nil {
		return fmt.Errorf("authorized_keys: %w", err)
	}
	switch {
	case added == 0 && removed == 0:
		fmt.Printf("authorized_keys: already up to date (%s)\n", sshkeys.Describe(target))
	default:
		fmt.Printf("authorized_keys: +%d -%d in %s\n", added, removed, sshkeys.Describe(target))
	}
	return nil
}

func sshKeysAccept(args []string, add bool) error {
	if len(args) != 1 {
		return errors.New("usage: locnet ssh-keys accept|revoke <peer>|all")
	}
	who := args[0]

	current, err := sshAcceptList()
	if err != nil {
		return err
	}
	set := map[string]bool{}
	for _, p := range current {
		set[p] = true
	}
	if add {
		set[who] = true
	} else {
		delete(set, who)
	}
	var out []string
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)

	c, err := ipc.Dial()
	if err != nil {
		return err
	}
	if err := c.Post("/sshkeys", map[string]any{"accept_from": out, "set_accept": true}, nil); err != nil {
		return err
	}

	if add {
		fmt.Printf("%s may now log in here as you.\n", who)
	} else {
		fmt.Printf("%s may no longer log in here.\n", who)
	}
	// The list is only a policy until the keys move, and leaving that to a
	// timer would mean "accept" appears not to work for a while.
	return sshKeysSync()
}

func sshAcceptList() ([]string, error) {
	c, err := ipc.Dial()
	if err != nil {
		return nil, err
	}
	var resp struct {
		AcceptFrom []string `json:"accept_from"`
	}
	if err := c.Post("/sshkeys", map[string]any{}, &resp); err != nil {
		return nil, err
	}
	return resp.AcceptFrom, nil
}

// abbreviate shortens a key for display: the type and the last few characters,
// which is enough to tell two keys apart without a wrapped wall of base64.
func abbreviate(key string) string {
	fields := strings.Fields(key)
	if len(fields) < 2 {
		return key
	}
	blob := fields[1]
	if len(blob) > 12 {
		blob = "…" + blob[len(blob)-12:]
	}
	out := fields[0] + " " + blob
	if len(fields) > 2 {
		out += " " + strings.Join(fields[2:], " ")
	}
	return out
}
