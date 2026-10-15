package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/mahantsunandan/locnet/internal/console"
	"github.com/mahantsunandan/locnet/internal/ipc"
	"github.com/mahantsunandan/locnet/internal/launch"
	"github.com/mahantsunandan/locnet/internal/node"
	"github.com/mahantsunandan/locnet/internal/peercfg"
	"github.com/mahantsunandan/locnet/internal/resource"
	"github.com/mahantsunandan/locnet/internal/shareclient"
)

// splitArgs separates positional arguments from flags. Go's flag package
// stops at the first non-flag argument, so a documented order like
// "compute enable -allow x" needs the positionals pulled out first.
func splitArgs(args []string) (positional, flags []string) {
	for i, a := range args {
		if strings.HasPrefix(a, "-") {
			return positional, args[i:]
		}
		positional = append(positional, a)
	}
	return positional, nil
}

// resolvePeer finds a peer by name or overlay address.
func resolvePeer(who string) (node.PeerStatus, error) {
	st, err := status()
	if err != nil {
		return node.PeerStatus{}, err
	}
	var names []string
	for _, p := range st.Peers {
		if p.Name == who || p.IP.String() == who {
			return p, nil
		}
		names = append(names, p.Name)
	}
	if len(names) == 0 {
		return node.PeerStatus{}, fmt.Errorf("no peers on this network yet")
	}
	sort.Strings(names)
	return node.PeerStatus{}, fmt.Errorf("no peer called %q. Known peers: %s", who, strings.Join(names, ", "))
}

// cmdPeers prints the network with everything each machine offers.
func cmdPeers(args []string) error {
	fs := flag.NewFlagSet("peers", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := status()
	if err != nil {
		return err
	}
	if len(st.Peers) == 0 {
		fmt.Println("No peers yet. Add a machine with a join code from the hub.")
		return nil
	}

	var unverified bool
	var problems []string
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PEER\tADDRESS\tOS\tPATH\tCPU\tFREE DISK\tSERVICES\tSHARES")
	for _, p := range st.Peers {
		path := p.Path
		if !p.Online {
			path = "offline"
		}
		var svc []string
		for _, s := range p.Services {
			// A server that answers but will not let anyone log in is the
			// worst kind of entry to show plainly: it looks like it works.
			if s.Problem != "" {
				svc = append(svc, s.Name+"!")
				problems = append(problems, fmt.Sprintf("%s %s: %s", p.Name, s.Name, s.Problem))
				continue
			}
			// A service nobody has confirmed from outside is marked, not
			// hidden. This column used to state as fact that a machine offered
			// SSH when its firewall blocked every peer on the network, because
			// the machine had asked itself and believed the answer. A "?" is
			// the difference between a claim and a checked claim.
			if s.Verified {
				svc = append(svc, s.Name)
				continue
			}
			svc = append(svc, s.Name+"?")
			unverified = true
		}
		var shares []string
		for _, s := range p.Shares {
			shares = append(shares, s.Name)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			p.Name, p.IP, orDash(p.OS), path,
			loadText(p.Stats), diskText(p.Stats),
			orDash(strings.Join(svc, ",")), orDash(strings.Join(shares, ",")))
	}
	w.Flush()
	fmt.Println("\n  locnet ssh|rdp|vnc <peer>     connect     locnet files <peer>   browse shares")
	if unverified {
		fmt.Println("  ?  the machine found this port open on itself, but no peer has confirmed")
		fmt.Println("     it is reachable — run `locnet doctor` there to find out which it is")
	}
	if len(problems) > 0 {
		fmt.Println("  !  answers, but will not let anyone in:")
		for _, line := range problems {
			fmt.Printf("     %s\n", line)
		}
	}
	return nil
}

func loadText(s resource.Stats) string {
	if s.CPUs == 0 {
		return "-"
	}
	if s.LoadPercent == 0 {
		return fmt.Sprintf("%d cores", s.CPUs)
	}
	return fmt.Sprintf("%.0f%% of %d", s.LoadPercent, s.CPUs)
}

func diskText(s resource.Stats) string {
	if s.DiskTotalGB == 0 {
		return "-"
	}
	return fmt.Sprintf("%dG/%dG", s.DiskFreeGB, s.DiskTotalGB)
}

// cmdConnect handles ssh, rdp and vnc.
func cmdConnect(kind launch.Kind, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: locnet %s [user@]<peer>", kind)
	}
	who := args[0]

	// An explicit user@peer wins, and is remembered so it need not be typed
	// again. Usernames differ between machines far too often to guess from
	// the local account — that guess is what made `locnet ssh` try to log in
	// as the wrong person.
	login := ""
	if u, host, ok := strings.Cut(who, "@"); ok {
		login, who = u, host
	}

	p, err := resolvePeer(who)
	if err != nil {
		return err
	}
	if !p.Online {
		fmt.Fprintf(os.Stderr, "locnet: %s is offline; trying anyway\n", p.Name)
	}

	if login != "" {
		if err := peercfg.Set(p.Name, peercfg.Peer{User: login}); err == nil {
			fmt.Fprintf(os.Stderr, "locnet: remembering %s@%s for next time\n", login, p.Name)
		}
	} else {
		login = peercfg.UserFor(p.Name)
	}

	port := defaultPortFor(kind)
	// Prefer a port actually seen listening on that peer, so a VNC server on
	// display 1 is found without anyone having to remember 5901.
	for _, s := range p.Services {
		if k, ok := launch.KindForService(s.Name); ok && k == kind {
			port = s.Port
			break
		}
	}

	target := launch.TargetFor(kind, p.IP.String(), port)
	switch {
	case kind == launch.KindSSH && login != "":
		target = login + "@" + target
	case kind == launch.KindSSH:
		// No remembered account and none given. Say so rather than silently
		// using the local username, which is wrong as often as it is right.
		fmt.Fprintf(os.Stderr,
			"locnet: no account remembered for %s, using your local username %q.\n"+
				"        If that is wrong: locnet ssh <account>@%s\n",
			p.Name, launch.InvokingUser(), p.Name)
	}

	if err := checkBeforeLaunch(kind, p, port); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "locnet: connecting to %s (%s)\n", p.Name, target)
	if kind == launch.KindVNC {
		fmt.Fprintf(os.Stderr, "locnet: if %s's desktop is locked, it asks for your password there.\n"+
			"        A window that stays black wakes up when you click inside it.\n", p.Name)
	}
	return launch.RunAs(kind, target, login)
}

// checkBeforeLaunch makes sure a remote-desktop server will let anyone in
// before a client is started at it. The port being open is not enough: a
// server that hangs up before login makes the client flash and vanish, and
// the person blames the client.
func checkBeforeLaunch(kind launch.Kind, p node.PeerStatus, port uint16) error {
	if kind != launch.KindRDP && kind != launch.KindVNC {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	addr := net.JoinHostPort(p.IP.String(), strconv.Itoa(int(port)))
	if problem := resource.CheckProtocol(ctx, string(kind), addr); problem != "" {
		return fmt.Errorf("%s: %s", p.Name, problem)
	}
	if kind == launch.KindVNC {
		// So the viewer opens on a desktop that is awake, not a black window.
		resource.WakeVNC(ctx, addr)
	}
	return nil
}

// cmdLogin remembers which account to use for a peer.
func cmdLogin(args []string) error {
	if len(args) == 0 || len(args) > 2 {
		return errors.New("usage: locnet login <peer> <account>   |   locnet login <peer> -forget")
	}
	p, err := resolvePeer(args[0])
	if err != nil {
		return err
	}
	if len(args) == 1 {
		if u := peercfg.UserFor(p.Name); u != "" {
			fmt.Printf("%s logs in as %s\n", p.Name, u)
		} else {
			fmt.Printf("No account remembered for %s.\n", p.Name)
		}
		return nil
	}
	if args[1] == "-forget" {
		if err := peercfg.Forget(p.Name); err != nil {
			return err
		}
		fmt.Printf("Forgot the account for %s.\n", p.Name)
		return nil
	}
	if err := peercfg.Set(p.Name, peercfg.Peer{User: args[1]}); err != nil {
		return err
	}
	fmt.Printf("%s will log in as %s.\n", p.Name, args[1])
	fmt.Printf("\n  Stop typing a password too:  locnet ssh-key %s\n", p.Name)
	return nil
}

// cmdSSHKey sets up key authentication so passwords stop being needed.
//
// This is LocNet's answer to "can it remember my password": no, and it should
// not — but it can remove the password. A key is better than a stored
// password in every respect, and ssh-copy-id has been the way to install one
// for twenty years.
func cmdSSHKey(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: locnet ssh-key <peer>")
	}
	p, err := resolvePeer(args[0])
	if err != nil {
		return err
	}
	login := peercfg.UserFor(p.Name)
	if login == "" {
		login = launch.InvokingUser()
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	if u := os.Getenv("SUDO_USER"); u != "" && u != "root" {
		return fmt.Errorf("run this without sudo — the key belongs to your account, not root's")
	}

	key := filepath.Join(home, ".ssh", "id_ed25519")
	if _, err := os.Stat(key); os.IsNotExist(err) {
		fmt.Printf("No SSH key found. Creating one at %s…\n", key)
		gen := exec.Command("ssh-keygen", "-t", "ed25519", "-f", key, "-N", "", "-C", "locnet")
		gen.Stdin, gen.Stdout, gen.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := gen.Run(); err != nil {
			return fmt.Errorf("ssh-keygen: %w", err)
		}
	}

	fmt.Printf("Copying your public key to %s@%s — this asks for that machine's password once.\n",
		login, p.Name)

	if p.OS == "windows" {
		if err := copyKeyToWindows(key+".pub", login, p.IP.String()); err != nil {
			return err
		}
	} else {
		copyID := exec.Command("ssh-copy-id", "-i", key+".pub", login+"@"+p.IP.String())
		copyID.Stdin, copyID.Stdout, copyID.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := copyID.Run(); err != nil {
			return fmt.Errorf("ssh-copy-id: %w", err)
		}
	}

	fmt.Printf("\nDone. `locnet ssh %s` should no longer ask for a password.\n", p.Name)
	return nil
}

// copyKeyToWindows installs a public key where a Windows sshd will read it.
//
// ssh-copy-id cannot do this job. It appends to ~/.ssh/authorized_keys, and
// Microsoft's default sshd_config sends the whole administrators group
// somewhere else entirely:
//
//	Match Group administrators
//	    AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
//
// On a normal Windows desktop the account somebody uses *is* an administrator,
// so the key lands in a file sshd never opens. ssh-copy-id reports success, the
// next login asks for a password, and there is nothing in any log to say why.
// That combination has cost people entire afternoons.
//
// The remote side also needs its inherited ACLs stripped, or sshd refuses the
// file for being too widely writable — again silently.
func copyKeyToWindows(pubPath, login, addr string) error {
	pub, err := os.ReadFile(pubPath)
	if err != nil {
		return err
	}
	line := strings.TrimSpace(string(pub))
	if line == "" {
		return errors.New("public key file is empty")
	}
	// Single-quote for PowerShell, doubling any quote in the key comment.
	quoted := "'" + strings.ReplaceAll(line, "'", "''") + "'"

	// Appended only when absent, so running this twice does not accumulate
	// duplicate lines.
	script := `$ErrorActionPreference='Stop'
$f = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
$k = ` + quoted + `
if (-not (Test-Path $f)) { New-Item -ItemType File -Path $f -Force | Out-Null }
if (-not (Select-String -Path $f -SimpleMatch -Pattern $k -Quiet)) { Add-Content -Path $f -Value $k }
icacls $f /inheritance:r /grant "SYSTEM:F" /grant "BUILTIN\Administrators:F" | Out-Null
Write-Output ("installed in " + $f)`

	cmd := exec.Command("ssh", login+"@"+addr, "powershell -NoProfile -NonInteractive -Command -")
	cmd.Stdin = strings.NewReader(script)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("installing the key on the Windows machine: %w", err)
	}
	return nil
}

func defaultPortFor(k launch.Kind) uint16 {
	switch k {
	case launch.KindSSH:
		return 22
	case launch.KindRDP:
		return 3389
	case launch.KindVNC:
		return 5900
	}
	return 0
}

// cmdOpen connects using whichever service the peer offers, named or guessed.
func cmdOpen(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: locnet open <peer> [service]")
	}
	p, err := resolvePeer(args[0])
	if err != nil {
		return err
	}
	if len(p.Services) == 0 {
		return fmt.Errorf("%s is not offering anything LocNet knows how to open", p.Name)
	}

	want := ""
	if len(args) > 1 {
		want = args[1]
	}
	for _, s := range p.Services {
		if want != "" && s.Name != want {
			continue
		}
		k, ok := launch.KindForService(s.Name)
		if !ok {
			continue
		}
		if err := checkBeforeLaunch(k, p, s.Port); err != nil {
			return err
		}
		return launch.Run(k, launch.TargetFor(k, p.IP.String(), s.Port))
	}
	var have []string
	for _, s := range p.Services {
		have = append(have, s.Name)
	}
	return fmt.Errorf("%s offers %s, not %q", p.Name, strings.Join(have, ", "), want)
}

// ---------------------------------------------------------------- shares

func cmdShare(args []string) error {
	if len(args) == 0 {
		return errors.New(shareUsage)
	}
	switch args[0] {
	case "list":
		return shareList()
	case "add":
		return shareAdd(args[1:])
	case "remove", "rm":
		if len(args) != 2 {
			return errors.New("usage: locnet share remove <name>")
		}
		c, err := ipc.Dial()
		if err != nil {
			return err
		}
		if err := c.Post("/share/remove", map[string]string{"name": args[1]}, nil); err != nil {
			return err
		}
		fmt.Printf("Removed share %q.\n", args[1])
		return nil
	default:
		return fmt.Errorf("unknown share command %q\n\n%s", args[0], shareUsage)
	}
}

const shareUsage = `Usage:
  locnet share list
  locnet share add <name> <path>          share a folder
  locnet share add <name> :<port>         publish a local service
  locnet share remove <name>

Flags for add:
  -allow  comma-separated peer names, or "*" for everyone (default: nobody)
  -rw     allow uploads to a folder share (default: read-only)
  -on     overlay port for a service share (default: the same as the local one)
  -desc   description shown in the console

Examples:
  locnet share add data /srv/data -allow workstation,laptop
  locnet share add drop /srv/incoming -allow "*" -rw
  locnet share add pg :5432 -allow workstation`

func shareList() error {
	st, err := status()
	if err != nil {
		return err
	}
	if len(st.Shares) == 0 {
		fmt.Println("This machine is not sharing anything.")
		fmt.Println("\n" + shareUsage)
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tKIND\tTARGET\tACCESS\tSHARED WITH")
	for _, s := range st.Shares {
		access := "read-only"
		if s.Kind == resource.KindPort {
			access = fmt.Sprintf("overlay :%d", s.Port)
		} else if !s.ReadOnly {
			access = "read-write"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", s.Name, s.Kind, s.Target, access, s.AllowText())
	}
	w.Flush()

	if st.IP.IsValid() {
		fmt.Printf("\n  Folders are served at %s:%d, reachable only through the tunnel.\n", st.IP, node.SharePort)
	}
	return nil
}

func shareAdd(args []string) error {
	fs := flag.NewFlagSet("share add", flag.ExitOnError)
	allow := fs.String("allow", "", `who may use it: comma-separated peer names, or "*"`)
	rw := fs.Bool("rw", false, "allow uploads (folder shares only)")
	on := fs.Uint("on", 0, "overlay port for a service share")
	desc := fs.String("desc", "", "description shown in the console")

	// Flags come after the positional arguments in the documented form, so
	// split them out before parsing.
	var pos []string
	var flags []string
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			flags = append(flags, args[i:]...)
			break
		}
		pos = append(pos, args[i])
	}
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 2 {
		return errors.New("usage: locnet share add <name> <path|:port>")
	}

	sh := resource.Share{
		Name:        pos[0],
		Description: *desc,
		ReadOnly:    !*rw,
	}
	if strings.HasPrefix(pos[1], ":") {
		port, err := strconv.ParseUint(strings.TrimPrefix(pos[1], ":"), 10, 16)
		if err != nil {
			return fmt.Errorf("bad port %q: %w", pos[1], err)
		}
		sh.Kind = resource.KindPort
		sh.Target = strconv.FormatUint(port, 10)
		sh.Port = uint16(port)
		if *on != 0 {
			sh.Port = uint16(*on)
		}
	} else {
		sh.Kind = resource.KindFiles
		abs, err := absPath(pos[1])
		if err != nil {
			return err
		}
		sh.Target = abs
	}

	if *allow != "" {
		for _, a := range strings.Split(*allow, ",") {
			if a = strings.TrimSpace(a); a != "" {
				sh.Allow = append(sh.Allow, a)
			}
		}
	}

	c, err := ipc.Dial()
	if err != nil {
		return err
	}
	if err := c.Post("/share/add", sh, nil); err != nil {
		return err
	}

	fmt.Printf("Sharing %q (%s) with %s.\n", sh.Name, sh.Target, sh.AllowText())
	if len(sh.Allow) == 0 {
		fmt.Println("\n  Nobody can use it yet — no peers were allowed.")
		fmt.Printf("  Grant access with:  locnet share add %s %s -allow <peer>\n", sh.Name, sh.Target)
	}
	return nil
}

func absPath(p string) (string, error) {
	if strings.HasPrefix(p, "~") {
		home, err := os.UserHomeDir()
		if err == nil {
			p = home + p[1:]
		}
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("cannot resolve %q: %w", p, err)
	}
	return abs, nil
}

// ------------------------------------------------------------- files

func cmdFiles(args []string) error {
	if len(args) == 0 {
		return errors.New(filesUsage)
	}
	p, err := resolvePeer(args[0])
	if err != nil {
		return err
	}
	client := shareclient.New(p.IP)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	switch {
	case len(args) == 1:
		shares, err := client.List(ctx)
		if err != nil {
			return err
		}
		if len(shares) == 0 {
			return fmt.Errorf("%s is not sharing anything with this machine", p.Name)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "SHARE\tKIND\tACCESS\tDESCRIPTION")
		for _, s := range shares {
			access := "read-only"
			if s.Kind == resource.KindPort {
				access = fmt.Sprintf("%s:%d", p.IP, s.Port)
			} else if !s.ReadOnly {
				access = "read-write"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", s.Name, s.Kind, access, orDash(s.Description))
		}
		w.Flush()
		fmt.Printf("\n  locnet files %s <share> [path]        list\n", p.Name)
		fmt.Printf("  locnet files %s <share> <path> -get  download\n", p.Name)
		return nil

	case len(args) >= 3 && args[len(args)-1] == "-get":
		remote := strings.Join(args[2:len(args)-1], " ")
		dest, err := client.Get(ctx, args[1], remote, ".")
		if err != nil {
			return err
		}
		fmt.Println("Saved", dest)
		return nil

	case len(args) >= 4 && args[len(args)-2] == "-put":
		local := args[len(args)-1]
		remote := strings.Join(args[2:len(args)-2], " ")
		if err := client.Put(ctx, args[1], remote, local); err != nil {
			return err
		}
		fmt.Printf("Uploaded %s to %s:%s/%s\n", local, p.Name, args[1], remote)
		return nil

	default:
		sub := ""
		if len(args) > 2 {
			sub = args[2]
		}
		entries, err := client.Dir(ctx, args[1], sub)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		for _, e := range entries {
			kind := "     "
			size := fmt.Sprintf("%d", e.Size)
			if e.IsDir {
				kind, size = "<dir>", ""
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", kind, size, e.ModTime.Format("2006-01-02 15:04"), e.Name)
		}
		return w.Flush()
	}
}

const filesUsage = `Usage:
  locnet files <peer>                          list the shares you may use
  locnet files <peer> <share> [path]           list a directory
  locnet files <peer> <share> <path> -get      download to the current directory
  locnet files <peer> <share> <path> -put <f>  upload a local file`

// ------------------------------------------------------------- console

func cmdConsole(args []string) error {
	fs := flag.NewFlagSet("console", flag.ExitOnError)
	port := fs.Int("port", 0, "port to listen on (0 picks a free one)")
	noOpen := fs.Bool("no-open", false, "print the URL instead of opening a browser")
	dir := fs.String("downloads", "", "where downloaded files are saved")
	if err := fs.Parse(args); err != nil {
		return err
	}

	srv, err := console.New(*dir)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return srv.ListenAndServe(ctx, *port, func(url string) {
		fmt.Println("LocNet console:", url)
		fmt.Println("Bound to localhost only. The token in the URL is new every run.")
		fmt.Println("Press Ctrl-C to stop.")
		if !*noOpen {
			if err := console.Open(url); err != nil {
				fmt.Fprintln(os.Stderr, "could not open a browser:", err)
			}
		}
	})
}
