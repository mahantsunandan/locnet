// Command locnet is the user-facing CLI. It does no networking of its own —
// every command is a call to the locnetd service over the local control
// socket.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/mahantsunandan/locnet/internal/console"
	"github.com/mahantsunandan/locnet/internal/ipc"
	"github.com/mahantsunandan/locnet/internal/joincode"
	"github.com/mahantsunandan/locnet/internal/launch"
	"github.com/mahantsunandan/locnet/internal/node"
	"github.com/mahantsunandan/locnet/internal/resource"
	"github.com/mahantsunandan/locnet/internal/setup"
	"github.com/mahantsunandan/locnet/internal/shareclient"
)

// Version is stamped at build time with -ldflags "-X main.Version=...".
var Version = "0.1.0"

const usage = `locnet — join and inspect a LocNet private mesh

Usage:
Network
  locnet join <code>      join, install what is missing, and check a peer can
                          get in. -no-setup to join and nothing more
  locnet up               bring the tunnel up
  locnet down             take the tunnel down
  locnet status [-json]   show this machine and its peers
  locnet peers            show peers with their services, shares and load
  locnet ip               print this machine's overlay address
  locnet leave            forget the network (keeps this machine's identity)

Connect
  locnet console          open the web console in a browser
  locnet ssh <peer>       shell into a peer, in your own terminal
  locnet vnc <peer>       a peer's screen, in your own VNC client
  locnet rdp <peer>       a Windows desktop, in your own RDP client
  locnet open <peer> [service]
  locnet login <peer> <account>   remember which account to log in as
  locnet ssh-key <peer>           set up key auth on one peer, by password
  locnet ssh-keys                 exchange keys over the mesh — no passwords,
                                  no host-key prompts. locnet ssh-keys -h

Share
  locnet share list|add|remove
  locnet files <peer> ...    browse and transfer files from a peer's shares
  locnet webshare add <site> <port>
                             publish a local web app on the internet over
                             HTTPS, through the hub. locnet webshare -h

Do it to several machines at once (over SSH — needs an account on each)
  locnet exec <command> -on all
  locnet copy <file|folder>... -to peer1,peer2 [-dest /path]
  locnet fetch <remote-path> -from all [-into ./collected]

Borrow another machine's compute
  locnet best [-gpu] [-cpus N] [-mem GB] [-vram GB]
                             rank machines by free CPU / RAM / GPU, and say why
  locnet job -- <command>    send this folder to the best machine, run, bring
                             results back. -on <peer> to pick, -gpu to require one
  locnet julia [-procs N]    print the addprocs() call for Julia's Distributed

Compute (LocNet's own channel — no account needed, opt-in, no shell)
  locnet compute             offer this machine's CPU to named peers
  locnet run <peer> -- cmd   run a command on a peer that offers compute
  locnet run -idle -- cmd    run it wherever there is capacity
  locnet compute peers       who will run work for this machine

Queue work for the whole fleet (the hub holds it until a machine is free)
  locnet queue submit -cpus 8 -- make -j8
  locnet queue                what is waiting and what is running
  locnet queue log <id>       the output of one job
  locnet queue workers        which machines will take queued work

Editors
  editors/vscode             VS Code extension: run the current file elsewhere

Run the network (on a machine the hub has made an administrator)
  locnet admin               every machine, as the hub sees it
  locnet invite              a join code for a new machine
  locnet admin remove <m>    take a machine off the network. locnet admin -h

Other
  locnet wake <peer>      turn a machine on, via a peer on its network
  locnet setup            install the SSH and screen servers this machine is missing
  locnet setup rdp        let peers log in to this desktop over RDP (GNOME; no sudo)
  locnet hosts on|off     manage a block of peer names in the system hosts file
  locnet doctor           check for the usual causes of a network that will not form
  locnet version

Most commands need administrator privileges, because they talk to a service
that owns a network interface.
`

func main() {
	console.Version = Version
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "join":
		err = cmdJoin(os.Args[2:])
	case "up":
		err = simplePost("/up", "Tunnel is up.")
	case "down":
		err = simplePost("/down", "Tunnel is down.")
	case "leave":
		err = cmdLeave(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "peers":
		err = cmdPeers(os.Args[2:])
	case "console":
		err = cmdConsole(os.Args[2:])
	case "ssh":
		err = cmdConnect(launch.KindSSH, os.Args[2:])
	case "rdp":
		err = cmdConnect(launch.KindRDP, os.Args[2:])
	case "vnc":
		err = cmdConnect(launch.KindVNC, os.Args[2:])
	case "desktop":
		err = cmdDesktop(os.Args[2:])
	case "screen":
		err = cmdScreen(os.Args[2:])
	case "wake":
		err = cmdWake(os.Args[2:])
	case "admin":
		err = cmdAdmin(os.Args[2:])
	case "invite":
		err = adminInvite(os.Args[2:])
	case "queue":
		err = cmdQueue(os.Args[2:])
	case "open":
		err = cmdOpen(os.Args[2:])
	case "login":
		err = cmdLogin(os.Args[2:])
	case "ssh-key":
		err = cmdSSHKey(os.Args[2:])
	case "ssh-keys":
		err = cmdSSHKeys(os.Args[2:])
	case "share":
		err = cmdShare(os.Args[2:])
	case "webshare", "web":
		err = cmdWebShare(os.Args[2:])
	case "files":
		err = cmdFiles(os.Args[2:])
	case "setup":
		err = cmdSetup(os.Args[2:])
	case "compute":
		if len(os.Args) > 2 && os.Args[2] == "peers" {
			err = cmdComputePeers()
		} else {
			err = cmdCompute(os.Args[2:])
		}
	case "run":
		err = cmdRun(os.Args[2:])
	case "best":
		err = cmdBest(os.Args[2:])
	case "job":
		err = cmdJob(os.Args[2:])
	case "julia":
		err = cmdJulia(os.Args[2:])
	case "exec":
		err = cmdExec(os.Args[2:])
	case "copy", "send":
		err = cmdCopy(os.Args[2:])
	case "fetch":
		err = cmdFetch(os.Args[2:])
	case "ip":
		err = cmdIP()
	case "hosts":
		err = cmdHosts(os.Args[2:])
	case "doctor":
		err = cmdDoctor()
	case "version":
		fmt.Println("locnet", Version)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "locnet: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "locnet:", err)
		os.Exit(1)
	}
}

func cmdJoin(args []string) error {
	fs := flag.NewFlagSet("join", flag.ExitOnError)
	noUp := fs.Bool("no-up", false, "join but do not bring the tunnel up")
	noSetup := fs.Bool("no-setup", false, "do not install the SSH and screen servers")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: locnet join <code>")
	}

	// Parsing locally first turns a mistyped code into an instant, specific
	// error rather than a round trip and a vague one.
	code := fs.Arg(0)
	if _, err := joincode.Parse(code); err != nil {
		return err
	}

	c, err := ipc.Dial()
	if err != nil {
		return err
	}
	var st node.Status
	req := map[string]any{"code": code, "up": !*noUp}
	if err := c.Post("/join", req, &st); err != nil {
		return err
	}

	fmt.Printf("Joined %s as %s (%s)\n", orDash(st.Network), st.Name, st.IP)
	if *noUp {
		return nil
	}
	fmt.Println("Tunnel is up.")

	// Joining used to end here, and the machine was then reachable by LocNet
	// and by nothing anyone wanted to use. Getting from "on the mesh" to "I can
	// open a shell on it" took three more commands, each of which could leave a
	// half-finished machine that reported success. Doing it here means the one
	// command a person actually runs is the one that finishes the job.
	if !*noSetup {
		runSetupAfterJoin()
	}
	verifyAfterJoin()
	return nil
}

// runSetupAfterJoin installs the SSH and screen servers, if it can.
//
// Unprivileged is a normal case rather than an error: `locnet join` is run with
// sudo on Linux and macOS and from an elevated prompt on Windows, but not
// always, and a machine that joined successfully should not report failure
// because the optional half needs rights it does not have.
func runSetupAfterJoin() {
	steps, err := setup.Plan()
	if err != nil {
		fmt.Printf("\nCould not work out what this machine needs: %v\n", err)
		return
	}
	pending := setup.Pending(steps)
	if len(pending) == 0 {
		fmt.Println("\nThis machine already has an SSH server and a screen server.")
		return
	}
	if !isPrivileged() {
		fmt.Printf("\n%d thing(s) still needed to make this machine reachable.\n", len(pending))
		fmt.Print(setup.Describe(steps))
		fmt.Println("  Install them with:  " + privilegedSetupCommand())
		return
	}

	fmt.Println("\nSetting this machine up to be reached:")
	fmt.Print(setup.Describe(steps))
	logf := func(format string, a ...any) { fmt.Printf(format+"\n", a...) }
	for _, s := range pending {
		fmt.Printf("  %s\n", s.Name)
		if err := setup.Run(s, logf); err != nil {
			fmt.Printf("    ✗ %v\n", err)
			continue
		}
		fmt.Printf("    ✓ done\n")
	}
	if runtime.GOOS == "linux" || runtime.GOOS == "windows" {
		publishScreenShare()
	}
}

// verifyAfterJoin asks a peer whether any of it actually worked.
//
// Everything up to this point is this machine's opinion of itself, and the
// failure that costs the most time is invisible from here: a server installed,
// running, listening, and firewalled off. So the last thing a join does is ask
// somebody else — the only vantage point from which the answer means anything.
func verifyAfterJoin() {
	fmt.Println("\nChecking that peers can reach this machine...")

	// The netmap arrives a moment after the tunnel does, and a peer that has
	// not appeared yet is not the same as no peers.
	st, ok := waitForAnyPeer(20 * time.Second)
	if !ok {
		fmt.Println("  No peer is online to ask, so this could not be checked.")
		fmt.Println("  Run `locnet doctor` once another machine is up.")
		return
	}
	reportInboundPorts(st, portsToVerify())
}

// waitForPeer polls until some peer is online, or the deadline passes.
func waitForAnyPeer(limit time.Duration) (node.Status, bool) {
	deadline := time.Now().Add(limit)
	for {
		st, err := status()
		if err == nil {
			if _, ok := firstOnlinePeer(st); ok {
				return st, true
			}
		}
		if time.Now().After(deadline) {
			return st, false
		}
		time.Sleep(time.Second)
	}
}

// portsToVerify is what setup just arranged to have listening.
//
// Deliberately not st.Services: the service scan runs every few minutes, so
// immediately after a join it is empty, and probing what this machine currently
// claims would verify nothing at exactly the moment verification matters.
func portsToVerify() []uint16 {
	ports := []uint16{node.SharePort, 22}
	if runtime.GOOS == "windows" {
		ports = append(ports, 3389)
		// VNC is optional on Windows, so it is checked only when present.
		if screenServerUp() {
			ports = append(ports, screenSharePort)
		}
	} else {
		ports = append(ports, screenSharePort)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	return ports
}

func privilegedSetupCommand() string {
	if runtime.GOOS == "windows" {
		return "locnet setup -install   (from an elevated prompt)"
	}
	return "sudo locnet setup -install"
}

func cmdLeave(args []string) error {
	fs := flag.NewFlagSet("leave", flag.ExitOnError)
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*yes {
		fmt.Print("This machine will leave the network and the tunnel will go down.\n" +
			"Its record stays on the hub until an operator removes it.\nType 'yes' to continue: ")
		var answer string
		fmt.Scanln(&answer)
		if strings.TrimSpace(strings.ToLower(answer)) != "yes" {
			return errors.New("cancelled")
		}
	}
	return simplePost("/leave", "Left the network.")
}

func cmdIP() error {
	st, err := status()
	if err != nil {
		return err
	}
	if !st.IP.IsValid() {
		return errors.New("this machine has no address yet — it has not joined a network")
	}
	fmt.Println(st.IP)
	return nil
}

func cmdHosts(args []string) error {
	if len(args) != 1 || (args[0] != "on" && args[0] != "off") {
		return errors.New("usage: locnet hosts on|off")
	}
	on := args[0] == "on"
	c, err := ipc.Dial()
	if err != nil {
		return err
	}
	if err := c.Post("/hosts", map[string]bool{"enabled": on}, nil); err != nil {
		return err
	}
	if on {
		fmt.Printf("Peer names are now written to %s.\nYou can reach machines by name, e.g. `ssh %s`.\n",
			node.HostsPath(), "othermachine")
	} else {
		fmt.Printf("Removed the LocNet block from %s.\n", node.HostsPath())
	}
	return nil
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print raw JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := status()
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(st)
	}

	if !st.Registered {
		fmt.Println("Not joined to any network.")
		fmt.Println("Get a code from whoever runs the hub, then: sudo locnet join <code>")
		return nil
	}

	state := "down"
	if st.Running {
		state = "up"
	}
	fmt.Printf("%-12s %s (%s)\n", "network:", orDash(st.Network), st.HubAddr)
	fmt.Printf("%-12s %s  %s\n", "this node:", st.Name, st.IP)
	fmt.Printf("%-12s %s", "tunnel:", state)
	if st.Interface != "" {
		fmt.Printf("  on %s", st.Interface)
	}
	if st.ListenPort != 0 {
		fmt.Printf("  udp/%d", st.ListenPort)
	}
	fmt.Println()
	if st.Observed != "" {
		fmt.Printf("%-12s %s\n", "seen as:", st.Observed)
	}
	if st.Relay != "" {
		fmt.Printf("%-12s %s\n", "relay:", st.Relay)
	}
	if st.LastError != "" {
		fmt.Printf("%-12s %s\n", "warning:", st.LastError)
	}

	if len(st.Peers) == 0 {
		fmt.Println("\nNo peers yet. Add another machine with a join code from the hub.")
		return nil
	}
	fmt.Println()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PEER\tADDRESS\tOS\tPATH\tVIA\tLATENCY")
	for _, p := range st.Peers {
		path := p.Path
		if !p.Online {
			path = "offline"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			p.Name, p.IP, orDash(p.OS), path, orDash(p.Addr), orDash(p.Latency))
	}
	w.Flush()

	fmt.Println("\n  direct = peer-to-peer     relay = through the hub     connecting = still probing")
	return nil
}

// cmdDoctor checks the handful of things that account for most networks that
// will not form, and says what to do about each.
// daemonLog is where to look when the tunnel will not come up. The answer
// differs enough per platform that guessing wastes a support round-trip.
func daemonLog() string {
	switch runtime.GOOS {
	case "darwin":
		return "sudo tail -50 /var/log/locnet/locnetd.log"
	case "windows":
		return `Get-Content C:\ProgramData\LocNet\logs\locnetd.log -Tail 50`
	default:
		return "sudo journalctl -u locnetd -n 50 --no-pager"
	}
}

func cmdDoctor() error {
	st, err := status()
	if err != nil {
		fmt.Println("✗ locnetd is not reachable.")
		fmt.Println("  Start it:  sudo systemctl start locnetd     (Linux)")
		fmt.Println("             sudo launchctl kickstart -k system/com.locnet.locnetd   (macOS)")
		fmt.Println("             Start-Service locnetd            (Windows, as Administrator)")
		return err
	}
	fmt.Println("✓ locnetd is running")

	if !st.Registered {
		fmt.Println("✗ this machine has not joined a network")
		fmt.Println("  Run: sudo locnet join <code>")
		return nil
	}
	fmt.Printf("✓ joined %s as %s (%s)\n", orDash(st.Network), st.Name, st.IP)

	if !st.Running {
		// This is the state that looks like "everything works but the other
		// machines say I am offline": peers still resolve from the netmap
		// cached at join, but nothing is polling the hub, so the hub stops
		// counting this machine as present.
		fmt.Println("✗ the tunnel is down — other machines will show this one as offline")
		if runtime.GOOS == "windows" {
			fmt.Println("  Run: locnet up   (from an elevated prompt)")
		} else {
			fmt.Println("  Run: sudo locnet up")
		}
		if st.LastError != "" {
			fmt.Printf("  Last error: %s\n", st.LastError)
		}
		fmt.Printf("  Daemon log: %s\n", daemonLog())
		return nil
	}
	fmt.Printf("✓ tunnel up on %s\n", st.Interface)

	switch {
	case st.LastError != "":
		fmt.Printf("✗ the hub is not answering: %s\n", st.LastError)
		fmt.Printf("  Check that %s is reachable and that `locnet-hub serve` is running there.\n", st.HubAddr)
	case !st.HubOK:
		// Not an error and not a success: the agent has only just started, or
		// every address is timing out and none has failed outright yet. The
		// address printed here is the first one it will try, not one that has
		// answered — saying otherwise put a tick beside a dead address.
		fmt.Printf("· waiting for the hub — nothing has answered yet, first to try is %s\n", st.HubAddr)
	default:
		fmt.Printf("✓ hub %s is answering\n", st.HubAddr)
		if note := node.TransportNote(st.HubTransport); st.HubTransport == "http" {
			fmt.Printf("! control plane %s.\n  Upgrade the hub: sudo bash deploy.sh --hub (from a 0.10.4 or later release)\n", note)
		} else if note != "" {
			fmt.Printf("✓ control plane %s\n", note)
		}
	}

	if len(st.Conflicts) > 0 {
		fmt.Println("✗ something on this machine overlaps the LocNet address range:")
		for _, c := range st.Conflicts {
			fmt.Printf("    %s\n", c)
		}
		fmt.Println("  Traffic for the overlapping addresses may go to the wrong interface.")
	} else {
		fmt.Println("✓ no address or route conflicts on this machine")
	}

	if st.Observed == "" {
		fmt.Println("✗ the relay has not told us our public address")
		fmt.Printf("  UDP to the hub may be blocked. Check that %s is open for UDP, not just TCP.\n", st.HubAddr)
	} else {
		fmt.Printf("✓ relay sees this machine at %s\n", st.Observed)
	}

	var direct, relayed, stuck int
	for _, p := range st.Peers {
		if !p.Online {
			continue
		}
		switch p.Path {
		case "direct":
			direct++
		case "relay":
			relayed++
		default:
			stuck++
		}
	}
	fmt.Printf("\n  peers: %d direct, %d relayed, %d still connecting\n", direct, relayed, stuck)

	reportReachability(st)
	reportInbound(st)
	reportServiceProblems(st)
	reportLocalShares(st)
	if relayed > 0 {
		fmt.Println("\n  Relayed peers still work, they are just slower and use the hub's bandwidth.")
		fmt.Println("  Common causes: both machines behind symmetric NAT (some mobile and")
		fmt.Println("  corporate networks), or UDP blocked outbound. Forwarding UDP port")
		fmt.Printf("  %d to one of the two machines usually fixes the pair.\n", st.ListenPort)
	}
	if runtime.GOOS == "linux" && direct+relayed == 0 && len(st.Peers) > 0 {
		fmt.Println("\n  No peer is reachable at all. Check the local firewall allows outbound UDP.")
	}
	return nil
}

// reportInbound asks a peer whether it can reach this machine's servers.
//
// Every other check in doctor is asked from here and answered from here, which
// makes them all blind to the one failure that costs the most time: a service
// that is installed, running, listening, and firewalled off. A machine cannot
// see that about itself. On Windows it especially cannot — traffic sent to a
// machine's own address never crosses its firewall, so the local scan connects
// happily to a port no peer on the network can open. That is not a hypothetical;
// it is how a node came to advertise SSH to everyone while refusing all of them.
//
// So this asks somebody else. One online peer is enough: a second opinion from
// the same side of the boundary adds nothing, and the useful signal — "the port
// I advertise is shut from out there" — is identical whoever reports it.
func reportInbound(st node.Status) {
	reportInboundPorts(st, advertisedPorts(st))
}

// reportInboundPorts is the shared body: doctor asks about what this machine
// advertises, a fresh join asks about what setup just installed.
func reportInboundPorts(st node.Status, ports []uint16) {
	if len(ports) == 0 {
		return
	}

	// Ask a peer the access policy lets in. Asking one it keeps out would
	// report every port as firewalled — and send people off to "fix" a
	// policy that is doing exactly what it was told.
	probers := node.Probers(st.Peers, ports)
	if len(probers) == 0 {
		// Not a failure worth a cross: with nobody else on the network, or
		// nobody allowed to connect here, there is no outside to ask.
		if _, anyone := firstOnlinePeer(st); anyone {
			fmt.Println("\n  Reachability from outside: the access policy lets no online peer connect here, so there is no one to ask.")
		} else {
			fmt.Println("\n  Reachability from outside: no peer is online to ask.")
		}
		return
	}
	peer := probers[0]

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	res, err := shareclient.New(peer.IP).Probe(ctx, peer.Name, ports)
	if err != nil {
		fmt.Printf("\n  Reachability from outside: could not ask %s (%v)\n", peer.Name, err)
		return
	}

	fmt.Printf("\n  Reachability from %s, connecting back to this machine:\n", res.From)
	firewalled := 0
	for _, p := range ports {
		name := serviceName(st, p)
		switch {
		case !peer.MayReach(p):
			fmt.Printf("    – %-14s port %d not checked: the access policy keeps %s out of it\n", name, p, res.From)
		case res.IsOpen(p):
			fmt.Printf("    ✓ %-14s port %d answers\n", name, p)
		default:
			fmt.Printf("    ✗ %-14s port %d is listening here but blocked from %s\n", name, p, res.From)
			firewalled++
		}
	}
	if firewalled > 0 {
		fmt.Println("\n  A port that is open here and blocked there is a firewall, not LocNet.")
		switch runtime.GOOS {
		case "windows":
			fmt.Println("  Fix it with:  locnet setup -install     (from an elevated prompt)")
		default:
			fmt.Println("  Fix it with:  sudo locnet setup -install")
		}
	}
}

// advertisedPorts is what this machine claims to offer, plus LocNet's own share
// port — which peers need for files, exec and the desktop, and which is
// therefore worth knowing about even though nothing advertises it.
func advertisedPorts(st node.Status) []uint16 {
	seen := map[uint16]bool{node.SharePort: true}
	ports := []uint16{node.SharePort}
	for _, s := range st.Services {
		if s.Port != 0 && !seen[s.Port] {
			seen[s.Port] = true
			ports = append(ports, s.Port)
		}
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	if len(ports) > resource.MaxProbePorts {
		ports = ports[:resource.MaxProbePorts]
	}
	return ports
}

// serviceName labels a port for display, falling back to LocNet's own.
func serviceName(st node.Status, port uint16) string {
	for _, s := range st.Services {
		if s.Port == port {
			return s.Name
		}
	}
	if port == node.SharePort {
		return "locnet"
	}
	return "-"
}

// firstOnlinePeer picks somebody to ask.
func firstOnlinePeer(st node.Status) (node.PeerStatus, bool) {
	for _, p := range st.Peers {
		if p.Online && p.IP.IsValid() {
			return p, true
		}
	}
	return node.PeerStatus{}, false
}

// reportServiceProblems names this machine's servers that accept connections
// and then refuse everyone — the case every port check above passes.
func reportServiceProblems(st node.Status) {
	var bad []resource.Service
	for _, s := range st.Services {
		if s.Problem != "" {
			bad = append(bad, s)
		}
	}
	if len(bad) == 0 {
		return
	}
	fmt.Println("\n  Servers here that answer but will not let anyone in:")
	for _, s := range bad {
		fmt.Printf("    ✗ %-14s port %d: %s\n", s.Name, s.Port, s.Problem)
	}
}

// reportLocalShares checks that the things this machine publishes are running.
//
// A port share is a forwarder, and a forwarder with nothing behind it still
// accepts connections. That combination advertises a service this machine does
// not have and hands peers a socket that closes without a byte — which reads,
// from the far end, as a broken server rather than an absent one. It is only
// visible from here, so here is where it gets checked.
func reportLocalShares(st node.Status) {
	var ports []resource.Share
	for _, sh := range st.Shares {
		if sh.Kind == resource.KindPort && sh.Port != 0 {
			ports = append(ports, sh)
		}
	}
	if len(ports) == 0 {
		return
	}

	fmt.Println("\n  What this machine publishes:")
	for _, sh := range ports {
		target := sh.Target
		if !strings.Contains(target, ":") {
			target = "127.0.0.1:" + target
		}
		c, err := net.DialTimeout("tcp", target, 3*time.Second)
		if err == nil {
			c.Close()
			fmt.Printf("    ✓ %-14s port %d → %s\n", sh.Name, sh.Port, target)
			continue
		}
		fmt.Printf("    ✗ %-14s port %d → %s is not listening\n", sh.Name, sh.Port, target)
		fmt.Printf("      Peers see this share offered and get an empty connection.\n")
		fmt.Printf("      Start the server, or stop offering it:  locnet share remove %s\n", sh.Name)
	}
}

// reportReachability sends real traffic down the tunnel to every online peer.
//
// Every other check in doctor asks locnetd what it believes. Belief is exactly
// what fails here: the agent can hold a signed netmap, a bound relay and a
// probed direct path — and print a column of ticks — while not one byte of
// tunnelled traffic gets through, because discovery and the tunnel are
// different code paths over the same socket. The only way to know is to use
// it, so this opens a TCP connection to each peer's share server, which every
// locnetd listens on and which is reachable only through the tunnel.
func reportReachability(st node.Status) {
	var peers []node.PeerStatus
	for _, p := range st.Peers {
		if p.Online && p.IP.IsValid() {
			peers = append(peers, p)
		}
	}
	if len(peers) == 0 {
		return
	}

	fmt.Println("\n  Reaching each machine through the tunnel:")

	type result struct {
		name string
		err  error
	}
	results := make([]result, len(peers))
	var wg sync.WaitGroup
	for i, p := range peers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addr := netip.AddrPortFrom(p.IP, node.SharePort).String()
			c, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err == nil {
				c.Close()
			}
			results[i] = result{name: p.Name, err: err}
		}()
	}
	wg.Wait()

	var failed int
	for i, r := range results {
		if r.err == nil {
			fmt.Printf("    ✓ %-14s %s answers on %s\n", r.name, peers[i].IP, peers[i].Path)
			continue
		}
		failed++
		fmt.Printf("    ✗ %-14s %s does not answer (path says %q)\n", r.name, peers[i].IP, peers[i].Path)
	}
	if failed == 0 {
		return
	}
	fmt.Println("\n  A machine that answers probes but not traffic is the tunnel failing, not")
	fmt.Println("  the network: the two use the same UDP socket, so the path shown above is")
	fmt.Println("  not evidence that data flows. Check the far machine is on this version,")
	fmt.Printf("  then look at both logs — %s.\n", daemonLog())
}

func status() (node.Status, error) {
	var st node.Status
	c, err := ipc.Dial()
	if err != nil {
		return st, err
	}
	return st, c.Get("/status", &st)
}

func simplePost(path, okMsg string) error {
	c, err := ipc.Dial()
	if err != nil {
		return err
	}
	if err := c.Post(path, struct{}{}, nil); err != nil {
		return err
	}
	fmt.Println(okMsg)
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
