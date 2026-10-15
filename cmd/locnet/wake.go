package main

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/mahantsunandan/locnet/internal/node"
	"github.com/mahantsunandan/locnet/internal/resource"
	"github.com/mahantsunandan/locnet/internal/shareclient"
	"github.com/mahantsunandan/locnet/internal/wake"
)

const wakeUsage = `Usage:
  locnet wake <peer>       turn a machine on
  locnet wake <peer> -via <other-peer>
                           choose who sends the packet

The machine being woken is not running anything — it is off. So the packet
comes from a peer that is still on and is plugged into the same network, and
LocNet knows which peers those are because every machine reports the subnets it
sits on while it is awake.

For this to work at all, Wake-on-LAN has to be enabled in that machine's
firmware (often "Power on by PCI-E" or "Wake on LAN") and in its operating
system's network adapter settings. Nothing LocNet can check from here.`

func cmdWake(args []string) error {
	pos, flagArgs := splitArgs(args)
	if len(pos) == 0 {
		return fmt.Errorf("which machine? Try: locnet wake <peer>\n\n%s", wakeUsage)
	}
	fs := flag.NewFlagSet("wake", flag.ExitOnError)
	via := fs.String("via", "", "peer that should send the packet")
	waitFor := fs.Duration("wait", 0, "wait this long for the machine to come back")
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}

	st, err := status()
	if err != nil {
		return err
	}
	target, err := resolvePeer(pos[0])
	if err != nil {
		return err
	}
	if target.Online {
		fmt.Printf("%s is already up.\n", target.Name)
		return nil
	}
	macs := resource.MACs(target.LAN)
	if len(macs) == 0 {
		return fmt.Errorf("%s has never reported a hardware address, so there is nothing to wake.\n"+
			"That happens when it has not been seen since this version of LocNet was installed there —\n"+
			"start it once by hand and it will be wakeable from then on", target.Name)
	}

	sender, err := pickWaker(st, target, *via)
	if err != nil {
		return err
	}

	var sent int
	if sender.Name == "" {
		sent, err = wake.Send(macs, st.LAN)
		if err != nil {
			return err
		}
		fmt.Printf("Sent %d magic packet(s) for %s from this machine.\n", sent, target.Name)
	} else {
		peer, err := resolvePeer(sender.Name)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		sent, err = shareclient.New(peer.IP).Wake(ctx, macs)
		if err != nil {
			return fmt.Errorf("%s could not send it: %w", sender.Name, err)
		}
		fmt.Printf("Sent %d magic packet(s) for %s via %s — %s.\n",
			sent, target.Name, sender.Name, sender.Reason)
	}

	if *waitFor <= 0 {
		fmt.Println("Give it a minute, then: locnet status")
		return nil
	}
	return waitForPeer(target.Name, *waitFor)
}

// pickWaker decides which machine should send the packet.
func pickWaker(st node.Status, target node.PeerStatus, via string) (wake.Waker, error) {
	if via != "" {
		peer, err := resolvePeer(via)
		if err != nil {
			return wake.Waker{}, err
		}
		if !peer.Online {
			return wake.Waker{}, fmt.Errorf("%s is offline, so it cannot send anything", peer.Name)
		}
		return wake.Waker{Name: peer.Name, Reason: "you chose it"}, nil
	}

	candidates := map[string][]resource.LANIface{}
	for _, p := range st.Peers {
		if p.Online && p.Name != target.Name && len(p.LAN) > 0 {
			candidates[p.Name] = p.LAN
		}
	}
	w, ok := wake.Choose(target.LAN, st.LAN, candidates)
	if !ok {
		return wake.Waker{}, fmt.Errorf(
			"no machine that is up shares a network with %s.\n"+
				"A magic packet is a broadcast and does not cross a router, so something on\n"+
				"%s has to send it. Known addresses for it: %s",
			target.Name, target.Name, strings.Join(addrList(target.LAN), ", "))
	}
	return w, nil
}

func addrList(ifaces []resource.LANIface) []string {
	var out []string
	for _, a := range resource.Addrs(ifaces) {
		out = append(out, a.String())
	}
	if len(out) == 0 {
		out = []string{"none"}
	}
	return out
}

// waitForPeer polls until the machine reappears, so a script can wake a
// machine and then use it.
func waitForPeer(name string, limit time.Duration) error {
	fmt.Printf("Waiting up to %s for %s…\n", limit, name)
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		time.Sleep(5 * time.Second)
		p, err := resolvePeer(name)
		if err == nil && p.Online {
			fmt.Printf("%s is up (%s).\n", name, p.IP)
			return nil
		}
	}
	return fmt.Errorf("%s has not come back within %s.\n"+
		"Wake-on-LAN may be disabled in its firmware, or the packet did not reach it", name, limit)
}
