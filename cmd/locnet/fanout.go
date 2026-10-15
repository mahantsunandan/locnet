package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/mahantsunandan/locnet/internal/node"
	"github.com/mahantsunandan/locnet/internal/peercfg"
	"github.com/mahantsunandan/locnet/internal/remote"
)

// resolveTargets turns a comma-separated list of peer names into SSH targets.
//
// "all" means every online peer, which is the case that makes these commands
// worth having: patching twelve machines is a chore, and typing twelve names
// is where people give up and do it by hand instead.
func resolveTargets(spec string) ([]remote.Target, error) {
	st, err := status()
	if err != nil {
		return nil, err
	}
	if len(st.Peers) == 0 {
		return nil, fmt.Errorf("no peers on this network yet")
	}

	want := map[string]bool{}
	all := strings.TrimSpace(spec) == "" || spec == "all"
	if !all {
		for _, n := range strings.Split(spec, ",") {
			if n = strings.TrimSpace(n); n != "" {
				want[n] = true
			}
		}
	}

	var out []remote.Target
	var skipped, known []string
	for _, p := range st.Peers {
		known = append(known, p.Name)
		if !all && !want[p.Name] && !want[p.IP.String()] {
			continue
		}
		delete(want, p.Name)
		delete(want, p.IP.String())
		if !p.Online {
			skipped = append(skipped, p.Name+" (offline)")
			continue
		}
		out = append(out, targetFor(p))
	}

	for n := range want {
		skipped = append(skipped, n+" (not on this network)")
	}
	if len(skipped) > 0 {
		sort.Strings(skipped)
		fmt.Fprintf(os.Stderr, "locnet: skipping %s\n", strings.Join(skipped, ", "))
	}
	if len(out) == 0 {
		sort.Strings(known)
		return nil, fmt.Errorf("no machines to act on. Known peers: %s", strings.Join(known, ", "))
	}
	sort.Slice(out, func(i, k int) bool { return out[i].Name < out[k].Name })
	return out, nil
}

func targetFor(p node.PeerStatus) remote.Target {
	return remote.Target{Name: p.Name, Host: p.IP.String(), Login: peercfg.UserFor(p.Name), OS: p.OS}
}

// interruptible returns a context cancelled by Ctrl-C, so a transfer to a
// dozen machines can be stopped without leaving orphaned scp processes.
func interruptible() (context.Context, func()) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// printLive prints output as it arrives, prefixed with the machine it came
// from. With one target the prefix is noise, so it is left off.
func printLive(n int) remote.Emit {
	if n == 1 {
		return func(_, line string) { fmt.Println(line) }
	}
	return func(target, line string) { fmt.Printf("%-14s %s\n", target+":", line) }
}

func report(res []remote.Result) error {
	fmt.Println()
	failed := 0
	for _, r := range res {
		if r.OK {
			fmt.Printf("  %-14s ok    %.1fs\n", r.Target, r.Secs)
			continue
		}
		failed++
		fmt.Printf("  %-14s FAIL  %s\n", r.Target, r.Error)
	}
	if failed > 0 {
		return fmt.Errorf("%s", remote.Summarise(res))
	}
	return nil
}

// cmdExec runs one command on several machines over SSH.
func cmdExec(args []string) error {
	fs := flag.NewFlagSet("exec", flag.ExitOnError)
	on := fs.String("on", "all", "machines to run on: comma-separated names, or \"all\"")
	pos, flags := splitArgs(args)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	command := strings.Join(pos, " ")
	if strings.TrimSpace(command) == "" {
		return fmt.Errorf("usage: locnet exec <command> [-on peer1,peer2|all]\n" +
			"Example: locnet exec 'uptime' -on all")
	}

	targets, err := resolveTargets(*on)
	if err != nil {
		return err
	}
	fmt.Printf("locnet: running on %d machine(s): %s\n\n", len(targets), targetNames(targets))

	ctx, stop := interruptible()
	defer stop()
	return report(remote.Exec(ctx, targets, command, printLive(len(targets))))
}

// cmdCopy sends files and folders to several machines over SFTP.
func cmdCopy(args []string) error {
	fs := flag.NewFlagSet("copy", flag.ExitOnError)
	to := fs.String("to", "", "machines to send to: comma-separated names, or \"all\"")
	dest := fs.String("dest", "", "destination path on the far machine (default: home directory)")
	pos, flags := splitArgs(args)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) == 0 || *to == "" {
		return fmt.Errorf("usage: locnet copy <file|folder>... -to peer1,peer2|all [-dest /path]\n" +
			"Example: locnet copy report.pdf notes/ -to all -dest /tmp")
	}
	for _, p := range pos {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("cannot send %s: %w", p, err)
		}
	}

	targets, err := resolveTargets(*to)
	if err != nil {
		return err
	}
	where := *dest
	if where == "" {
		where = "the home directory"
	}
	fmt.Printf("locnet: sending %d item(s) to %s → %s\n\n", len(pos), targetNames(targets), where)

	ctx, stop := interruptible()
	defer stop()
	return report(remote.Copy(ctx, targets, pos, *dest, printLive(len(targets))))
}

// cmdFetch pulls a path from several machines at once.
func cmdFetch(args []string) error {
	fs := flag.NewFlagSet("fetch", flag.ExitOnError)
	from := fs.String("from", "", "machines to fetch from: comma-separated names, or \"all\"")
	into := fs.String("into", ".", "local folder to collect into")
	pos, flags := splitArgs(args)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 || *from == "" {
		return fmt.Errorf("usage: locnet fetch <remote-path> -from peer1,peer2|all [-into dir]\n" +
			"Example: locnet fetch /var/log/syslog -from all -into ./logs")
	}

	targets, err := resolveTargets(*from)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*into, 0o755); err != nil {
		return err
	}
	// One subfolder per machine: see remote.Fetch. Collecting syslog from
	// six machines into one folder would leave one file.
	for _, t := range targets {
		if err := os.MkdirAll(*into+string(os.PathSeparator)+t.Name, 0o755); err != nil {
			return err
		}
	}
	fmt.Printf("locnet: fetching %s from %s into %s\n\n", pos[0], targetNames(targets), *into)

	ctx, stop := interruptible()
	defer stop()
	return report(remote.Fetch(ctx, targets, pos[0], *into, printLive(len(targets))))
}

func targetNames(t []remote.Target) string {
	out := make([]string, 0, len(t))
	for _, x := range t {
		out = append(out, x.Name)
	}
	return strings.Join(out, ", ")
}
