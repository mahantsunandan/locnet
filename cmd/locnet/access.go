package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/mahantsunandan/locnet/internal/hub"
	"github.com/mahantsunandan/locnet/internal/policy"
)

const accessUsage = `Usage:
  locnet admin access                               who may connect to whom
  locnet admin access block <from> <to> [service…]  stop <from> opening connections to <to>
  locnet admin access allow <from> <to> [service…]  let it again

Services: ssh, vnc, rdp, smb, locnet (files, compute and shares), all — or
port numbers and ranges. No service means all of them. <from> and <to> are
machine names, policy groups, or "*".

Examples:
  locnet admin access block winpc-01 hubpc ssh vnc
  locnet admin access allow winpc-01 hubpc vnc
  locnet admin access block winpc-01 linuxbox        # every port

A block is one-way: the other machine can still connect to <from>, and its
replies come back. Changes reach every machine within seconds and are kept in
the hub's audit log (locnet admin audit). This decides who may *connect*; each
machine still decides for itself whether it shares files or runs jobs at all.`

func cmdAccess(args []string) error {
	if len(args) == 0 {
		return accessShow()
	}
	switch args[0] {
	case "allow", "block":
		if len(args) < 3 {
			return errors.New(accessUsage)
		}
		return accessChange(hub.AccessChange{Action: args[0], Src: args[1], Dst: args[2], Services: args[3:]})
	case "-h", "--help", "help":
		fmt.Println(accessUsage)
		return nil
	default:
		return fmt.Errorf("unknown access command %q\n\n%s", args[0], accessUsage)
	}
}

func accessShow() error {
	var v policy.AccessView
	if err := manageCall("access", map[string]string{}, &v); err != nil {
		return err
	}
	printAccess(v)
	return nil
}

func accessChange(c hub.AccessChange) error {
	ports, err := policy.ParseServices(c.Services)
	if err != nil {
		return err
	}
	var v policy.AccessView
	if err := manageCall("access", c, &v); err != nil {
		return err
	}
	verb := "may now"
	if c.Action == "block" {
		verb = "may no longer"
	}
	fmt.Printf("%s %s open %s on %s.\n\n", c.Src, verb, policy.DescribePorts(ports), c.Dst)
	printAccess(v)
	return nil
}

// printAccess draws the matrix: one row per machine connecting, one column per
// machine connected to.
func printAccess(v policy.AccessView) {
	cell := map[[2]string]string{}
	for _, p := range v.Pairs {
		cell[[2]string{p.Src, p.Dst}] = p.Describe()
	}
	fmt.Println("Who may open connections to whom (row → column):")
	fmt.Println()
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(tw, "FROM \\ TO\t%s\n", strings.Join(v.Machines, "\t"))
	for _, src := range v.Machines {
		row := []string{src}
		for _, dst := range v.Machines {
			if src == dst {
				row = append(row, "·")
			} else {
				row = append(row, cell[[2]string{src, dst}])
			}
		}
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	tw.Flush()

	if v.Policy != nil && len(v.Policy.Blocks) > 0 {
		fmt.Println("\nBlocks in force:")
		for _, b := range v.Policy.Blocks {
			fmt.Printf("  %s ✗ %s  %s\n", strings.Join(b.Src, ","), strings.Join(b.Dst, ","), policy.DescribePorts(b.Ports))
		}
	}
	var names []string
	for _, s := range v.Services {
		names = append(names, fmt.Sprintf("%s %d", s.Name, s.Port))
	}
	fmt.Printf("\nServices: %s. Change with: locnet admin access block|allow <from> <to> [service…]\n",
		strings.Join(names, ", "))
}
