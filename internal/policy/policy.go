// Package policy decides which machines may talk to which, and on what ports.
//
// The model is deliberately small: named groups of machines, and a list of
// accept rules over them. There is no deny rule and no ordering to reason
// about — traffic is permitted if some rule permits it, and refused otherwise.
// Policies that read top-to-bottom with shadowing rules are how people end up
// with a firewall nobody can explain.
//
// Enforcement happens in two places, and the split matters:
//
//   - Machine-level rules are enforced by *leaving a peer out of the network
//     map*. No map entry means no WireGuard peer, no key, and no path. This is
//     enforced by the cryptography rather than by a check somebody could
//     forget to make.
//   - Port-level rules are enforced by a packet filter in the agent, because
//     WireGuard's allowed-IPs cannot express a port.
//
// A machine denied at the first level never even learns the other exists.
package policy

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Wildcard matches every machine or every port.
const Wildcard = "*"

// Rule permits traffic from one set of machines to another.
type Rule struct {
	// Src and Dst are group names, machine names, or "*".
	Src []string `json:"src"`
	Dst []string `json:"dst"`
	// Ports are "*", a number, or a range like "8000-8100". An empty list
	// means every port, which is the same as ["*"].
	Ports []string `json:"ports,omitempty"`
	// Comment is why this rule exists. Worth filling in.
	Comment string `json:"comment,omitempty"`
}

// Policy is the whole rule set for a network.
type Policy struct {
	// Groups maps a group name to the machine names in it. A machine may be
	// in several groups.
	Groups map[string][]string `json:"groups,omitempty"`
	Rules  []Rule              `json:"rules"`
	// Blocks take ports away again, and always win: traffic is permitted if
	// some rule permits it and no block refuses it. Order still means
	// nothing. They exist so one connection can be switched off — "winpc-01
	// may not SSH to hubpc" — without rewriting the rules that grant
	// everything else.
	Blocks []Rule `json:"blocks,omitempty"`
}

// Default is the policy a new network starts with: everything may reach
// everything.
//
// Starting closed would be more defensible in the abstract and worse in
// practice — the first thing anybody does with a new mesh is check that two
// machines can ping each other, and a network that silently refuses that
// teaches people to distrust the tool before they have learned it. Opening
// with an explicit, visible allow-all rule makes the choice legible and makes
// tightening it a deliberate edit.
func Default() *Policy {
	return &Policy{
		Rules: []Rule{{
			Src:     []string{Wildcard},
			Dst:     []string{Wildcard},
			Ports:   []string{Wildcard},
			Comment: "default: every machine may reach every machine",
		}},
	}
}

// Validate checks a policy for the mistakes that make one useless.
func (p *Policy) Validate() error {
	if p == nil {
		return fmt.Errorf("policy is empty")
	}
	for name, members := range p.Groups {
		if name == Wildcard {
			return fmt.Errorf("a group cannot be called %q", Wildcard)
		}
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("a group name cannot be blank")
		}
		if len(members) == 0 {
			return fmt.Errorf("group %q has no members", name)
		}
	}
	if err := validateRules("block", p.Blocks); err != nil {
		return err
	}
	return validateRules("rule", p.Rules)
}

func validateRules(kind string, rules []Rule) error {
	for i, r := range rules {
		if len(r.Src) == 0 || len(r.Dst) == 0 {
			return fmt.Errorf("%s %d needs both src and dst", kind, i+1)
		}
		for _, ref := range append(append([]string{}, r.Src...), r.Dst...) {
			if ref == Wildcard {
				continue
			}
			if strings.TrimSpace(ref) == "" {
				return fmt.Errorf("%s %d has a blank name", kind, i+1)
			}
		}
		for _, spec := range r.Ports {
			if _, _, err := parsePorts(spec); err != nil {
				return fmt.Errorf("%s %d: %w", kind, i+1, err)
			}
		}
	}
	return nil
}

// expand resolves a src/dst reference into machine names. An unknown name is
// treated as a machine name, so a policy can name a machine before it joins.
func (p *Policy) expand(ref string, allMachines []string) []string {
	if ref == Wildcard {
		return allMachines
	}
	if members, ok := p.Groups[ref]; ok {
		var out []string
		for _, m := range members {
			// A group may contain another group.
			if _, nested := p.Groups[m]; nested && m != ref {
				out = append(out, p.expand(m, allMachines)...)
				continue
			}
			out = append(out, m)
		}
		return out
	}
	return []string{ref}
}

// GroupsFor lists the groups a machine belongs to.
func (p *Policy) GroupsFor(machine string) []string {
	var out []string
	for name := range p.Groups {
		for _, m := range p.expand(name, nil) {
			if m == machine {
				out = append(out, name)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// CanReach reports whether src may open a connection to dst on port, and
// whether any port at all is permitted between them.
//
// The second return value is what drives netmap filtering: a pair with no
// permitted port has no reason to know about each other.
func (p *Policy) CanReach(src, dst string, port uint16, allMachines []string) (allowed, anyPort bool) {
	if src == dst {
		return true, true // a machine may always reach itself
	}
	eff := p.effective(src, dst, allMachines)
	anyPort = len(eff) > 0
	if port == 0 {
		return anyPort, anyPort
	}
	return eff.has(port), anyPort
}

// Reachable returns every machine src may open a connection to, plus every
// machine that may open one to src.
//
// Both directions matter. A tunnel is not one-way: if the stations may be
// reached by the workstation, the workstation must appear in each station's
// map too, or the reply packets have nowhere to go.
func (p *Policy) Reachable(machine string, allMachines []string) map[string]bool {
	out := map[string]bool{}
	for _, other := range allMachines {
		if other == machine {
			continue
		}
		if _, any := p.CanReach(machine, other, 0, allMachines); any {
			out[other] = true
			continue
		}
		if _, any := p.CanReach(other, machine, 0, allMachines); any {
			out[other] = true
		}
	}
	return out
}

func (p *Policy) expand2(refs, allMachines []string) []string {
	var out []string
	for _, r := range refs {
		out = append(out, p.expand(r, allMachines)...)
	}
	return out
}

// PortRange is a resolved, inclusive port range.
// NoPorts is the range that permits nothing: port 0 is never the
// destination of a real connection. The hub sends it for a peer that may
// reach no port at all, because an empty list means "every port".
var NoPorts = PortRange{Lo: 0, Hi: 0}

type PortRange struct {
	Lo uint16 `json:"lo"`
	Hi uint16 `json:"hi"`
}

// InboundPorts returns the ports src may reach on dst, already resolved to
// ranges so the agent's packet filter does no parsing per packet.
//
// all=true means every port, and is the common case — the hub sends nothing
// for those pairs and the agent skips filtering entirely.
func (p *Policy) InboundPorts(src, dst string, allMachines []string) (ranges []PortRange, all bool) {
	eff := p.effective(src, dst, allMachines)
	if eff.full() {
		return nil, true
	}
	return []PortRange(eff), false
}

// effective is what src may reach on dst: every port some rule grants, less
// every port some block refuses.
func (p *Policy) effective(src, dst string, allMachines []string) portSet {
	granted := p.matching(p.Rules, src, dst, allMachines)
	if len(granted) == 0 {
		return nil
	}
	return granted.minus(p.matching(p.Blocks, src, dst, allMachines))
}

// matching is the union of the ports of every rule in rules that covers the
// pair.
func (p *Policy) matching(rules []Rule, src, dst string, allMachines []string) portSet {
	var out portSet
	for _, r := range rules {
		if !contains(p.expand2(r.Src, allMachines), src) || !contains(p.expand2(r.Dst, allMachines), dst) {
			continue
		}
		out = out.union(specSet(r.Ports))
	}
	return out
}

// ------------------------------------------------------------- ports

// parsePorts accepts "*", "22", or "8000-8100".
func parsePorts(spec string) (lo, hi uint16, err error) {
	spec = strings.TrimSpace(spec)
	if spec == Wildcard || spec == "" {
		return 0, 65535, nil
	}
	if a, b, ok := strings.Cut(spec, "-"); ok {
		lo64, err1 := strconv.ParseUint(strings.TrimSpace(a), 10, 16)
		hi64, err2 := strconv.ParseUint(strings.TrimSpace(b), 10, 16)
		if err1 != nil || err2 != nil {
			return 0, 0, fmt.Errorf("bad port range %q", spec)
		}
		if lo64 > hi64 {
			return 0, 0, fmt.Errorf("port range %q runs backwards", spec)
		}
		return uint16(lo64), uint16(hi64), nil
	}
	n, err := strconv.ParseUint(spec, 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("bad port %q", spec)
	}
	return uint16(n), uint16(n), nil
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// Summary renders the policy for `locnet-hub policy`.
func (p *Policy) Summary() string {
	var b strings.Builder
	if len(p.Groups) > 0 {
		b.WriteString("Groups\n")
		names := make([]string, 0, len(p.Groups))
		for n := range p.Groups {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			fmt.Fprintf(&b, "  %-16s %s\n", n, strings.Join(p.Groups[n], ", "))
		}
		b.WriteString("\n")
	}
	b.WriteString("Rules\n")
	for i, r := range p.Rules {
		ports := "any port"
		if len(r.Ports) > 0 && !contains(r.Ports, Wildcard) {
			ports = "ports " + strings.Join(r.Ports, ",")
		}
		fmt.Fprintf(&b, "  %d. %s → %s (%s)\n",
			i+1, strings.Join(r.Src, ","), strings.Join(r.Dst, ","), ports)
		if r.Comment != "" {
			fmt.Fprintf(&b, "     %s\n", r.Comment)
		}
	}
	if len(p.Blocks) > 0 {
		b.WriteString("\nBlocks (always win over rules)\n")
		for i, r := range p.Blocks {
			fmt.Fprintf(&b, "  %d. %s ✗ %s (%s)\n",
				i+1, strings.Join(r.Src, ","), strings.Join(r.Dst, ","), DescribePorts(r.Ports))
			if r.Comment != "" {
				fmt.Fprintf(&b, "     %s\n", r.Comment)
			}
		}
	}
	return b.String()
}
