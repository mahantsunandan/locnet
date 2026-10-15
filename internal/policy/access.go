package policy

import (
	"fmt"
	"sort"
	"strings"
)

// Switching single connections on and off.
//
// A policy is written by hand as groups and rules. What an operator usually
// wants afterwards is narrower — "winpc-01 may not SSH to hubpc", "let it
// again" — and asking them to rework the rules for that is how policies end up
// with a rule nobody can explain. Allow and Block make exactly that change and
// no other: they edit only rules and blocks written for that one pair, and
// never touch the group rules an operator wrote.

// Service is a well-known port, named the way people think of it.
type Service struct {
	Name string `json:"name"`
	Port uint16 `json:"port"`
	Desc string `json:"desc"`
}

// Services are the connections the access controls name. "locnet" is one
// port for several things — files, compute and the desktop helper all speak
// to the share server — so it cannot be split further at the network.
var Services = []Service{
	{Name: "ssh", Port: 22, Desc: "SSH: shells, exec, copy, fetch, job"},
	{Name: "vnc", Port: 5900, Desc: "VNC screen sharing"},
	{Name: "rdp", Port: 3389, Desc: "Remote Desktop"},
	{Name: "smb", Port: 445, Desc: "Windows file sharing"},
	{Name: "locnet", Port: 8421, Desc: "LocNet files, compute and shares"},
}

// ParseServices turns what an operator typed — service names, "all", port
// numbers or ranges — into a rule's port list. Nothing means everything.
func ParseServices(args []string) ([]string, error) {
	if len(args) == 0 {
		return []string{Wildcard}, nil
	}
	var set portSet
	for _, a := range args {
		for _, word := range strings.Split(a, ",") {
			word = strings.ToLower(strings.TrimSpace(word))
			if word == "" {
				continue
			}
			if word == "all" || word == Wildcard {
				return []string{Wildcard}, nil
			}
			if svc, ok := serviceByName(word); ok {
				set = set.union(portSet{{Lo: svc.Port, Hi: svc.Port}})
				continue
			}
			lo, hi, err := parsePorts(word)
			if err != nil {
				return nil, fmt.Errorf("%q is not a service (%s, all) or a port", word, serviceNames())
			}
			set = set.union(portSet{{Lo: lo, Hi: hi}})
		}
	}
	if len(set) == 0 {
		return []string{Wildcard}, nil
	}
	return set.specs(), nil
}

func serviceByName(name string) (Service, bool) {
	for _, s := range Services {
		if s.Name == name {
			return s, true
		}
	}
	return Service{}, false
}

func serviceNames() string {
	var n []string
	for _, s := range Services {
		n = append(n, s.Name)
	}
	return strings.Join(n, ", ")
}

// DescribePorts names a port list for people: "ssh, vnc", "every port".
func DescribePorts(specs []string) string {
	set := specSet(specs)
	if set.full() {
		return "every port"
	}
	var out []string
	rest := set
	for _, s := range Services {
		if set.has(s.Port) {
			out = append(out, s.Name)
			rest = rest.minus(portSet{{Lo: s.Port, Hi: s.Port}})
		}
	}
	if len(rest) > 0 {
		out = append(out, "ports "+strings.Join(rest.specs(), ","))
	}
	return strings.Join(out, ", ")
}

// Clone copies a policy deeply, so an edit can be tried and thrown away.
func (p *Policy) Clone() *Policy {
	c := &Policy{Groups: map[string][]string{}}
	for k, v := range p.Groups {
		c.Groups[k] = append([]string(nil), v...)
	}
	cp := func(rs []Rule) []Rule {
		var out []Rule
		for _, r := range rs {
			r.Src = append([]string(nil), r.Src...)
			r.Dst = append([]string(nil), r.Dst...)
			r.Ports = append([]string(nil), r.Ports...)
			out = append(out, r)
		}
		return out
	}
	c.Rules, c.Blocks = cp(p.Rules), cp(p.Blocks)
	if len(c.Groups) == 0 {
		c.Groups = nil
	}
	return c
}

// Allow lets src open connections to dst on ports.
//
// Blocks written for exactly this pair give the ports back first. If that is
// not enough — nothing grants them — an allow rule for the pair is added, or
// widened if one exists. A block written for a group or "*" is the
// operator's own and is left alone; if one still refuses some of the ports,
// Allow changes nothing and says which.
func (p *Policy) Allow(src, dst string, ports []string, comment string, allMachines []string) error {
	want := specSet(ports)
	next := p.Clone()

	next.Blocks = trimPair(next.Blocks, src, dst, want)
	missing := want.minus(next.effective(src, dst, allMachines))
	if len(missing) > 0 {
		if i := pairIndex(next.Rules, src, dst); i >= 0 {
			next.Rules[i].Ports = specSet(next.Rules[i].Ports).union(missing).specs()
		} else {
			next.Rules = append(next.Rules, Rule{Src: []string{src}, Dst: []string{dst},
				Ports: missing.specs(), Comment: comment})
		}
	}
	if still := want.minus(next.effective(src, dst, allMachines)); len(still) > 0 {
		return fmt.Errorf("%s → %s %s is still refused by a block written for a group or every machine; "+
			"edit the policy (locnet-hub policy edit) to change that one",
			src, dst, DescribePorts(still.specs()))
	}
	*p = *next
	return nil
}

// Block stops src opening connections to dst on ports.
//
// Allow rules written for exactly this pair lose the ports, and a block for
// the pair records them — whether or not anything grants them today, so that
// a group rule added later cannot quietly undo it.
func (p *Policy) Block(src, dst string, ports []string, comment string) {
	want := specSet(ports)
	p.Rules = trimPair(p.Rules, src, dst, want)
	if i := pairIndex(p.Blocks, src, dst); i >= 0 {
		p.Blocks[i].Ports = specSet(p.Blocks[i].Ports).union(want).specs()
		return
	}
	p.Blocks = append(p.Blocks, Rule{Src: []string{src}, Dst: []string{dst}, Ports: want.specs(), Comment: comment})
}

// pairIndex finds the rule written for exactly src → dst.
func pairIndex(rules []Rule, src, dst string) int {
	for i, r := range rules {
		if isPair(r, src, dst) {
			return i
		}
	}
	return -1
}

func isPair(r Rule, src, dst string) bool {
	return len(r.Src) == 1 && r.Src[0] == src && len(r.Dst) == 1 && r.Dst[0] == dst
}

// trimPair takes ports out of the rules written for exactly src → dst, and
// drops any rule left with none.
func trimPair(rules []Rule, src, dst string, ports portSet) []Rule {
	var out []Rule
	for _, r := range rules {
		if isPair(r, src, dst) {
			left := specSet(r.Ports).minus(ports)
			if len(left) == 0 {
				continue
			}
			r.Ports = left.specs()
		}
		out = append(out, r)
	}
	return out
}

// PairAccess is what one machine may open on another.
type PairAccess struct {
	Src   string      `json:"src"`
	Dst   string      `json:"dst"`
	All   bool        `json:"all,omitempty"`
	Ports []PortRange `json:"ports,omitempty"`
	// Desc is Describe's summary, sent so the console words it the same
	// way as the CLI.
	Desc string `json:"desc"`
}

// AccessView is the whole matrix, for the CLI and the console.
type AccessView struct {
	Machines []string     `json:"machines"`
	Services []Service    `json:"services"`
	Pairs    []PairAccess `json:"pairs"`
	Policy   *Policy      `json:"policy"`
}

// View resolves the policy into every ordered pair of machines.
func (p *Policy) View(machines []string) AccessView {
	ms := append([]string(nil), machines...)
	sort.Strings(ms)
	v := AccessView{Machines: ms, Services: Services, Policy: p}
	for _, src := range ms {
		for _, dst := range ms {
			if src == dst {
				continue
			}
			eff := p.effective(src, dst, ms)
			pa := PairAccess{Src: src, Dst: dst, All: eff.full(), Ports: []PortRange(eff)}
			pa.Desc = pa.Describe()
			v.Pairs = append(v.Pairs, pa)
		}
	}
	return v
}

// Allows reports whether the pair may use port.
func (a PairAccess) Allows(port uint16) bool { return a.All || portSet(a.Ports).has(port) }

// Describe sums the pair up for a person: "all", "none", "ssh, vnc", or —
// when it is everything less a few services — "all but ssh".
func (a PairAccess) Describe() string {
	if a.All {
		return "all"
	}
	allowed := portSet(a.Ports)
	if len(allowed) == 0 {
		return "none"
	}
	refused := fullSet.minus(allowed)
	named := true
	for _, r := range refused {
		for p := uint32(r.Lo); p <= uint32(r.Hi); p++ {
			if _, ok := serviceByPort(uint16(p)); !ok && p != 0 {
				named = false
				break
			}
		}
		if !named {
			break
		}
	}
	if named {
		return "all but " + DescribePorts(refused.minus(portSet{{0, 0}}).specs())
	}
	return DescribePorts(allowed.specs())
}

func serviceByPort(port uint16) (Service, bool) {
	for _, s := range Services {
		if s.Port == port {
			return s, true
		}
	}
	return Service{}, false
}
