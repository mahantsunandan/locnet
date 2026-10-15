package policy

import (
	"fmt"
	"sort"
)

// portSet is a set of ports kept as sorted, non-overlapping, non-adjacent
// ranges. Block rules make the ports a pair may use a difference of two
// unions, which is easiest to get right as plain set arithmetic.
type portSet []PortRange

// fullSet is every port.
var fullSet = portSet{{Lo: 0, Hi: 65535}}

// specSet turns a rule's port list into a set. An empty list is every port,
// as it is everywhere in a policy; a spec that does not parse adds nothing
// (Validate has refused it already).
func specSet(specs []string) portSet {
	if len(specs) == 0 {
		return fullSet
	}
	var out portSet
	for _, spec := range specs {
		lo, hi, err := parsePorts(spec)
		if err != nil {
			continue
		}
		out = append(out, PortRange{Lo: lo, Hi: hi})
	}
	return out.normal()
}

// normal sorts and merges, so equal sets compare equal.
func (s portSet) normal() portSet {
	if len(s) == 0 {
		return nil
	}
	in := append(portSet(nil), s...)
	sort.Slice(in, func(i, j int) bool { return in[i].Lo < in[j].Lo })
	out := portSet{in[0]}
	for _, r := range in[1:] {
		last := &out[len(out)-1]
		if uint32(r.Lo) <= uint32(last.Hi)+1 {
			if r.Hi > last.Hi {
				last.Hi = r.Hi
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

func (s portSet) union(o portSet) portSet { return append(append(portSet(nil), s...), o...).normal() }

// minus is s without anything in o.
func (s portSet) minus(o portSet) portSet {
	out := append(portSet(nil), s.normal()...)
	for _, cut := range o.normal() {
		var next portSet
		for _, r := range out {
			if cut.Hi < r.Lo || cut.Lo > r.Hi {
				next = append(next, r)
				continue
			}
			if cut.Lo > r.Lo {
				next = append(next, PortRange{Lo: r.Lo, Hi: cut.Lo - 1})
			}
			if cut.Hi < r.Hi {
				next = append(next, PortRange{Lo: cut.Hi + 1, Hi: r.Hi})
			}
		}
		out = next
	}
	return out
}

func (s portSet) intersect(o portSet) portSet { return s.minus(s.minus(o)) }

func (s portSet) has(port uint16) bool {
	for _, r := range s {
		if port >= r.Lo && port <= r.Hi {
			return true
		}
	}
	return false
}

func (s portSet) full() bool {
	n := s.normal()
	return len(n) == 1 && n[0] == fullSet[0]
}

// specs renders the set back as a rule's port list: "*", "22", "8000-8100".
func (s portSet) specs() []string {
	if s.full() {
		return []string{Wildcard}
	}
	var out []string
	for _, r := range s.normal() {
		if r.Lo == r.Hi {
			out = append(out, fmt.Sprint(r.Lo))
		} else {
			out = append(out, fmt.Sprintf("%d-%d", r.Lo, r.Hi))
		}
	}
	return out
}
