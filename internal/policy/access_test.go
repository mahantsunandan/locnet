package policy

import (
	"reflect"
	"strings"
	"testing"
)

var machines = []string{"linuxbox", "winpc-01", "hubpc"}

func TestPortSetArithmetic(t *testing.T) {
	s := specSet([]string{"20-30", "25", "31", "100"})
	if got := s.specs(); !reflect.DeepEqual(got, []string{"20-31", "100"}) {
		t.Errorf("normalised to %v", got)
	}
	if got := fullSet.minus(portSet{{22, 22}}).specs(); !reflect.DeepEqual(got, []string{"0-21", "23-65535"}) {
		t.Errorf("every port but 22 = %v", got)
	}
	if got := s.intersect(specSet([]string{"30-200"})).specs(); !reflect.DeepEqual(got, []string{"30-31", "100"}) {
		t.Errorf("intersection = %v", got)
	}
	if !fullSet.minus(portSet{{0, 0}}).union(portSet{{0, 0}}).full() {
		t.Error("taking a port out and putting it back is not the full set")
	}
	if len(specSet([]string{"22"}).minus(fullSet)) != 0 {
		t.Error("anything minus everything should be nothing")
	}
}

func TestParseServices(t *testing.T) {
	for in, want := range map[string][]string{
		"":              {"*"},
		"all":           {"*"},
		"ssh":           {"22"},
		"vnc,ssh":       {"22", "5900"},
		"rdp 8000-8100": {"3389", "8000-8100"},
		"locnet":        {"8421"},
	} {
		got, err := ParseServices(strings.Fields(in))
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("ParseServices(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseServices([]string{"telnet"}); err == nil {
		t.Error("an unknown service name was accepted")
	}
}

// Under an open policy, blocking one service takes exactly that port away,
// in one direction only, and allowing it again leaves no trace.
func TestBlockThenAllowUnderOpenPolicy(t *testing.T) {
	p := Default()
	p.Block("winpc-01", "hubpc", []string{"22"}, "test")

	if ok, _ := p.CanReach("winpc-01", "hubpc", 22, machines); ok {
		t.Error("winpc-01 can still SSH to hubpc")
	}
	if ok, _ := p.CanReach("winpc-01", "hubpc", 5900, machines); !ok {
		t.Error("blocking SSH also took VNC away")
	}
	if ok, _ := p.CanReach("hubpc", "winpc-01", 22, machines); !ok {
		t.Error("blocking one direction blocked the other")
	}
	if ranges, all := p.InboundPorts("winpc-01", "hubpc", machines); all ||
		!reflect.DeepEqual(portSet(ranges).specs(), []string{"0-21", "23-65535"}) {
		t.Errorf("InboundPorts = %v, %v", ranges, all)
	}

	if err := p.Allow("winpc-01", "hubpc", []string{"22"}, "test", machines); err != nil {
		t.Fatal(err)
	}
	if len(p.Blocks) != 0 || len(p.Rules) != 1 {
		t.Errorf("after allowing it back: %d rules, %d blocks; want the original 1 rule and no blocks", len(p.Rules), len(p.Blocks))
	}
}

// Today's live policy: home machines reach everything, winpc-01 nothing at
// home. Allowing one service adds one narrow rule; blocking it again removes
// that rule rather than piling a block on top.
func TestAllowAndBlockOnAOneWayPolicy(t *testing.T) {
	p := &Policy{
		Groups: map[string][]string{"home": {"linuxbox", "hubpc"}},
		Rules:  []Rule{{Src: []string{"home"}, Dst: []string{Wildcard}}},
	}
	if err := p.Allow("winpc-01", "hubpc", []string{"5900"}, "test", machines); err != nil {
		t.Fatal(err)
	}
	if ok, _ := p.CanReach("winpc-01", "hubpc", 5900, machines); !ok {
		t.Error("allowed VNC is not reachable")
	}
	if ok, _ := p.CanReach("winpc-01", "hubpc", 22, machines); ok {
		t.Error("allowing VNC let SSH through too")
	}
	if ok, _ := p.CanReach("winpc-01", "linuxbox", 5900, machines); ok {
		t.Error("allowing hubpc opened linuxbox")
	}

	p.Block("winpc-01", "hubpc", []string{"5900"}, "test")
	if ok, _ := p.CanReach("winpc-01", "hubpc", 5900, machines); ok {
		t.Error("blocked VNC is still reachable")
	}
	if pairIndex(p.Rules, "winpc-01", "hubpc") >= 0 {
		t.Error("the now-empty pair rule was left behind")
	}
	if len(p.Rules) != 1 || p.Rules[0].Src[0] != "home" {
		t.Errorf("the operator's own rule was changed: %+v", p.Rules)
	}
}

// A block the operator wrote for a group is theirs. Allow must not quietly
// work around it, and must leave the policy as it was.
func TestAllowRefusesToOverrideAGroupBlock(t *testing.T) {
	p := Default()
	p.Groups = map[string][]string{"guests": {"winpc-01"}}
	p.Blocks = []Rule{{Src: []string{"guests"}, Dst: []string{Wildcard}, Ports: []string{"22"}}}
	before := p.Clone()
	if err := p.Allow("winpc-01", "hubpc", []string{"22"}, "test", machines); err == nil {
		t.Fatal("Allow went around a group block")
	}
	if !reflect.DeepEqual(p, before) {
		t.Errorf("a refused Allow changed the policy:\n%+v", p)
	}
}

// Blocking every port in both directions takes a pair out of each other's
// network map; one direction alone must not, or replies could not flow.
func TestBlockingAllPortsAndTheNetmap(t *testing.T) {
	p := Default()
	p.Block("winpc-01", "hubpc", []string{Wildcard}, "test")
	if !p.Reachable("hubpc", machines)["winpc-01"] {
		t.Error("a one-way block removed the pair from the map")
	}
	if ranges, all := p.InboundPorts("winpc-01", "hubpc", machines); all || len(ranges) != 0 {
		t.Errorf("fully blocked direction resolves to %v, %v; want no ports", ranges, all)
	}
	p.Block("hubpc", "winpc-01", []string{Wildcard}, "test")
	if p.Reachable("hubpc", machines)["winpc-01"] {
		t.Error("a pair blocked both ways is still in each other's map")
	}
}

func TestViewCoversEveryOrderedPair(t *testing.T) {
	p := Default()
	p.Block("winpc-01", "linuxbox", []string{"22", "5900"}, "test")
	v := p.View(machines)
	if len(v.Pairs) != 6 {
		t.Fatalf("%d pairs, want 6", len(v.Pairs))
	}
	for _, pa := range v.Pairs {
		blocked := pa.Src == "winpc-01" && pa.Dst == "linuxbox"
		if pa.Allows(22) == blocked || pa.Allows(5900) == blocked || !pa.Allows(3389) {
			t.Errorf("%s → %s: ssh=%v vnc=%v rdp=%v", pa.Src, pa.Dst, pa.Allows(22), pa.Allows(5900), pa.Allows(3389))
		}
	}
	if !strings.Contains(p.Summary(), "winpc-01 ✗ linuxbox (ssh, vnc)") {
		t.Errorf("summary does not show the block:\n%s", p.Summary())
	}
}

func TestPairDescriptions(t *testing.T) {
	p := Default()
	p.Block("winpc-01", "hubpc", []string{"22", "5900"}, "")
	p.Block("winpc-01", "linuxbox", []string{Wildcard}, "")
	_ = p.Allow("linuxbox", "winpc-01", []string{"22"}, "", machines)
	want := map[string]string{
		"winpc-01→hubpc":    "all but ssh, vnc",
		"winpc-01→linuxbox": "none",
		"hubpc→winpc-01":    "all",
	}
	for _, pa := range p.View(machines).Pairs {
		if w, ok := want[pa.Src+"→"+pa.Dst]; ok && pa.Describe() != w {
			t.Errorf("%s → %s described as %q, want %q", pa.Src, pa.Dst, pa.Describe(), w)
		}
	}
	only := PairAccess{Ports: []PortRange{{22, 22}, {5900, 5900}}}
	if got := only.Describe(); got != "ssh, vnc" {
		t.Errorf("two services described as %q", got)
	}
}
