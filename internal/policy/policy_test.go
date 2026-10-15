package policy

import (
	"sort"
	"testing"
)

var fleet = []string{"unit-01", "unit-02", "unit-03", "workstation", "laptop", "collector"}

// fleetPolicy is the shape a real deployment ends up with: operators reach
// everything, a collector reaches one port, and the field machines are
// isolated from each other.
func fleetPolicy() *Policy {
	return &Policy{
		Groups: map[string][]string{
			"field-units": {"unit-01", "unit-02", "unit-03"},
			"operators":   {"workstation", "laptop"},
		},
		Rules: []Rule{
			{Src: []string{"operators"}, Dst: []string{"field-units"}, Ports: []string{"*"}},
			{Src: []string{"collector"}, Dst: []string{"field-units"}, Ports: []string{"8421"}},
			{Src: []string{"operators"}, Dst: []string{"operators"}},
		},
	}
}

func TestDefaultPolicyAllowsEverything(t *testing.T) {
	p := Default()
	if err := p.Validate(); err != nil {
		t.Fatalf("the default policy does not validate: %v", err)
	}
	for _, a := range fleet {
		for _, b := range fleet {
			if ok, _ := p.CanReach(a, b, 22, fleet); !ok {
				t.Errorf("default policy blocked %s → %s", a, b)
			}
		}
	}
}

// TestFieldUnitsAreIsolated is the property the whole feature exists for.
func TestFieldUnitsAreIsolated(t *testing.T) {
	p := fleetPolicy()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}

	if ok, any := p.CanReach("unit-01", "unit-02", 22, fleet); ok || any {
		t.Error("two field-units can reach each other; they should be isolated")
	}
	// And therefore they must not appear in each other's network map.
	if p.Reachable("unit-01", fleet)["unit-02"] {
		t.Error("unit-02 is in unit-01's netmap despite no rule connecting them")
	}
}

func TestOperatorsReachFieldUnitsBothWays(t *testing.T) {
	p := fleetPolicy()

	if ok, _ := p.CanReach("workstation", "unit-01", 3389, fleet); !ok {
		t.Error("an operator cannot reach a field unit")
	}
	// The rule is one-directional, but the netmap must be symmetric or the
	// replies have nowhere to go.
	if !p.Reachable("unit-01", fleet)["workstation"] {
		t.Error("workstation is missing from unit-01's netmap, so replies cannot route")
	}
	if !p.Reachable("workstation", fleet)["unit-01"] {
		t.Error("unit-01 is missing from workstation's netmap")
	}
}

func TestPortRestriction(t *testing.T) {
	p := fleetPolicy()

	if ok, _ := p.CanReach("collector", "unit-01", 8421, fleet); !ok {
		t.Error("the collector cannot reach the share port it was granted")
	}
	for _, port := range []uint16{22, 3389, 5900, 8422} {
		if ok, _ := p.CanReach("collector", "unit-01", port, fleet); ok {
			t.Errorf("the collector reached port %d, which was never granted", port)
		}
	}
	// It still belongs in the netmap: some port is permitted.
	if !p.Reachable("collector", fleet)["unit-01"] {
		t.Error("unit-01 is missing from the collector's netmap")
	}

	ranges, all := p.InboundPorts("collector", "unit-01", fleet)
	if all {
		t.Fatal("InboundPorts said every port")
	}
	if len(ranges) != 1 || ranges[0].Lo != 8421 || ranges[0].Hi != 8421 {
		t.Errorf("InboundPorts = %+v, want one range 8421-8421", ranges)
	}

	if _, all := p.InboundPorts("workstation", "unit-01", fleet); !all {
		t.Error("an operator should be unrestricted")
	}
}

func TestPortRanges(t *testing.T) {
	p := &Policy{Rules: []Rule{
		{Src: []string{"a"}, Dst: []string{"b"}, Ports: []string{"8000-8100", "22"}},
	}}
	all := []string{"a", "b"}

	allowed := []uint16{22, 8000, 8050, 8100}
	for _, port := range allowed {
		if ok, _ := p.CanReach("a", "b", port, all); !ok {
			t.Errorf("port %d should be allowed", port)
		}
	}
	for _, port := range []uint16{21, 23, 7999, 8101} {
		if ok, _ := p.CanReach("a", "b", port, all); ok {
			t.Errorf("port %d should be blocked", port)
		}
	}
}

func TestSelfIsAlwaysReachable(t *testing.T) {
	// An empty policy blocks everything except a machine talking to itself,
	// which must never be blocked or the machine cannot use its own overlay
	// address.
	p := &Policy{}
	if ok, _ := p.CanReach("a", "a", 22, []string{"a"}); !ok {
		t.Error("a machine cannot reach itself")
	}
	if ok, _ := p.CanReach("a", "b", 22, []string{"a", "b"}); ok {
		t.Error("an empty policy allowed traffic")
	}
}

func TestNestedGroups(t *testing.T) {
	p := &Policy{
		Groups: map[string][]string{
			"field":    {"unit-01", "unit-02"},
			"lab":      {"unit-03"},
			"everyone": {"field", "lab", "workstation"},
		},
		Rules: []Rule{{Src: []string{"workstation"}, Dst: []string{"everyone"}}},
	}
	for _, dst := range []string{"unit-01", "unit-02", "unit-03"} {
		if ok, _ := p.CanReach("workstation", dst, 22, fleet); !ok {
			t.Errorf("nested group did not expand to include %s", dst)
		}
	}
}

func TestGroupsFor(t *testing.T) {
	p := fleetPolicy()
	got := p.GroupsFor("unit-01")
	if len(got) != 1 || got[0] != "field-units" {
		t.Errorf("GroupsFor(unit-01) = %v, want [field-units]", got)
	}
	if len(p.GroupsFor("collector")) != 0 {
		t.Errorf("collector should be in no group, got %v", p.GroupsFor("collector"))
	}
}

func TestValidateCatchesMistakes(t *testing.T) {
	bad := []*Policy{
		{Groups: map[string][]string{"*": {"a"}}, Rules: []Rule{{Src: []string{"a"}, Dst: []string{"b"}}}},
		{Groups: map[string][]string{"empty": {}}, Rules: []Rule{{Src: []string{"a"}, Dst: []string{"b"}}}},
		{Rules: []Rule{{Src: []string{"a"}}}},
		{Rules: []Rule{{Src: []string{"a"}, Dst: []string{"b"}, Ports: []string{"not-a-port"}}}},
		{Rules: []Rule{{Src: []string{"a"}, Dst: []string{"b"}, Ports: []string{"900-100"}}}},
		{Rules: []Rule{{Src: []string{"a"}, Dst: []string{"b"}, Ports: []string{"99999"}}}},
	}
	for i, p := range bad {
		if err := p.Validate(); err == nil {
			t.Errorf("policy %d validated but should not have: %+v", i, p)
		}
	}
	if err := fleetPolicy().Validate(); err != nil {
		t.Errorf("a good policy failed validation: %v", err)
	}
}

// TestWildcardExpandsToKnownMachines checks that "*" means the machines that
// exist, not a literal name.
func TestWildcardExpandsToKnownMachines(t *testing.T) {
	p := &Policy{Rules: []Rule{{Src: []string{Wildcard}, Dst: []string{"unit-01"}}}}
	for _, src := range fleet {
		if src == "unit-01" {
			continue
		}
		if ok, _ := p.CanReach(src, "unit-01", 22, fleet); !ok {
			t.Errorf("%s should match the wildcard source", src)
		}
	}
	if ok, _ := p.CanReach("unit-01", "unit-02", 22, fleet); ok {
		t.Error("the wildcard rule allowed a destination it never named")
	}
}

func TestReachableIsSymmetric(t *testing.T) {
	p := fleetPolicy()
	for _, a := range fleet {
		for b := range p.Reachable(a, fleet) {
			if !p.Reachable(b, fleet)[a] {
				t.Errorf("%s sees %s but %s does not see %s — the tunnel would be one-way", a, b, b, a)
			}
		}
	}
}

func TestSummaryMentionsEverything(t *testing.T) {
	got := fleetPolicy().Summary()
	for _, want := range []string{"field-units", "operators", "unit-01", "8421"} {
		if !contains(splitWords(got), want) {
			t.Errorf("Summary does not mention %q:\n%s", want, got)
		}
	}
}

func splitWords(s string) []string {
	var out []string
	word := ""
	for _, r := range s {
		switch r {
		case ' ', '\n', '\t', ',', '(', ')', '→':
			if word != "" {
				out = append(out, word)
				word = ""
			}
		default:
			word += string(r)
		}
	}
	if word != "" {
		out = append(out, word)
	}
	sort.Strings(out)
	return out
}
