package resource

import (
	"fmt"
	"sort"
	"time"
)

// Machine is the minimum a health check needs to know about a node. Both the
// hub and each agent can supply it, which is what lets alerts be computed in
// either place from the same rules.
type Machine struct {
	Name      string
	Stats     Stats
	LastSeen  time.Time
	Approved  bool
	CreatedAt time.Time
}

// HealthRules are the thresholds that turn a machine's reported state into
// something worth telling somebody about.
//
// This is the part that makes LocNet useful for a fleet rather than a laptop.
// A mesh VPN tells you a machine is reachable; it does not tell you that the
// disk on the station recording overnight data has four gigabytes left. Those
// are different questions and operators need both, usually at 2am.
type HealthRules struct {
	// DiskFreePercentWarn/Critical fire when free space drops below them.
	DiskFreePercentWarn     float64 `json:"disk_free_percent_warn"`
	DiskFreePercentCritical float64 `json:"disk_free_percent_critical"`

	// LoadPercentWarn fires when sustained CPU load exceeds it.
	LoadPercentWarn float64 `json:"load_percent_warn"`

	// MemFreePercentWarn fires when free memory drops below it.
	MemFreePercentWarn float64 `json:"mem_free_percent_warn"`

	// OfflineAfter is how long a machine may be out of contact before it is
	// worth an alert, as opposed to the shorter window that merely marks it
	// offline in the UI. A laptop that is shut for the night is not an
	// incident; a station that has been quiet for an hour is.
	OfflineAfter Duration `json:"offline_after"`

	// Muted lists machine names that raise no alerts. For the laptop that is
	// legitimately off most of the time.
	Muted []string `json:"muted,omitempty"`
}

// DefaultHealthRules are deliberately loose. Thresholds that cry wolf get
// ignored, and an ignored alert is worse than no alert.
func DefaultHealthRules() HealthRules {
	return HealthRules{
		DiskFreePercentWarn:     10,
		DiskFreePercentCritical: 3,
		LoadPercentWarn:         90,
		MemFreePercentWarn:      5,
		OfflineAfter:            Duration(30 * time.Minute),
	}
}

// Duration is a time.Duration that marshals as a human string ("30m") rather
// than a nanosecond count, so the hub's state file stays editable by hand.
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + time.Duration(d).String() + `"`), nil
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	s := string(b)
	if len(s) >= 2 && s[0] == '"' {
		s = s[1 : len(s)-1]
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("bad duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// Level is how loud an alert is.
type Level string

const (
	LevelWarn     Level = "warn"
	LevelCritical Level = "critical"
)

// Alert is one thing wrong with one machine.
type Alert struct {
	Node    string    `json:"node"`
	Level   Level     `json:"level"`
	Kind    string    `json:"kind"`
	Message string    `json:"message"`
	Since   time.Time `json:"since,omitempty"`
}

// Alerts evaluates the health rules against every machine.
//
// Alerts are computed on demand rather than stored. A stored alert has to be
// cleared, and something has to decide when — which is a second source of
// truth and a second thing to get wrong. Deriving them from current state
// means an alert disappears exactly when the condition does.
func Evaluate(nodes []Machine, rules HealthRules, requireApproval bool) []Alert {
	muted := map[string]bool{}
	for _, m := range rules.Muted {
		muted[m] = true
	}

	var out []Alert
	for _, n := range nodes {
		if muted[n.Name] {
			continue
		}

		if requireApproval && !n.Approved {
			out = append(out, Alert{
				Node: n.Name, Level: LevelWarn, Kind: "unapproved",
				Message: fmt.Sprintf("%s joined and is waiting for approval", n.Name),
				Since:   n.CreatedAt,
			})
			// An unapproved machine reports nothing else worth acting on.
			continue
		}

		if offline := time.Since(n.LastSeen); offline > time.Duration(rules.OfflineAfter) {
			out = append(out, Alert{
				Node: n.Name, Level: LevelCritical, Kind: "offline",
				Message: fmt.Sprintf("%s has been out of contact for %s", n.Name, humanDuration(offline)),
				Since:   n.LastSeen,
			})
			// Everything else it reported is stale by definition.
			continue
		}

		out = append(out, diskAlerts(n.Name, n.Stats, rules)...)
		out = append(out, loadAlerts(n.Name, n.Stats, rules)...)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Level != out[j].Level {
			return out[i].Level == LevelCritical
		}
		return out[i].Node < out[j].Node
	})
	return out
}

func diskAlerts(name string, st Stats, r HealthRules) []Alert {
	if st.DiskTotalGB == 0 {
		return nil // not measured on this platform
	}
	freePct := float64(st.DiskFreeGB) / float64(st.DiskTotalGB) * 100

	switch {
	case r.DiskFreePercentCritical > 0 && freePct < r.DiskFreePercentCritical:
		return []Alert{{
			Node: name, Level: LevelCritical, Kind: "disk",
			Message: fmt.Sprintf("%s has %d GB left (%.0f%% of %d GB)", name, st.DiskFreeGB, freePct, st.DiskTotalGB),
		}}
	case r.DiskFreePercentWarn > 0 && freePct < r.DiskFreePercentWarn:
		return []Alert{{
			Node: name, Level: LevelWarn, Kind: "disk",
			Message: fmt.Sprintf("%s has %d GB left (%.0f%% of %d GB)", name, st.DiskFreeGB, freePct, st.DiskTotalGB),
		}}
	}
	return nil
}

func loadAlerts(name string, st Stats, r HealthRules) []Alert {
	var out []Alert
	if r.LoadPercentWarn > 0 && st.LoadPercent > r.LoadPercentWarn {
		out = append(out, Alert{
			Node: name, Level: LevelWarn, Kind: "load",
			Message: fmt.Sprintf("%s is at %.0f%% CPU across %d cores", name, st.LoadPercent, st.CPUs),
		})
	}
	if r.MemFreePercentWarn > 0 && st.MemTotalMB > 0 && st.MemFreeMB > 0 {
		freePct := float64(st.MemFreeMB) / float64(st.MemTotalMB) * 100
		if freePct < r.MemFreePercentWarn {
			out = append(out, Alert{
				Node: name, Level: LevelWarn, Kind: "memory",
				Message: fmt.Sprintf("%s has %.0f%% memory free (%d of %d MB)", name, freePct, st.MemFreeMB, st.MemTotalMB),
			})
		}
	}
	return out
}

// humanDuration says how long, the way a person would: "40 minutes", "5 hours",
// "34 days". A machine that has been gone for a month was reported as
// "814h47m0s", which is accurate and has to be divided by 24 in your head.
func humanDuration(d time.Duration) string {
	plural := func(n int, unit string) string {
		if n == 1 {
			return "1 " + unit
		}
		return fmt.Sprintf("%d %ss", n, unit)
	}
	switch {
	case d < time.Minute:
		return plural(int(d.Seconds()), "second")
	case d < time.Hour:
		return plural(int(d.Minutes()), "minute")
	case d < 48*time.Hour:
		h := int(d.Hours())
		if m := int(d.Minutes()) % 60; m >= 5 && h < 10 {
			return fmt.Sprintf("%s %s", plural(h, "hour"), plural(m, "minute"))
		}
		return plural(h, "hour")
	default:
		return plural(int(d.Hours()/24), "day")
	}
}
