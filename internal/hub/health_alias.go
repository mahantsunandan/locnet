package hub

import "github.com/mahantsunandan/locnet/internal/resource"

// The health rule types live in internal/resource so that both the hub and
// each agent can evaluate them from the same definitions — an agent shows
// alerts for the peers it can see without needing an admin token. These
// aliases keep the hub's own API reading naturally.
type (
	HealthRules = resource.HealthRules
	Alert       = resource.Alert
	Level       = resource.Level
	Duration    = resource.Duration
)

const (
	LevelWarn     = resource.LevelWarn
	LevelCritical = resource.LevelCritical
)

// DefaultHealthRules are the thresholds a new network starts with.
func DefaultHealthRules() HealthRules { return resource.DefaultHealthRules() }
