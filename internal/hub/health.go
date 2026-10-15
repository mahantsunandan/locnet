package hub

import (
	"fmt"
	"time"

	"github.com/mahantsunandan/locnet/internal/resource"
)

// Alerts evaluates the health rules against every machine the hub knows.
func (s *Store) Alerts() []resource.Alert {
	s.mu.Lock()
	rules := s.st.Health
	requireApproval := s.st.RequireApproval
	nodes := s.nodesLocked()
	s.mu.Unlock()

	machines := make([]resource.Machine, 0, len(nodes))
	for _, n := range nodes {
		machines = append(machines, resource.Machine{
			Name: n.Name, Stats: n.Stats, LastSeen: n.LastSeen,
			Approved: n.Approved, CreatedAt: n.CreatedAt,
		})
	}
	return resource.Evaluate(machines, rules, requireApproval)
}

// SetHealthRules replaces the thresholds.
func (s *Store) SetHealthRules(r HealthRules) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Health = r
	s.auditLocked("admin", "health.set", fmt.Sprintf("disk warn %.0f%%, critical %.0f%%, offline after %s",
		r.DiskFreePercentWarn, r.DiskFreePercentCritical, time.Duration(r.OfflineAfter)))
	// The thresholds travel in the network map, and every node evaluates its
	// own alerts from them. Without a bump the new values reached nobody until
	// something unrelated happened to change.
	s.bump()
	return s.save()
}

// HealthRules returns the current thresholds.
func (s *Store) HealthRules() HealthRules {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.Health
}
