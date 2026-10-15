package hub

import (
	"fmt"
	"time"
)

// maxAuditEntries bounds the log. The hub keeps its whole state in memory and
// writes it on every change, so an unbounded log would eventually make every
// registration slow.
//
// For a real retention policy, tail the hub's stdout into your log collector —
// every entry is printed as it happens. This in-state log exists so that
// `locnet-hub audit` works on a machine with no log infrastructure at all,
// which is most of them.
const maxAuditEntries = 500

// AuditEntry is one thing that happened to the network's membership or rules.
//
// Only administrative actions are recorded — who joined, who was removed, what
// the policy became. Connections between peers are deliberately *not* logged:
// they never touch the hub, and a log that claimed to record them would be
// lying about coverage the moment two machines went direct.
type AuditEntry struct {
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Detail string    `json:"detail,omitempty"`
}

// auditLocked appends an entry. Callers must hold s.mu and must save
// afterwards.
func (s *Store) auditLocked(actor, action, detail string) {
	e := AuditEntry{At: time.Now(), Actor: actor, Action: action, Detail: detail}
	s.st.Audit = append(s.st.Audit, e)
	if n := len(s.st.Audit); n > maxAuditEntries {
		// Keep the newest. Copy rather than reslice so the dropped entries
		// become garbage instead of staying alive behind the slice header.
		kept := make([]AuditEntry, maxAuditEntries)
		copy(kept, s.st.Audit[n-maxAuditEntries:])
		s.st.Audit = kept
	}
	if s.logf != nil {
		s.logf("audit: %s %s %s", actor, action, detail)
	}
}

// Audit returns the log, newest first.
func (s *Store) Audit(limit int) []AuditEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit > len(s.st.Audit) {
		limit = len(s.st.Audit)
	}
	out := make([]AuditEntry, 0, limit)
	for i := len(s.st.Audit) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, s.st.Audit[i])
	}
	return out
}

// Describe renders an entry for the CLI.
func (e AuditEntry) Describe() string {
	if e.Detail == "" {
		return fmt.Sprintf("%s  %-12s %s", e.At.Format("2006-01-02 15:04:05"), e.Actor, e.Action)
	}
	return fmt.Sprintf("%s  %-12s %-16s %s", e.At.Format("2006-01-02 15:04:05"), e.Actor, e.Action, e.Detail)
}
