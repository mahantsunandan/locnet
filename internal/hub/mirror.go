package hub

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mahantsunandan/locnet/internal/hubapi"
	"github.com/mahantsunandan/locnet/internal/hubtls"
)

// A second hub, and what it can and cannot buy you.
//
// The hub is a single point of failure for *joining and finding*, not for
// traffic: tunnels already established keep working while it is down, because
// every node caches the last map it was given. What stops is anything that
// needs the register — a new machine joining, a machine that moved being found
// again, a policy change reaching anyone.
//
// A standby fixes that, and the honest way to do it is a warm spare rather
// than a cluster. The spare copies the primary's whole state, including the
// identity key, and stays silent. Nodes carry both addresses and try them in
// order, so the moment the spare is promoted they find it and its maps verify
// against the fingerprint they already trust.
//
// Two consequences, said plainly rather than buried:
//
//   - The spare holds a copy of the hub's signing key. It is therefore exactly
//     as sensitive as the primary and must be a machine you trust the same
//     amount. Anything else — separate keys per hub, a quorum, a consensus
//     protocol — is a much larger system than this one.
//   - Promotion is manual by default. Two hubs serving the same identity with
//     diverging registers is worse than no hub at all: both sign maps, nodes
//     believe whichever answers first, and the two halves of the network stop
//     agreeing about who is a member. A human deciding "the primary is really
//     gone" is a cheap and reliable way to never have that happen.

// StandbyMarker is the file that promotes a standby. `locnet-hub promote`
// writes it; the running standby notices and takes over.
const StandbyMarker = "promote"

// mirrorInterval is how often a standby refreshes its copy. A minute is well
// inside the window that matters: the cost of a stale spare is that machines
// which joined in the last minute must rejoin, and the cost of a shorter
// interval is a request per hub per second forever.
const mirrorInterval = time.Minute

// Mirror keeps a standby hub's state file in step with a primary.
type Mirror struct {
	// From is the primary's address. A bare host:port is reached over TLS
	// pinned to Fingerprint; an https:// URL through a proxy with a real
	// certificate; an http:// URL in the clear, which a primary from 0.10.4
	// on refuses unless it is this machine.
	From string
	// Fingerprint pins the primary's identity key, as a join code does.
	// See MirrorPin.
	Fingerprint [16]byte
	// Token is the primary's admin token.
	Token string
	// Path is this hub's state file.
	Path string
	// Interval overrides mirrorInterval.
	Interval time.Duration

	Logf func(string, ...any)

	client *http.Client

	mu       sync.Mutex
	lastOK   time.Time
	lastErr  string
	versions uint64
}

// Status describes a standby for `locnet-hub status`.
type MirrorStatus struct {
	LastSync time.Time `json:"last_sync,omitzero"`
	LastErr  string    `json:"last_error,omitempty"`
	Version  uint64    `json:"version,omitempty"`
}

// Status reports how the mirroring is going.
func (m *Mirror) Status() MirrorStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	return MirrorStatus{LastSync: m.lastOK, LastErr: m.lastErr, Version: m.versions}
}

// Run mirrors until ctx is cancelled or the standby is promoted. It returns
// nil when promoted, so the caller can start serving.
func (m *Mirror) Run(ctx context.Context) error {
	logf := m.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	interval := m.Interval
	if interval <= 0 {
		interval = mirrorInterval
	}

	if err := m.once(ctx); err != nil {
		// A standby that cannot reach the primary at startup is still worth
		// running: it may have an older copy on disk that is far better than
		// nothing, and the primary may simply be rebooting.
		logf("standby: first sync failed: %v", err)
	} else {
		logf("standby: synced from %s", m.From)
	}

	t := time.NewTicker(interval)
	defer t.Stop()
	promote := time.NewTicker(3 * time.Second)
	defer promote.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-promote.C:
			if m.promoted() {
				logf("standby: promotion marker found — taking over as the hub")
				return nil
			}
		case <-t.C:
			if err := m.once(ctx); err != nil {
				logf("standby: sync failed: %v", err)
			}
		}
	}
}

// promoted reports whether someone has run `locnet-hub promote` here.
func (m *Mirror) promoted() bool {
	marker := filepath.Join(filepath.Dir(m.Path), StandbyMarker)
	if _, err := os.Stat(marker); err != nil {
		return false
	}
	// The marker is consumed, so a promoted hub that is later demoted back to
	// standby does not immediately promote itself again.
	_ = os.Remove(marker)
	return true
}

// MirrorPin works out which primary a standby may copy from.
//
// The snapshot is the hub's signing key, and the admin token that fetches it
// is the hub's master password, so a standby must know it is talking to the
// real primary before it sends either: the same 16-byte fingerprint a join
// code carries. It comes from -follow-fingerprint, or, for a standby that
// has synced before, from the copy already on disk — which is what lets a
// standby set up before 0.10.4 keep running without a new flag.
func MirrorPin(statePath, flagHex string) ([16]byte, error) {
	var fp [16]byte
	if flagHex != "" {
		raw, err := hex.DecodeString(strings.TrimSpace(flagHex))
		if err != nil || len(raw) != 16 {
			return fp, fmt.Errorf("-follow-fingerprint must be 32 hex digits, as printed by " +
				"`locnet-hub fingerprint` on the primary")
		}
		fp = [16]byte(raw)
	}
	have, ok := pinFromState(statePath)
	switch {
	case flagHex != "" && ok && have != fp:
		return fp, fmt.Errorf("-follow-fingerprint %x is not the hub this standby already holds a copy of (%x); "+
			"to follow a different hub, move %s aside first", fp, have, statePath)
	case flagHex != "":
		return fp, nil
	case ok:
		return have, nil
	}
	return fp, errors.New("a new standby needs the primary's fingerprint: " +
		"run `locnet-hub fingerprint` on the primary, then add -follow-fingerprint <it>")
}

// pinFromState reads the hub key out of a previous copy.
func pinFromState(path string) ([16]byte, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return [16]byte{}, false
	}
	var st State
	if json.Unmarshal(raw, &st) != nil || st.HubKey.IsZero() {
		return [16]byte{}, false
	}
	return st.HubKey.Public().Fingerprint(), true
}

// pinned reports whether From is reached over TLS pinned to Fingerprint.
func (m *Mirror) pinned() bool { return !strings.Contains(m.From, "://") }

func (m *Mirror) httpClient() *http.Client {
	if m.client == nil {
		m.client = &http.Client{Timeout: 30 * time.Second}
		if m.pinned() {
			m.client.Transport = hubtls.NewTransport(m.Fingerprint, nil)
		}
	}
	return m.client
}

// once pulls one snapshot and writes it out.
func (m *Mirror) once(ctx context.Context) error {
	base := m.From
	if m.pinned() {
		if m.Fingerprint == ([16]byte{}) {
			err := errors.New("no fingerprint to pin the primary to")
			m.note(err)
			return err
		}
		base = "https://" + base
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(base, "/")+hubapi.APIVersion+"/admin/snapshot", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+m.Token)

	resp, err := m.httpClient().Do(req)
	if err != nil {
		if hubtls.IsPlainServer(err) {
			// Never fall back on our own: that would hand the admin token
			// to anyone able to fake an old hub's answer. The operator can
			// choose the clear with an explicit http:// address.
			err = fmt.Errorf("the primary at %s does not speak TLS — upgrade the primary first "+
				"(hub before standby), or follow http://%s to copy in the clear meanwhile", m.From, m.From)
		}
		m.note(err)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		err := fmt.Errorf("the primary answered %s: %s", resp.Status, strings.TrimSpace(string(body)))
		m.note(err)
		return err
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		m.note(err)
		return err
	}

	// Parse before writing. A truncated or garbled snapshot written over a
	// good one would turn the spare from a partial answer into no answer at
	// all, which is the opposite of the point.
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		err = fmt.Errorf("the snapshot is not valid hub state: %w", err)
		m.note(err)
		return err
	}
	if st.HubKey.IsZero() || st.Network.Prefix.Bits() == 0 {
		err := fmt.Errorf("the snapshot has no hub key or no network — refusing to overwrite good state with it")
		m.note(err)
		return err
	}
	// The TLS handshake already proved who answered, but an https:// proxy
	// or an http:// address proves nothing about whose state this is, and
	// a spare holding some other hub's key would take over as that hub.
	if m.Fingerprint != ([16]byte{}) && st.HubKey.Public().Fingerprint() != m.Fingerprint {
		err := fmt.Errorf("the snapshot is of hub %x, not the pinned %x — refusing it",
			st.HubKey.Public().Fingerprint(), m.Fingerprint)
		m.note(err)
		return err
	}

	if err := os.MkdirAll(filepath.Dir(m.Path), 0o700); err != nil {
		m.note(err)
		return err
	}
	tmp := m.Path + ".mirror"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		m.note(err)
		return err
	}
	if err := os.Rename(tmp, m.Path); err != nil {
		os.Remove(tmp)
		m.note(err)
		return err
	}

	m.mu.Lock()
	m.lastOK, m.lastErr, m.versions = time.Now(), "", st.Version
	m.mu.Unlock()
	return nil
}

func (m *Mirror) note(err error) {
	m.mu.Lock()
	m.lastErr = err.Error()
	m.mu.Unlock()
}

// Snapshot returns the whole state as it is stored, for a standby to copy.
//
// This is the hub's private key and every join token in one response, so it
// sits behind the admin token and belongs on a network you control. It is the
// same file an operator would copy with scp; serving it just means the copy
// stays current without a cron job.
func (s *Store) Snapshot() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return json.MarshalIndent(s.st, "", "  ")
}
