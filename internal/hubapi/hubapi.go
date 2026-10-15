// Package hubapi defines the wire types and the request-signing scheme shared
// by locnetd and locnet-hub.
//
// Every authenticated request carries an Ed25519 signature over a canonical
// summary of itself — method, path, timestamp, body digest. That binds the
// signature to one request: it cannot be lifted onto a different endpoint, and
// the timestamp bounds how long a captured request stays replayable.
package hubapi

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/mahantsunandan/locnet/internal/key"
	"github.com/mahantsunandan/locnet/internal/netmap"
	"github.com/mahantsunandan/locnet/internal/placement"
	"github.com/mahantsunandan/locnet/internal/resource"
)

// APIVersion is the path prefix for all endpoints.
const APIVersion = "/v1"

// MaxClockSkew is how far a request's timestamp may be from the hub's clock.
// Generous enough for machines that only sync NTP at boot, tight enough that a
// captured request is not useful for long.
const MaxClockSkew = 5 * time.Minute

// Header names for the signing scheme.
const (
	HeaderTimestamp = "X-LocNet-Timestamp"
	HeaderNodeID    = "X-LocNet-Node"
	HeaderSignature = "X-LocNet-Signature"
)

// RegisterRequest is sent once, when a machine first joins a network.
//
// It is the only unauthenticated-by-signature request: the machine has no node
// ID yet. The join token stands in, and the response establishes the node ID
// that signs everything afterwards.
type RegisterRequest struct {
	// Token is the 16-byte join token from the join code, base64-encoded.
	Token string `json:"token"`

	Hostname   string            `json:"hostname"`
	OS         string            `json:"os"`
	MachineKey key.MachinePublic `json:"machine_key"`
	WGKey      key.WGPublic      `json:"wg_key"`
	DiscoKey   key.DiscoPublic   `json:"disco_key"`
}

// RegisterResponse tells a freshly joined machine who it is.
type RegisterResponse struct {
	NodeID string         `json:"node_id"`
	IP     netip.Addr     `json:"ip"`
	Name   string         `json:"name"`
	NetMap *netmap.Signed `json:"netmap"`
}

// ReportRequest is a node's periodic account of itself: where it can be
// reached, what it is running, what it offers, and how loaded it is.
//
// One request rather than four because all of it is refreshed on the same
// schedule and all of it lands in the same netmap. Splitting it would mean
// four signatures and four round trips to update one row.
type ReportRequest struct {
	// Local are addresses discovered on the node's own interfaces.
	Local []netip.AddrPort `json:"local"`
	// Observed is what the relay saw as this node's source address — its
	// public side of the NAT, when there is one.
	Observed netip.AddrPort `json:"observed,omitempty"`

	// Services are listening ports the node found on its own overlay
	// address.
	Services []resource.Service `json:"services,omitempty"`

	// SSH are this node's public SSH keys, for peers to recognise it and to
	// let its operator in without a password. Public halves only.
	SSH resource.SSHKeys `json:"ssh,omitzero"`

	// Shares are what this node offers, with their access lists but
	// without their local paths — where a folder lives on disk is nobody
	// else's business, including the hub's.
	Shares []resource.Share `json:"shares,omitempty"`

	// Stats describes the hardware.
	Stats resource.Stats `json:"stats,omitzero"`

	// LAN is this node's real interfaces, so that a peer can wake it after
	// it has been switched off.
	LAN []resource.LANIface `json:"lan,omitempty"`

	// Compute is this node's offer to run work for peers, with its access
	// list. The hub filters it per recipient the same way it filters shares.
	Compute resource.ComputeConfig `json:"compute,omitzero"`

	// Desktop is this node's offer to show its screen, with its access
	// list, filtered per recipient exactly like Compute.
	Desktop resource.DesktopConfig `json:"desktop,omitzero"`

	// Screen is what the session helper reports: whether anyone is logged
	// in, at what resolution, and why not if not. Unlike Desktop this is
	// live state rather than configuration, which is why it is separate —
	// the hub must not persist it as a setting.
	Screen resource.DesktopStatus `json:"screen,omitzero"`
}

// NetMapResponse is the answer to a poll.
type NetMapResponse struct {
	// Changed is false when the long poll timed out with nothing new. The
	// node should poll again; NetMap is nil.
	Changed bool           `json:"changed"`
	NetMap  *netmap.Signed `json:"netmap,omitempty"`
}

// HubInfo is the unauthenticated response from GET /v1/info. It lets a node
// confirm it is talking to the right hub before sending anything.
type HubInfo struct {
	HubKey  key.MachinePublic `json:"hub_key"`
	Version string            `json:"version"`
	Relay   string            `json:"relay"` // host:port of the UDP relay
}

// ErrorResponse is the body of any non-2xx reply.
type ErrorResponse struct {
	Error string `json:"error"`
}

// ---------------------------------------------------------------- signing

// SigningString builds the canonical text that gets signed.
//
// Newline-separated fields with a fixed order and a hex digest of the body:
// no field can absorb another's content, so there is no way to shuffle bytes
// between them and keep the same signature.
func SigningString(method, path string, ts time.Time, body []byte) string {
	sum := sha256.Sum256(body)
	return strings.Join([]string{
		strings.ToUpper(method),
		path,
		strconv.FormatInt(ts.Unix(), 10),
		fmt.Sprintf("%x", sum),
	}, "\n")
}

// SignRequest attaches the node's identity signature to req.
//
// body must be the exact bytes that will be sent, and the caller is
// responsible for setting req.Body from the same slice.
func SignRequest(req *http.Request, nodeID string, mk key.MachinePrivate, body []byte) {
	ts := time.Now()
	sig := mk.Sign([]byte(SigningString(req.Method, req.URL.Path, ts, body)))
	req.Header.Set(HeaderNodeID, nodeID)
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(ts.Unix(), 10))
	req.Header.Set(HeaderSignature, base64.StdEncoding.EncodeToString(sig))
}

// WithNonce adds a random "nonce" member to a JSON object body.
//
// A signature covers method, path, second and body, so two identical requests
// in the same second carry the same signature — which is what lets the hub
// refuse a signature it has already seen without refusing a person who did
// the same thing twice. Hubs ignore the member; older hubs never knew it.
// Anything that is not a JSON object is returned unchanged.
func WithNonce(body []byte) []byte {
	if len(body) < 2 || body[0] != '{' {
		return body
	}
	var n [12]byte
	if _, err := rand.Read(n[:]); err != nil {
		return body
	}
	member := `"nonce":"` + hex.EncodeToString(n[:]) + `"`
	rest := bytes.TrimSpace(body[1:])
	out := make([]byte, 0, len(body)+len(member)+1)
	out = append(out, '{')
	out = append(out, member...)
	if len(rest) > 0 && rest[0] != '}' {
		out = append(out, ',')
	}
	return append(out, rest...)
}

// VerifyRequest checks the signature on an inbound request.
//
// lookup maps a node ID to its registered identity key; it returns false for
// unknown nodes. Returning the node ID keeps the caller from having to re-read
// the header it just validated.
func VerifyRequest(req *http.Request, body []byte, lookup func(nodeID string) (key.MachinePublic, bool)) (string, error) {
	nodeID := req.Header.Get(HeaderNodeID)
	if nodeID == "" {
		return "", fmt.Errorf("missing %s", HeaderNodeID)
	}
	rawTS := req.Header.Get(HeaderTimestamp)
	if rawTS == "" {
		return "", fmt.Errorf("missing %s", HeaderTimestamp)
	}
	unix, err := strconv.ParseInt(rawTS, 10, 64)
	if err != nil {
		return "", fmt.Errorf("bad %s: %w", HeaderTimestamp, err)
	}
	ts := time.Unix(unix, 0)
	if skew := time.Since(ts); skew > MaxClockSkew || skew < -MaxClockSkew {
		return "", fmt.Errorf("timestamp is %s away from hub time; check the clock on this machine", skew.Round(time.Second))
	}
	sig, err := base64.StdEncoding.DecodeString(req.Header.Get(HeaderSignature))
	if err != nil {
		return "", fmt.Errorf("bad %s: %w", HeaderSignature, err)
	}
	pub, ok := lookup(nodeID)
	if !ok {
		return "", fmt.Errorf("unknown node %q", nodeID)
	}
	if !pub.Verify([]byte(SigningString(req.Method, req.URL.Path, ts, body)), sig) {
		return "", fmt.Errorf("signature does not verify")
	}
	return nodeID, nil
}

// WriteJSON writes v as a JSON response with the given status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError writes an ErrorResponse.
func WriteError(w http.ResponseWriter, status int, format string, args ...any) {
	WriteJSON(w, status, ErrorResponse{Error: fmt.Sprintf(format, args...)})
}

// ---------------------------------------------------------------- queue

// Job states.
const (
	JobQueued    = "queued"
	JobRunning   = "running"
	JobDone      = "done"
	JobFailed    = "failed"
	JobCancelled = "cancelled"
)

// Terminal reports whether a job has stopped for good.
func (j *Job) Terminal() bool {
	return j.State == JobDone || j.State == JobFailed || j.State == JobCancelled
}

// Age is how long the job has been in its current state.
func (j *Job) Age() time.Duration {
	switch j.State {
	case JobQueued:
		return time.Since(j.QueuedAt)
	case JobRunning:
		return time.Since(j.StartedAt)
	default:
		if j.FinishedAt.IsZero() {
			return 0
		}
		return time.Since(j.FinishedAt)
	}
}

// Job is one unit of queued work.
type Job struct {
	ID string `json:"id"`
	// Submitter is the node that asked for it. A worker runs the job only
	// if its compute access list names this machine.
	Submitter string `json:"submitter"`

	Command []string `json:"command"`
	Dir     string   `json:"dir,omitempty"`
	Env     []string `json:"env,omitempty"`
	Label   string   `json:"label,omitempty"`

	// Need is what the job requires of a machine. Machines that cannot meet
	// it are excluded rather than ranked low.
	Need placement.Need `json:"need,omitzero"`
	// On pins the job to one machine by name.
	On string `json:"on,omitempty"`
	// Priority orders the queue; higher runs first. Equal priorities run in
	// submission order.
	Priority int `json:"priority,omitempty"`
	// MaxSeconds bounds one attempt.
	MaxSeconds int `json:"max_seconds,omitempty"`
	// Index and Count place this job within a sweep submitted with -n, and
	// reach the process as LOCNET_JOB_INDEX and LOCNET_JOB_COUNT.
	Index int `json:"index,omitempty"`
	Count int `json:"count,omitempty"`
	// Attempts made so far, and the ceiling. A job whose worker vanishes is
	// retried; a job that fails on its own merits is not.
	Attempts    int `json:"attempts,omitempty"`
	MaxAttempts int `json:"max_attempts,omitempty"`

	State string `json:"state"`
	// Node is where it is running, or where it last ran.
	Node string `json:"node,omitempty"`
	// LeaseUntil is when an unfinished claim is assumed lost.
	LeaseUntil time.Time `json:"lease_until,omitzero"`

	QueuedAt   time.Time `json:"queued_at"`
	StartedAt  time.Time `json:"started_at,omitzero"`
	FinishedAt time.Time `json:"finished_at,omitzero"`

	ExitCode int     `json:"exit_code,omitempty"`
	Stdout   string  `json:"stdout,omitempty"`
	Stderr   string  `json:"stderr,omitempty"`
	Seconds  float64 `json:"seconds,omitempty"`
	Error    string  `json:"error,omitempty"`
	// OutputBytes is set in a brief listing, where Stdout and Stderr are
	// left out, to say how much output there is to ask for.
	OutputBytes int `json:"output_bytes,omitempty"`
}

// JobResult is what a worker reports back.
type JobResult struct {
	ID       string  `json:"id"`
	ExitCode int     `json:"exit_code"`
	Stdout   string  `json:"stdout,omitempty"`
	Stderr   string  `json:"stderr,omitempty"`
	Seconds  float64 `json:"seconds,omitempty"`
	Error    string  `json:"error,omitempty"`
}

// KeepStdout and KeepStderr bound what the hub keeps of one job's output.
//
// A worker may collect several megabytes; the hub rewrites its whole state file
// on every change, and two hundred finished jobs at full size would make every
// registration and every report write the better part of a gigabyte. The
// worker trims to the same sizes before sending, so a result is never larger on
// the wire than what will be kept.
const (
	KeepStdout = 256 << 10
	KeepStderr = 64 << 10
)

// TrimOutput shortens s to about max bytes, keeping its head and its tail.
func TrimOutput(s string, max int) string {
	if len(s) <= max {
		return s
	}
	head := max / 8
	tail := max - head
	// Cut on line boundaries where there is one nearby, so the join does not
	// land in the middle of a word.
	h := s[:head]
	if i := strings.LastIndexByte(h, '\n'); i > head/2 {
		h = h[:i+1]
	}
	t := s[len(s)-tail:]
	if i := strings.IndexByte(t, '\n'); i >= 0 && i < tail/2 {
		t = t[i+1:]
	}
	return fmt.Sprintf("%s\n[… %d bytes of output dropped by LocNet …]\n\n%s", h, len(s)-len(h)-len(t), t)
}
