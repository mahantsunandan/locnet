package resource

import (
	"fmt"
	"strings"
)

// DesktopConfig is a machine's offer to show its screen to its peers, and
// optionally to let them drive it.
//
// This is the most invasive thing a machine can offer — more than a file share
// and, in practice, more than compute, because a desktop session is already
// logged in as somebody. So the defaults are the paranoid ones: off, nobody
// allowed, and view-only even once it is on. Turning on control is a separate,
// deliberate flag.
//
// The pixels do not come from locnetd. A system service has no desktop to look
// at — on Windows it lives in session 0 where the screen is a blank virtual
// one, and on Linux it has no DISPLAY and no X authority. Capture therefore
// happens in `locnet desktop serve`, a small process that runs as the logged-in
// user and registers itself with the daemon. The daemon still decides who is
// allowed in; the helper only ever answers loopback.
type DesktopConfig struct {
	// Enabled is false until someone turns it on. There is no way to enable
	// it remotely.
	Enabled bool `json:"enabled"`

	// Allow lists the peer names that may watch. "*" means every member.
	// Empty means nobody, which is the default.
	Allow []string `json:"allow,omitempty"`

	// Control lets watchers move the mouse and type. Off by default: being
	// able to see a screen and being able to use it are different decisions
	// and deserve different answers.
	Control bool `json:"control,omitempty"`

	// MaxFPS caps the frame rate. Zero means DefaultDesktopFPS.
	MaxFPS int `json:"max_fps,omitempty"`

	// Quality is the JPEG quality for changed tiles, 1..100. Zero means
	// DefaultDesktopQuality.
	Quality int `json:"quality,omitempty"`

	// Label is free text shown to peers, e.g. "reception PC, 4K".
	Label string `json:"label,omitempty"`
}

const (
	// DefaultDesktopFPS is fast enough to feel live and slow enough that a
	// 4K screen does not saturate a link on its own.
	DefaultDesktopFPS = 12
	// DefaultDesktopQuality trades a little sharpness on photographs for a
	// large saving on the text and flat panels that make up most of a
	// desktop.
	DefaultDesktopQuality = 62
	// MaxDesktopFPS bounds what a client may ask for.
	MaxDesktopFPS = 30
)

// Validate checks a configuration before it is stored.
func (c *DesktopConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if len(c.Allow) == 0 {
		return fmt.Errorf("desktop sharing is enabled but no peer is allowed to watch — pass -allow")
	}
	if c.MaxFPS < 0 || c.MaxFPS > MaxDesktopFPS {
		return fmt.Errorf("frame rate must be between 1 and %d", MaxDesktopFPS)
	}
	if c.Quality < 0 || c.Quality > 100 {
		return fmt.Errorf("quality must be between 1 and 100")
	}
	return nil
}

// AllowsPeer reports whether a peer may watch this screen.
func (c *DesktopConfig) AllowsPeer(name string) bool {
	if !c.Enabled {
		return false
	}
	for _, a := range c.Allow {
		if a == "*" || a == name {
			return true
		}
	}
	return false
}

// AllowText renders the audience for display.
func (c *DesktopConfig) AllowText() string {
	switch {
	case !c.Enabled:
		return "disabled"
	case len(c.Allow) == 0:
		return "nobody"
	case len(c.Allow) == 1 && c.Allow[0] == "*":
		return "everyone"
	default:
		return strings.Join(c.Allow, ", ")
	}
}

// FPS returns the effective frame-rate cap.
func (c *DesktopConfig) FPS() int {
	if c.MaxFPS > 0 {
		return min(c.MaxFPS, MaxDesktopFPS)
	}
	return DefaultDesktopFPS
}

// JPEGQuality returns the effective tile quality.
func (c *DesktopConfig) JPEGQuality() int {
	if c.Quality > 0 {
		return c.Quality
	}
	return DefaultDesktopQuality
}

// DesktopStatus is what the session helper reports about the screen it is
// attached to. It is live state, not configuration: it changes when someone
// logs out, plugs in a monitor, or locks the machine.
type DesktopStatus struct {
	// Ready is true when the screen can be captured right now.
	Ready bool `json:"ready,omitempty"`
	// Width and Height are the current resolution.
	Width  int `json:"width,omitempty"`
	Height int `json:"height,omitempty"`
	// Control is true when this platform can also inject input. A Mac can
	// be watched but not driven, and saying so up front is kinder than a
	// mouse that does nothing.
	Control bool `json:"control,omitempty"`
	// Error explains a screen that cannot be captured — a Wayland session,
	// a missing permission — in a sentence meant for a person.
	Error string `json:"error,omitempty"`

	// Via names where the pixels come from: the platform's own capture, or
	// a VNC server being bridged. Worth showing, because a bridged screen
	// behaves slightly differently — no remote cursor, and it stops when
	// that server does.
	Via string `json:"via,omitempty"`
}

// DesktopOffer is what a peer is told: that a machine will show its screen,
// whether that peer may also drive it, and whether anyone is currently logged
// in to look at. Never who is logged in, or what they are running.
type DesktopOffer struct {
	// Control is true when this viewer may send input, not merely when the
	// machine permits control in general.
	Control bool `json:"control,omitempty"`

	// Ready is true when a session helper is registered right now. When it
	// is false the machine is willing but nobody is logged in — which is a
	// different problem from "not allowed", and the console says so.
	Ready bool `json:"ready"`

	// Label is free text from the operator.
	Label string `json:"label,omitempty"`

	// Width and Height are the last known screen size, zero if the helper
	// has not captured anything yet.
	Width  int `json:"width,omitempty"`
	Height int `json:"height,omitempty"`

	// Problem is why a willing machine cannot be watched, when there is
	// such a reason. Empty is the normal case.
	Problem string `json:"problem,omitempty"`

	// Via names where the pixels come from, when it is not the platform's
	// own capture.
	Via string `json:"via,omitempty"`
}
