//go:build linux

package screen

import "os"

// open attaches to the X server this session belongs to.
//
// A Wayland session is refused rather than half-served. Xwayland answers on
// DISPLAY and will happily hand over the root window, but that window contains
// only the X11 clients still running under translation — usually nothing — so
// capturing it produces a black rectangle and a bug report. Wayland's own
// screen capture goes through the desktop portal, which means dbus, PipeWire
// and a consent dialog on the far machine; deskserve falls back to a local VNC
// server instead, which is a dependency you can see and turn off.
func open() (Session, error) {
	if isWayland() && os.Getenv("LOCNET_DESKTOP_X11") == "" {
		return nil, unsupported("this is a Wayland session, which cannot be captured through X11.\n" +
			"Either log in to an Xorg session, or run a VNC server here and let LocNet bridge it " +
			"(see docs/DESKTOP.md). Set LOCNET_DESKTOP_X11=1 to try anyway")
	}
	return dialX11()
}

func isWayland() bool {
	return os.Getenv("WAYLAND_DISPLAY") != "" || os.Getenv("XDG_SESSION_TYPE") == "wayland"
}
