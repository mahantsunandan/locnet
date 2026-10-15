package screen

import "unicode/utf8"

// The browser is the only thing that knows what the viewer pressed, and what
// it reports is a DOM KeyboardEvent: a `key` ("a", "A", "Enter") and a `code`
// ("KeyA", "Enter", "ShiftLeft"). Neither is a keycode on any platform, so
// every backend needs the same translation and does it from this one table.
//
// `code` is preferred wherever it exists, because it says which physical key
// was pressed regardless of the viewer's own layout, and because it is the
// only one that distinguishes left shift from right.

// namedKey identifies a key that has no character to type.
type namedKey int

const (
	keyNone namedKey = iota
	keyBackspace
	keyTab
	keyEnter
	keyEscape
	keyDelete
	keyInsert
	keyHome
	keyEnd
	keyPageUp
	keyPageDown
	keyLeft
	keyUp
	keyRight
	keyDown
	keyShiftL
	keyShiftR
	keyCtrlL
	keyCtrlR
	keyAltL
	keyAltR
	keyMetaL
	keyMetaR
	keyCapsLock
	keyNumLock
	keyScrollLock
	keyPause
	keyPrintScreen
	keyMenu
	keyF1
	keyF2
	keyF3
	keyF4
	keyF5
	keyF6
	keyF7
	keyF8
	keyF9
	keyF10
	keyF11
	keyF12
	keyNumpadEnter
	keyNumpadDivide
	keyNumpadMultiply
	keyNumpadSubtract
	keyNumpadAdd
	keyNumpadDecimal
	keyNumpad0
	keyNumpad1
	keyNumpad2
	keyNumpad3
	keyNumpad4
	keyNumpad5
	keyNumpad6
	keyNumpad7
	keyNumpad8
	keyNumpad9
)

// byCode covers everything the DOM names the same way on every layout.
var byCode = map[string]namedKey{
	"Backspace":      keyBackspace,
	"Tab":            keyTab,
	"Enter":          keyEnter,
	"Escape":         keyEscape,
	"Delete":         keyDelete,
	"Insert":         keyInsert,
	"Home":           keyHome,
	"End":            keyEnd,
	"PageUp":         keyPageUp,
	"PageDown":       keyPageDown,
	"ArrowLeft":      keyLeft,
	"ArrowUp":        keyUp,
	"ArrowRight":     keyRight,
	"ArrowDown":      keyDown,
	"ShiftLeft":      keyShiftL,
	"ShiftRight":     keyShiftR,
	"ControlLeft":    keyCtrlL,
	"ControlRight":   keyCtrlR,
	"AltLeft":        keyAltL,
	"AltRight":       keyAltR,
	"MetaLeft":       keyMetaL,
	"MetaRight":      keyMetaR,
	"OSLeft":         keyMetaL,
	"OSRight":        keyMetaR,
	"CapsLock":       keyCapsLock,
	"NumLock":        keyNumLock,
	"ScrollLock":     keyScrollLock,
	"Pause":          keyPause,
	"PrintScreen":    keyPrintScreen,
	"ContextMenu":    keyMenu,
	"F1":             keyF1,
	"F2":             keyF2,
	"F3":             keyF3,
	"F4":             keyF4,
	"F5":             keyF5,
	"F6":             keyF6,
	"F7":             keyF7,
	"F8":             keyF8,
	"F9":             keyF9,
	"F10":            keyF10,
	"F11":            keyF11,
	"F12":            keyF12,
	"NumpadEnter":    keyNumpadEnter,
	"NumpadDivide":   keyNumpadDivide,
	"NumpadMultiply": keyNumpadMultiply,
	"NumpadSubtract": keyNumpadSubtract,
	"NumpadAdd":      keyNumpadAdd,
	"NumpadDecimal":  keyNumpadDecimal,
	"Numpad0":        keyNumpad0,
	"Numpad1":        keyNumpad1,
	"Numpad2":        keyNumpad2,
	"Numpad3":        keyNumpad3,
	"Numpad4":        keyNumpad4,
	"Numpad5":        keyNumpad5,
	"Numpad6":        keyNumpad6,
	"Numpad7":        keyNumpad7,
	"Numpad8":        keyNumpad8,
	"Numpad9":        keyNumpad9,
}

// byKey is the fallback for browsers or remote-control clients that send only
// `key`. Sides are guessed as left, which is what a single-sided report means
// in practice.
var byKey = map[string]namedKey{
	"Backspace":   keyBackspace,
	"Tab":         keyTab,
	"Enter":       keyEnter,
	"Escape":      keyEscape,
	"Esc":         keyEscape,
	"Delete":      keyDelete,
	"Del":         keyDelete,
	"Insert":      keyInsert,
	"Home":        keyHome,
	"End":         keyEnd,
	"PageUp":      keyPageUp,
	"PageDown":    keyPageDown,
	"ArrowLeft":   keyLeft,
	"ArrowUp":     keyUp,
	"ArrowRight":  keyRight,
	"ArrowDown":   keyDown,
	"Left":        keyLeft,
	"Up":          keyUp,
	"Right":       keyRight,
	"Down":        keyDown,
	"Shift":       keyShiftL,
	"Control":     keyCtrlL,
	"Alt":         keyAltL,
	"AltGraph":    keyAltR,
	"Meta":        keyMetaL,
	"OS":          keyMetaL,
	"CapsLock":    keyCapsLock,
	"NumLock":     keyNumLock,
	"ScrollLock":  keyScrollLock,
	"Pause":       keyPause,
	"PrintScreen": keyPrintScreen,
	"ContextMenu": keyMenu,
	"F1":          keyF1,
	"F2":          keyF2,
	"F3":          keyF3,
	"F4":          keyF4,
	"F5":          keyF5,
	"F6":          keyF6,
	"F7":          keyF7,
	"F8":          keyF8,
	"F9":          keyF9,
	"F10":         keyF10,
	"F11":         keyF11,
	"F12":         keyF12,
}

// lookupNamed resolves a DOM key/code pair to a named key.
func lookupNamed(key, code string) (namedKey, bool) {
	if code != "" {
		if k, ok := byCode[code]; ok {
			return k, true
		}
	}
	if key != "" {
		if k, ok := byKey[key]; ok {
			return k, true
		}
	}
	return keyNone, false
}

// namedKeysym is the X11 keysym for each named key. The numeric constants are
// from keysymdef.h, which has not changed since the 1990s and will not.
var namedKeysym = map[namedKey]uint32{
	keyBackspace:      0xFF08,
	keyTab:            0xFF09,
	keyEnter:          0xFF0D,
	keyEscape:         0xFF1B,
	keyDelete:         0xFFFF,
	keyInsert:         0xFF63,
	keyHome:           0xFF50,
	keyEnd:            0xFF57,
	keyPageUp:         0xFF55,
	keyPageDown:       0xFF56,
	keyLeft:           0xFF51,
	keyUp:             0xFF52,
	keyRight:          0xFF53,
	keyDown:           0xFF54,
	keyShiftL:         0xFFE1,
	keyShiftR:         0xFFE2,
	keyCtrlL:          0xFFE3,
	keyCtrlR:          0xFFE4,
	keyAltL:           0xFFE9,
	keyAltR:           0xFFEA,
	keyMetaL:          0xFFEB, // Super_L: what a Windows key does on Linux
	keyMetaR:          0xFFEC,
	keyCapsLock:       0xFFE5,
	keyNumLock:        0xFF7F,
	keyScrollLock:     0xFF14,
	keyPause:          0xFF13,
	keyPrintScreen:    0xFF61,
	keyMenu:           0xFF67,
	keyF1:             0xFFBE,
	keyF2:             0xFFBF,
	keyF3:             0xFFC0,
	keyF4:             0xFFC1,
	keyF5:             0xFFC2,
	keyF6:             0xFFC3,
	keyF7:             0xFFC4,
	keyF8:             0xFFC5,
	keyF9:             0xFFC6,
	keyF10:            0xFFC7,
	keyF11:            0xFFC8,
	keyF12:            0xFFC9,
	keyNumpadEnter:    0xFF8D,
	keyNumpadDivide:   0xFFAF,
	keyNumpadMultiply: 0xFFAA,
	keyNumpadSubtract: 0xFFAD,
	keyNumpadAdd:      0xFFAB,
	keyNumpadDecimal:  0xFFAE,
	keyNumpad0:        0xFFB0,
	keyNumpad1:        0xFFB1,
	keyNumpad2:        0xFFB2,
	keyNumpad3:        0xFFB3,
	keyNumpad4:        0xFFB4,
	keyNumpad5:        0xFFB5,
	keyNumpad6:        0xFFB6,
	keyNumpad7:        0xFFB7,
	keyNumpad8:        0xFFB8,
	keyNumpad9:        0xFFB9,
}

// keysymFor turns a DOM key event into an X11 keysym, or zero when there is
// nothing sensible to press.
func keysymFor(key, code string) uint32 {
	if nk, ok := lookupNamed(key, code); ok {
		return namedKeysym[nk]
	}
	r := singleRune(key)
	switch {
	case r == 0:
		return 0
	case r < 0x100:
		// Latin-1 is its own keysym range, which is why 'a' is 0x61.
		return uint32(r)
	default:
		// Everything else uses the Unicode escape introduced in X11R6.
		return 0x01000000 | uint32(r)
	}
}

// singleRune returns the character a key event types, or zero if the key value
// is a name rather than a character.
func singleRune(key string) rune {
	if key == "" {
		return 0
	}
	r, size := utf8.DecodeRuneInString(key)
	if size != len(key) || r == utf8.RuneError {
		return 0
	}
	return r
}
