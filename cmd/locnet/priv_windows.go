package main

import "golang.org/x/sys/windows"

// canWriteSystemRegistry reports whether this process is running elevated.
//
// Opening a machine-wide key for write is a cheap and honest proxy: it is
// exactly the permission the setup steps need, and it fails safe if the answer
// is no.
func canWriteSystemRegistry() bool {
	const path = `SYSTEM\CurrentControlSet\Control\Terminal Server`
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	var h windows.Handle
	if err := windows.RegOpenKeyEx(windows.HKEY_LOCAL_MACHINE, name, 0, windows.KEY_SET_VALUE, &h); err != nil {
		return false
	}
	windows.RegCloseKey(h)
	return true
}
