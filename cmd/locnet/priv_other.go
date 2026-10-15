//go:build !windows

package main

// canWriteSystemRegistry exists only so the privilege check compiles on every
// platform. On Unix the euid check is the real answer.
func canWriteSystemRegistry() bool { return false }
