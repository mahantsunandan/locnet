package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// As in cmd/locnet: every command in locnet-hub's help is in the reference.
func TestEveryCommandIsInTheReference(t *testing.T) {
	ref, err := os.ReadFile("../../docs/COMMANDS.md")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\s+locnet-hub ([a-z][a-z-]*)`).FindAllStringSubmatch(usage, -1) {
		cmd := m[1]
		if seen[cmd] {
			continue
		}
		seen[cmd] = true
		if !strings.Contains(string(ref), "`locnet-hub "+cmd) {
			t.Errorf("`locnet-hub %s` is in locnet-hub's help but not in docs/COMMANDS.md", cmd)
		}
	}
	if len(seen) < 10 {
		t.Errorf("found only %d commands in the help; the pattern no longer matches it", len(seen))
	}
}
