package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Every command `locnet --help` lists must have an entry in the command
// reference. A command added without one fails here, which is the point: the
// reference is only worth having if it is complete.
func TestEveryCommandIsInTheReference(t *testing.T) {
	ref, err := os.ReadFile("../../docs/COMMANDS.md")
	if err != nil {
		t.Fatal(err)
	}
	cmds := commandsIn(usage, "locnet")
	if len(cmds) < 30 {
		t.Errorf("found only %d commands in the help; the pattern no longer matches it", len(cmds))
	}
	for _, cmd := range cmds {
		if !strings.Contains(string(ref), "`locnet "+cmd) {
			t.Errorf("`locnet %s` is in locnet's help but not in docs/COMMANDS.md", cmd)
		}
	}
}

// commandsIn finds the subcommands a usage text names: "prog word".
func commandsIn(text, prog string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range regexp.MustCompile(`(?m)^\s+`+regexp.QuoteMeta(prog)+` ([a-z][a-z-]*)`).FindAllStringSubmatch(text, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}
