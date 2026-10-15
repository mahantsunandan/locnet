package setup

import (
	"os"
	"os/exec"
	"strings"
)

// runQuiet runs a command and reports whether it succeeded.
func runQuiet(name string, args ...string) bool {
	return exec.Command(name, args...).Run() == nil
}

// runOutput runs a command and returns its combined output.
func runOutput(name string, args ...string) (string, bool) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err == nil
}

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
