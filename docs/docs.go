// Package docs is LocNet's documentation, compiled into the programs so the
// console's Docs page always describes the version that is running — never a
// newer or older copy found on disk or on a web site.
package docs

import (
	"embed"
	"io/fs"
	"strings"
)

//go:embed *.md
var files embed.FS

// Order is how the console lists them: where to start, the reference, the
// guides by topic, the internals, and what changed. A document not named here
// is listed after these, so adding one never hides it.
var Order = []string{
	"GUIDE", "COMMANDS", "INSTALL", "SHARING", "DESKTOP", "COMPUTE", "QUEUE",
	"OPERATIONS", "SECURITY", "ARCHITECTURE", "PROTOCOL", "CHANGELOG",
}

// Doc is one document.
type Doc struct {
	Name  string `json:"name"`  // "GUIDE", from GUIDE.md
	Title string `json:"title"` // its first heading
}

// List returns every document, in Order.
func List() []Doc {
	entries, _ := fs.ReadDir(files, ".")
	have := map[string]bool{}
	for _, e := range entries {
		if name, ok := strings.CutSuffix(e.Name(), ".md"); ok {
			have[name] = true
		}
	}
	var out []Doc
	add := func(name string) {
		if have[name] {
			text, _ := Read(name)
			out = append(out, Doc{Name: name, Title: title(text, name)})
			delete(have, name)
		}
	}
	for _, name := range Order {
		add(name)
	}
	for _, e := range entries {
		if name, ok := strings.CutSuffix(e.Name(), ".md"); ok {
			add(name)
		}
	}
	return out
}

// Read returns one document's markdown, by name without ".md".
func Read(name string) (string, bool) {
	if strings.ContainsAny(name, `/\.`) {
		return "", false
	}
	b, err := files.ReadFile(name + ".md")
	if err != nil {
		return "", false
	}
	return string(b), true
}

func title(text, fallback string) string {
	for _, line := range strings.Split(text, "\n") {
		if t, ok := strings.CutPrefix(line, "# "); ok {
			return strings.TrimSpace(t)
		}
	}
	return fallback
}
