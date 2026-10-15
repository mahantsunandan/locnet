package docs

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"unicode"
)

func TestEveryDocumentIsListedWithATitle(t *testing.T) {
	list := List()
	if len(list) < len(Order) {
		t.Fatalf("%d documents listed, want at least %d", len(list), len(Order))
	}
	for i, name := range Order {
		if list[i].Name != name {
			t.Errorf("position %d is %s, want %s", i, list[i].Name, name)
		}
	}
	for _, d := range list {
		if d.Title == d.Name {
			t.Errorf("%s.md has no # title", d.Name)
		}
	}
	if _, ok := Read("../go"); ok {
		t.Error("Read left the docs directory")
	}
}

// Every link between these documents must land on a document and a heading
// that exist, with anchors worked out the way GitHub works them out — so the
// links work on GitHub, in an editor's preview and in the console alike.
func TestLinksResolve(t *testing.T) {
	anchors := map[string]map[string]bool{}
	for _, d := range List() {
		text, _ := Read(d.Name)
		anchors[d.Name] = headingAnchors(text)
	}
	link := regexp.MustCompile(`\]\(([^)\s]+)\)`)
	for _, d := range List() {
		text, _ := Read(d.Name)
		inFence := false
		for n, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(line, "```") {
				inFence = !inFence
			}
			if inFence {
				continue
			}
			for _, m := range link.FindAllStringSubmatch(line, -1) {
				target := m[1]
				if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
					continue
				}
				doc, anchor, _ := strings.Cut(target, "#")
				name := d.Name
				if doc != "" {
					base, ok := strings.CutSuffix(doc, ".md")
					if !ok || strings.Contains(base, "/") {
						continue // a file elsewhere in the repository
					}
					name = base
					if anchors[name] == nil {
						t.Errorf("%s.md:%d links to %s, which does not exist", d.Name, n+1, doc)
						continue
					}
				}
				if anchor != "" && !anchors[name][anchor] {
					t.Errorf("%s.md:%d links to %s#%s, which has no such heading", d.Name, n+1, name, anchor)
				}
			}
		}
	}
}

// headingAnchors is GitHub's rule: lower-case, drop punctuation but keep
// letters, digits, spaces, hyphens and underscores, spaces become hyphens,
// and repeats get -1, -2.
func headingAnchors(text string) map[string]bool {
	out, seen := map[string]bool{}, map[string]int{}
	inFence := false
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "```") {
			inFence = !inFence
		}
		if inFence || !strings.HasPrefix(line, "#") {
			continue
		}
		h := strings.TrimLeft(line, "#")
		if !strings.HasPrefix(h, " ") {
			continue
		}
		h = strings.ToLower(strings.TrimSpace(h))
		h = regexp.MustCompile(`\[([^\]]+)\]\([^)]*\)`).ReplaceAllString(h, "$1")
		var b strings.Builder
		for _, r := range h {
			switch {
			case unicode.IsLetter(r), unicode.IsDigit(r), r == '_', r == '-':
				b.WriteRune(r)
			case unicode.IsSpace(r):
				b.WriteRune('-')
			}
		}
		id := b.String()
		if n, dup := seen[id]; dup {
			seen[id] = n + 1
			id = fmt.Sprintf("%s-%d", id, n+1)
		} else {
			seen[id] = 0
		}
		out[id] = true
	}
	return out
}
