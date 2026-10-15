package remote

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestListRemoteHandlesAwkwardNames(t *testing.T) {
	home := fakeMachine(t)

	// The names that break `ls -l` parsing: spaces, and a leading dot.
	dir := filepath.Join(home, "work")
	if err := os.MkdirAll(filepath.Join(dir, "a folder with spaces"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "my report v2.pdf"), "1234567890")
	write(t, filepath.Join(dir, ".hidden"), "x")

	got, err := ListRemote(context.Background(),
		Target{Name: "lab", Host: "10.99.0.1"}, dir)
	if err != nil {
		t.Fatal(err)
	}

	byName := map[string]Entry{}
	for _, e := range got.Entries {
		byName[e.Name] = e
	}

	if e, ok := byName["a folder with spaces"]; !ok || !e.IsDir {
		t.Errorf("a folder whose name contains spaces was lost or misclassified: %+v", got.Entries)
	}
	if e, ok := byName["my report v2.pdf"]; !ok {
		t.Errorf("a file whose name contains spaces was lost: %+v", got.Entries)
	} else if e.Size != 10 {
		t.Errorf("size = %d, want 10", e.Size)
	}
	// Dotfiles are the ones people are looking for when they browse a home
	// directory over SSH, so a listing that hides them is wrong.
	if _, ok := byName[".hidden"]; !ok {
		t.Errorf("hidden files were not listed: %+v", got.Entries)
	}
}

func TestListRemoteFoldersSortFirst(t *testing.T) {
	home := fakeMachine(t)
	dir := filepath.Join(home, "s")
	os.MkdirAll(filepath.Join(dir, "zzz-folder"), 0o755)
	write(t, filepath.Join(dir, "aaa-file"), "x")

	got, err := ListRemote(context.Background(), Target{Name: "lab", Host: "10.99.0.1"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) < 2 || !got.Entries[0].IsDir {
		t.Errorf("folders should sort before files: %+v", got.Entries)
	}
}

func TestListRemoteMissingFolderIsAClearError(t *testing.T) {
	fakeMachine(t)
	_, err := ListRemote(context.Background(),
		Target{Name: "lab", Host: "10.99.0.1"}, "/definitely/not/here")
	if err == nil {
		t.Fatal("expected an error for a missing folder")
	}
}

func TestListLocalReadsThisMachine(t *testing.T) {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "sub"), 0o755)
	write(t, filepath.Join(dir, "file with space.txt"), "abc")

	got, err := ListLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(got.Entries), got.Entries)
	}
	if !got.Entries[0].IsDir || got.Entries[0].Name != "sub" {
		t.Errorf("folders should sort first, got %+v", got.Entries)
	}
	if got.Parent == "" {
		t.Error("a parent should be offered so the pane can go up")
	}
}
