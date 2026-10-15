package node

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mahantsunandan/locnet/internal/resource"
)

// newTestServer builds a share server whose peer lookup is fixed, so a test
// can present itself as any peer by choosing a source address.
func newTestServer(t *testing.T, shares ...resource.Share) *shareServer {
	t.Helper()
	s := newShareServer(func(string, ...any) {})
	s.setShares(shares)
	s.setPeerLookup(func(a netip.Addr) (string, bool) {
		switch a.String() {
		case "100.100.0.2":
			return "alpha", true
		case "100.100.0.3":
			return "beta", true
		}
		return "", false
	})
	return s
}

// request drives the handler as if from the given overlay address.
func request(s *shareServer, method, path, from string, body io.Reader) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, body)
	r.RemoteAddr = from + ":54321"
	w := httptest.NewRecorder()
	s.serve(w, r)
	return w
}

func filesShare(t *testing.T, name string, allow ...string) (resource.Share, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	return resource.Share{
		Name: name, Kind: resource.KindFiles, Target: dir,
		ReadOnly: true, Allow: allow,
	}, dir
}

// TestShareAccessControl is the core promise: a peer sees only what it was
// granted, and cannot reach anything else even by asking directly.
func TestShareAccessControl(t *testing.T) {
	forAlpha, _ := filesShare(t, "alpha-only", "alpha")
	forAll, _ := filesShare(t, "public", "*")
	forNobody, _ := filesShare(t, "private")
	s := newTestServer(t, forAlpha, forAll, forNobody)

	cases := []struct {
		peer, addr string
		visible    []string
	}{
		{"alpha", "100.100.0.2", []string{"alpha-only", "public"}},
		{"beta", "100.100.0.3", []string{"public"}},
	}
	for _, tc := range cases {
		w := request(s, http.MethodGet, "/shares", tc.addr, nil)
		if w.Code != 200 {
			t.Fatalf("%s: /shares returned %d", tc.peer, w.Code)
		}
		var got []resource.Advert
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, a := range got {
			names = append(names, a.Name)
		}
		if strings.Join(names, ",") != strings.Join(tc.visible, ",") {
			t.Errorf("%s sees %v, want %v", tc.peer, names, tc.visible)
		}
	}

	// beta was never granted alpha-only, so asking for it directly must fail
	// — the listing filter is not the enforcement point.
	if w := request(s, http.MethodGet, "/files/alpha-only/readme.txt", "100.100.0.3", nil); w.Code != 404 {
		t.Errorf("beta reading alpha's share returned %d, want 404", w.Code)
	}
	if w := request(s, http.MethodGet, "/files/alpha-only/readme.txt", "100.100.0.2", nil); w.Code != 200 {
		t.Errorf("alpha reading its own share returned %d, want 200", w.Code)
	}
	// A share with an empty access list is shared with nobody, not everybody.
	if w := request(s, http.MethodGet, "/files/private/readme.txt", "100.100.0.2", nil); w.Code != 404 {
		t.Errorf("reading a share with no access list returned %d, want 404", w.Code)
	}
}

// TestNonMemberIsRefused covers a source address that is not in the netmap.
func TestNonMemberIsRefused(t *testing.T) {
	sh, _ := filesShare(t, "public", "*")
	s := newTestServer(t, sh)

	for _, addr := range []string{"100.100.0.9", "192.168.1.10", "127.0.0.1"} {
		if w := request(s, http.MethodGet, "/shares", addr, nil); w.Code != 403 {
			t.Errorf("request from %s returned %d, want 403", addr, w.Code)
		}
	}
}

// TestReadOnlyRejectsUploads covers the read-only flag.
func TestReadOnlyRejectsUploads(t *testing.T) {
	ro, _ := filesShare(t, "ro", "*")
	rw, dir := filesShare(t, "rw", "*")
	rw.ReadOnly = false
	s := newTestServer(t, ro, rw)

	if w := request(s, http.MethodPut, "/files/ro/new.txt", "100.100.0.2", strings.NewReader("x")); w.Code != 403 {
		t.Errorf("upload to a read-only share returned %d, want 403", w.Code)
	}
	if w := request(s, http.MethodPut, "/files/rw/new.txt", "100.100.0.2", strings.NewReader("payload")); w.Code != 204 {
		t.Fatalf("upload to a read-write share returned %d, want 204", w.Code)
	}
	got, err := os.ReadFile(filepath.Join(dir, "new.txt"))
	if err != nil || string(got) != "payload" {
		t.Errorf("uploaded file is %q (%v), want %q", got, err, "payload")
	}
	// The temporary file used during upload must not survive.
	if entries, _ := os.ReadDir(dir); len(entries) != 2 {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("share directory contains %v, want just readme.txt and new.txt", names)
	}
}

// TestPathTraversalIsRefused is the check that keeps a share a share.
func TestPathTraversalIsRefused(t *testing.T) {
	sh, dir := filesShare(t, "pub", "*")
	s := newTestServer(t, sh)

	// Something worth stealing, one level above the share.
	secret := filepath.Join(filepath.Dir(dir), "secret.txt")
	if err := os.WriteFile(secret, []byte("do not leak"), 0o644); err != nil {
		t.Fatal(err)
	}

	attacks := []string{
		"/files/pub/../secret.txt",
		"/files/pub/../../secret.txt",
		"/files/pub/subdir/../../secret.txt",
		"/files/pub/%2e%2e/secret.txt",
		`/files/pub/..\secret.txt`,
	}
	for _, path := range attacks {
		w := request(s, http.MethodGet, path, "100.100.0.2", nil)
		if w.Code == 200 && strings.Contains(w.Body.String(), "do not leak") {
			t.Errorf("%s escaped the share and read the secret", path)
		}
	}
}

// TestSymlinkEscapeIsRefused covers the subtler version: a link that lives
// inside the share but points outside it.
func TestSymlinkEscapeIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need elevation on Windows")
	}
	sh, dir := filesShare(t, "pub", "*")
	s := newTestServer(t, sh)

	secret := filepath.Join(filepath.Dir(dir), "secret.txt")
	if err := os.WriteFile(secret, []byte("do not leak"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(dir, "innocent.txt")); err != nil {
		t.Fatal(err)
	}

	w := request(s, http.MethodGet, "/files/pub/innocent.txt", "100.100.0.2", nil)
	if w.Code == 200 && strings.Contains(w.Body.String(), "do not leak") {
		t.Error("a symlink inside the share read a file outside it")
	}
}

// TestResolveWithin exercises the path check directly.
func TestResolveWithin(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	ok := []string{"", "sub", "sub/f.txt", "/sub/f.txt", "./sub/f.txt"}
	for _, rel := range ok {
		if _, err := resolveWithin(root, rel); err != nil {
			t.Errorf("resolveWithin(%q) = %v, want success", rel, err)
		}
	}
	bad := []string{"..", "../..", "sub/../../elsewhere", "/../etc/passwd"}
	for _, rel := range bad {
		if p, err := resolveWithin(root, rel); err == nil && !isWithin(root, p) {
			t.Errorf("resolveWithin(%q) = %q with no error", rel, p)
		}
	}
}

// TestShareValidation covers the rules applied before a share is accepted.
func TestShareValidation(t *testing.T) {
	bad := []resource.Share{
		{Kind: resource.KindFiles, Target: "/tmp"},                     // no name
		{Name: "a/b", Kind: resource.KindFiles, Target: "/tmp"},        // slash in name
		{Name: "x", Kind: "nonsense", Target: "/tmp"},                  // unknown kind
		{Name: "x", Kind: resource.KindFiles},                          // no target
		{Name: "x", Kind: resource.KindFiles, Target: "relative/path"}, // not absolute
		{Name: "x", Kind: resource.KindPort, Target: "5432"},           // no overlay port
		{Name: "x", Kind: resource.KindPort, Target: "80", Port: 80},   // privileged port
	}
	for _, sh := range bad {
		if err := sh.Validate(); err == nil {
			t.Errorf("Validate accepted %+v", sh)
		}
	}
	good := []resource.Share{
		{Name: "data", Kind: resource.KindFiles, Target: absTemp(t)},
		{Name: "pg", Kind: resource.KindPort, Target: "5432", Port: 15432},
	}
	for _, sh := range good {
		if err := sh.Validate(); err != nil {
			t.Errorf("Validate rejected %+v: %v", sh, err)
		}
	}
}

func absTemp(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return `C:\Temp`
	}
	return "/tmp"
}

// TestUploadDoesNotFollowAPlantedLink: locnetd writes uploads as root, so a
// temporary file at a name anyone could predict let a local user who can write
// in the share's folder aim that write at any file on the machine.
func TestUploadDoesNotFollowAPlantedLink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need elevation on Windows")
	}
	sh, dir := filesShare(t, "drop", "*")
	sh.ReadOnly = false
	s := newTestServer(t, sh)

	victim := filepath.Join(filepath.Dir(dir), "victim.txt")
	if err := os.WriteFile(victim, []byte("intact"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The name the old code used for its temporary file.
	if err := os.Symlink(victim, filepath.Join(dir, "report.txt.locnet-upload")); err != nil {
		t.Fatal(err)
	}

	if w := request(s, http.MethodPut, "/files/drop/report.txt", "100.100.0.2", strings.NewReader("upload")); w.Code != 204 {
		t.Fatalf("upload returned %d: %s", w.Code, w.Body)
	}
	if got, _ := os.ReadFile(victim); string(got) != "intact" {
		t.Errorf("the file outside the share now holds %q", got)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "report.txt")); string(got) != "upload" {
		t.Errorf("the upload holds %q", got)
	}
}

func TestDownloadNameIsQuoted(t *testing.T) {
	sh, dir := filesShare(t, "pub", "*")
	if err := os.WriteFile(filepath.Join(dir, `a"b.txt`), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t, sh)
	w := request(s, http.MethodGet, "/files/pub/a%22b.txt", "100.100.0.2", nil)
	if w.Code != 200 {
		t.Fatalf("download returned %d", w.Code)
	}
	if got := w.Header().Get("Content-Disposition"); got != `attachment; filename="a\"b.txt"` {
		t.Errorf("Content-Disposition is %q", got)
	}
}
