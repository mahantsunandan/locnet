package node

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mahantsunandan/locnet/internal/resource"
)

// SharePort is where the file-share API listens, on the overlay address only.
const SharePort = 8421

// maxUploadSize caps a single uploaded file.
const maxUploadSize = 8 << 30 // 8 GiB

// shareServer serves this node's shares to peers.
//
// Authentication is the connection's source address, and that is stronger here
// than it sounds anywhere else. The listener is bound to the overlay address,
// so the only way to reach it is through the tunnel, and WireGuard's
// allowed-IP check means a packet claiming to be from 100.100.0.3 was
// decrypted with that node's key. There is no token to steal and no password
// to leak, because the tunnel has already answered the question.
//
// The one thing this depends on is that the listener never becomes reachable
// from outside the tunnel. That is why it binds a specific address rather than
// 0.0.0.0, and why it re-checks the source address on every request instead of
// trusting the bind alone.
type shareServer struct {
	logf func(string, ...any)

	mu       sync.Mutex
	shares   []resource.Share
	compute  resource.ComputeConfig
	desktop  resource.DesktopConfig
	deskReg  *desktopReg
	lookup   resource.PeerLookup
	overlay  netip.Addr
	http     *http.Server
	forwards map[string]*forwarder // keyed by share name
	// lastProbe is the last probe result logged for each peer, so a result
	// that has not changed is not logged again every five minutes.
	lastProbe map[string]string
}

func newShareServer(logf func(string, ...any)) *shareServer {
	return &shareServer{
		logf:     logf,
		forwards: map[string]*forwarder{},
		deskReg:  newDesktopReg(),
	}
}

// start binds the file-share API to the overlay address.
func (s *shareServer) start(overlay netip.Addr) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.http != nil {
		return nil
	}
	s.overlay = overlay

	addr := netip.AddrPortFrom(overlay, SharePort).String()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("share server: listen on %s: %w", addr, err)
	}

	srv := &http.Server{
		Handler:           http.HandlerFunc(s.serve),
		ReadHeaderTimeout: 15 * time.Second,
	}
	s.http = srv
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.logf("share server: %v", err)
		}
	}()
	s.logf("share server listening on %s", addr)
	return nil
}

// stop shuts the API and every port forward down.
func (s *shareServer) stop() {
	s.mu.Lock()
	srv := s.http
	s.http = nil
	fwds := s.forwards
	s.forwards = map[string]*forwarder{}
	s.overlay = netip.Addr{}
	s.mu.Unlock()

	for _, f := range fwds {
		f.close()
	}
	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
}

// setShares replaces the share list and reconciles the port forwards.
func (s *shareServer) setShares(shares []resource.Share) {
	s.mu.Lock()
	s.shares = append(s.shares[:0], shares...)
	overlay := s.overlay
	running := s.http != nil
	s.mu.Unlock()

	if !running || !overlay.IsValid() {
		return
	}
	s.reconcileForwards(shares, overlay)
}

// setPeerLookup installs the function that turns an overlay address into a
// peer name. It changes on every netmap update.
func (s *shareServer) setPeerLookup(l resource.PeerLookup) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lookup = l
}

// identify resolves a request's source address to a peer name.
func (s *shareServer) identify(remoteAddr string) (string, bool) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return "", false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return "", false
	}
	s.mu.Lock()
	lookup := s.lookup
	s.mu.Unlock()
	if lookup == nil {
		return "", false
	}
	return lookup(ip.Unmap())
}

// shareFor returns the named share if peer may use it.
func (s *shareServer) shareFor(name, peer string) (resource.Share, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sh := range s.shares {
		if sh.Name == name && sh.AllowsPeer(peer) {
			return sh, true
		}
	}
	return resource.Share{}, false
}

// ------------------------------------------------------------------ HTTP

func (s *shareServer) serve(w http.ResponseWriter, r *http.Request) {
	peer, ok := s.identify(r.RemoteAddr)
	if !ok {
		// Either not a member, or a member the netmap has not caught up
		// with. Either way there is nothing to say to them.
		http.Error(w, "not a member of this network", http.StatusForbidden)
		return
	}

	switch {
	case r.URL.Path == "/shares":
		s.handleList(w, peer)
	case strings.HasPrefix(r.URL.Path, "/files/"):
		s.handleFiles(w, r, peer)
	case r.URL.Path == "/exec" && r.Method == http.MethodPost:
		s.handleExec(w, r, peer)
	case strings.HasPrefix(r.URL.Path, "/desktop/"):
		s.handleDesktop(w, r, peer)
	case r.URL.Path == "/wake" && r.Method == http.MethodPost:
		s.handleWake(w, r, peer)
	case r.URL.Path == "/probe" && r.Method == http.MethodPost:
		s.handleProbe(w, r, peer)
	default:
		http.NotFound(w, r)
	}
}

func (s *shareServer) handleList(w http.ResponseWriter, peer string) {
	s.mu.Lock()
	shares := append([]resource.Share(nil), s.shares...)
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resource.Advertise(shares, peer))
}

func (s *shareServer) handleFiles(w http.ResponseWriter, r *http.Request, peer string) {
	rest := strings.TrimPrefix(r.URL.Path, "/files/")
	shareName, rel, _ := strings.Cut(rest, "/")

	share, ok := s.shareFor(shareName, peer)
	if !ok || share.Kind != resource.KindFiles {
		s.logf("share server: %s asked for share %q and was refused", peer, shareName)
		http.Error(w, "no such share", http.StatusNotFound)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.serveGet(w, r, share, rel)
	case http.MethodPut:
		s.servePut(w, r, share, rel, peer)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *shareServer) serveGet(w http.ResponseWriter, r *http.Request, share resource.Share, rel string) {
	if _, err := resolveWithin(share.Target, rel); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// resolveWithin decides whether the request is acceptable and says why
	// not; the open goes through an os.Root, which refuses to leave the share
	// at the moment of opening. Between a check and an open, a local user who
	// can write inside the share could swap a directory for a symlink to /,
	// and locnetd, which runs as root, would follow it.
	root, err := os.OpenRoot(share.Target)
	if err != nil {
		http.Error(w, "share root is unreadable", http.StatusInternalServerError)
		return
	}
	defer root.Close()
	f, err := root.Open(rootRel(rel))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	if info.IsDir() {
		entries, err := f.ReadDir(-1)
		if err != nil {
			http.Error(w, "cannot read directory", http.StatusInternalServerError)
			return
		}
		out := make([]resource.FileEntry, 0, len(entries))
		for _, e := range entries {
			fi, err := e.Info()
			if err != nil {
				continue
			}
			out = append(out, resource.FileEntry{
				Name: e.Name(), Size: fi.Size(),
				IsDir: e.IsDir(), ModTime: fi.ModTime(),
			})
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].IsDir != out[j].IsDir {
				return out[i].IsDir
			}
			return out[i].Name < out[j].Name
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
		return
	}

	// FormatMediaType quotes and escapes the name; a file called `a".txt`
	// pasted between quotes by hand produced a header no client parsed.
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": info.Name()}))
	http.ServeContent(w, r, info.Name(), info.ModTime(), f)
}

func (s *shareServer) servePut(w http.ResponseWriter, r *http.Request, share resource.Share, rel, peer string) {
	if share.ReadOnly {
		http.Error(w, "this share is read-only", http.StatusForbidden)
		return
	}
	if rel == "" {
		http.Error(w, "no filename given", http.StatusBadRequest)
		return
	}
	if _, err := resolveWithin(share.Target, rel); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	root, err := os.OpenRoot(share.Target)
	if err != nil {
		http.Error(w, "share root is unreadable", http.StatusInternalServerError)
		return
	}
	defer root.Close()
	name := rootRel(rel)

	// Write to a temporary name and rename into place, so an interrupted
	// upload never leaves a half-written file where a whole one is expected.
	//
	// The temporary name is random and created exclusively. It used to be
	// the target's name plus ".locnet-upload", opened with O_TRUNC: anyone
	// who could write in the share's folder could put a symlink there first,
	// and the next upload had root truncate and fill whatever it pointed at.
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		http.Error(w, "cannot create file", http.StatusInternalServerError)
		return
	}
	tmp := name + ".locnet-upload-" + hex.EncodeToString(suffix[:])
	f, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		http.Error(w, "cannot create file", http.StatusInternalServerError)
		return
	}
	n, err := io.Copy(f, io.LimitReader(r.Body, maxUploadSize))
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		root.Remove(tmp)
		http.Error(w, "write failed", http.StatusInternalServerError)
		return
	}
	if err := root.Rename(tmp, name); err != nil {
		root.Remove(tmp)
		http.Error(w, "could not finish the upload", http.StatusInternalServerError)
		return
	}
	s.logf("share server: %s uploaded %s to share %q (%d bytes)", peer, rel, share.Name, n)
	w.WriteHeader(http.StatusNoContent)
}

// rootRel turns a request path into the relative form os.Root takes: cleaned,
// anchored so that ".." cannot climb, with the anchor removed.
func rootRel(rel string) string {
	clean := filepath.Clean(string(filepath.Separator) + filepath.FromSlash(rel))
	clean = strings.TrimLeft(clean, string(filepath.Separator))
	if clean == "" {
		return "."
	}
	return clean
}

// resolveWithin turns a request path into a real path inside root, or an
// error.
//
// Two checks, and both are needed. Cleaning the path stops "../.." from
// walking out. Resolving symlinks stops a link *inside* the share from
// pointing outside it — the classic way a "read-only share of /srv/public"
// turns into a read of /etc/shadow.
func resolveWithin(root, rel string) (string, error) {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("share root is unreadable")
	}

	// Anchor at / before cleaning so that leading ".." is discarded rather
	// than escaping, then strip the anchor back off.
	clean := filepath.Clean("/" + filepath.FromSlash(rel))
	full := filepath.Join(realRoot, clean)

	// The target may not exist yet — an upload of a new file. In that case
	// the containing directory is what has to be inside the share.
	check := full
	if _, err := os.Lstat(full); err != nil {
		check = filepath.Dir(full)
	}
	realTarget, err := filepath.EvalSymlinks(check)
	if err != nil {
		return "", fmt.Errorf("no such path")
	}
	if !isWithin(realRoot, realTarget) {
		return "", fmt.Errorf("path is outside the share")
	}
	return full, nil
}

func isWithin(root, p string) bool {
	if p == root {
		return true
	}
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// -------------------------------------------------------------- forwards

// forwarder publishes a local service on the overlay.
//
// This is what makes a database bound to 127.0.0.1 reachable by a colleague
// without rebinding it to 0.0.0.0 and exposing it to the whole LAN. The
// listener is on the overlay address only, and every accepted connection is
// checked against the share's access list before anything is dialled.
type forwarder struct {
	share    resource.Share
	ln       net.Listener
	srv      *shareServer
	closeOne sync.Once
}

func (s *shareServer) reconcileForwards(shares []resource.Share, overlay netip.Addr) {
	want := map[string]resource.Share{}
	for _, sh := range shares {
		if sh.Kind == resource.KindPort {
			want[sh.Name] = sh
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for name, f := range s.forwards {
		sh, keep := want[name]
		if !keep || sh.Port != f.share.Port || sh.Target != f.share.Target {
			f.close()
			delete(s.forwards, name)
			continue
		}
		// Same listener, possibly a changed access list.
		f.share = sh
	}

	for name, sh := range want {
		if _, exists := s.forwards[name]; exists {
			continue
		}
		addr := netip.AddrPortFrom(overlay, sh.Port).String()
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			s.logf("share %q: cannot listen on %s: %v", name, addr, err)
			continue
		}
		f := &forwarder{share: sh, ln: ln, srv: s}
		s.forwards[name] = f
		go f.accept()
		s.logf("share %q: forwarding %s to %s", name, addr, sh.Target)
	}
}

func (f *forwarder) accept() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return // listener closed
		}
		go f.handle(conn)
	}
}

func (f *forwarder) handle(conn net.Conn) {
	defer conn.Close()

	peer, ok := f.srv.identify(conn.RemoteAddr().String())
	if !ok {
		return
	}
	f.srv.mu.Lock()
	share := f.share
	f.srv.mu.Unlock()

	if !share.AllowsPeer(peer) {
		f.srv.logf("share %q: refused %s", share.Name, peer)
		return
	}

	target := share.Target
	if !strings.Contains(target, ":") {
		target = "127.0.0.1:" + target
	}
	upstream, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		// Worth spelling out, because the peer cannot tell this apart from a
		// broken server: it opened a connection, got nothing, and closed. The
		// share is published and the thing it publishes is not running.
		f.srv.logf("share %q: %s asked for it but nothing is listening on %s (%v) — "+
			"the share is published, the server behind it is not running",
			share.Name, peer, target, err)
		return
	}
	defer upstream.Close()

	// Copy both ways and stop as soon as either direction ends, so a
	// half-closed connection does not leak a goroutine.
	done := make(chan struct{}, 2)
	go func() { io.Copy(upstream, conn); done <- struct{}{} }()
	go func() { io.Copy(conn, upstream); done <- struct{}{} }()
	<-done
}

func (f *forwarder) close() {
	f.closeOne.Do(func() { f.ln.Close() })
}
