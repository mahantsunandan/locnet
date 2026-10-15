package remote

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Entry is one file or folder, on either side.
type Entry struct {
	Name  string `json:"name"`
	Size  int64  `json:"size"`
	IsDir bool   `json:"is_dir"`
	// Mod is a Unix timestamp. Zero when it could not be read.
	Mod int64 `json:"mod,omitempty"`
	// Link is true for a symlink, which is worth showing because copying
	// one does something different from copying what it points at.
	Link bool `json:"link,omitempty"`
}

// Listing is a folder and what is in it.
type Listing struct {
	Path    string  `json:"path"`
	Parent  string  `json:"parent,omitempty"`
	Entries []Entry `json:"entries"`
}

// ListLocal reads a folder on this machine.
func ListLocal(dir string) (*Listing, error) {
	if dir == "" || dir == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		dir = home
	}
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	out := &Listing{Path: dir, Parent: path.Dir(dir)}
	if out.Parent == dir {
		out.Parent = ""
	}
	for _, de := range des {
		e := Entry{Name: de.Name(), IsDir: de.IsDir(), Link: de.Type()&os.ModeSymlink != 0}
		if info, err := de.Info(); err == nil {
			e.Size, e.Mod = info.Size(), info.ModTime().Unix()
			if e.Link {
				// Follow it so a linked folder still browses as a folder.
				if st, err := os.Stat(path.Join(dir, de.Name())); err == nil {
					e.IsDir = st.IsDir()
				}
			}
		}
		out.Entries = append(out.Entries, e)
	}
	sortEntries(out.Entries)
	return out, nil
}

// listScript prints one line per entry, in a form no locale or `ls` variant
// can rearrange.
//
// Parsing `ls -l` is the obvious approach and the wrong one: the column layout
// shifts between platforms, dates are localised, and a filename containing a
// space cannot be told from the columns around it. Emitting the fields we want,
// tab-separated, with the name last, removes all of that.
//
// GNU find does the whole folder in one process. The loop is for machines
// without it — macOS, BSD, busybox — and costs a process or two per entry,
// which a home directory with a few thousand files notices, so it is only the
// fallback. Fields: type (following links), size, modified time, whether it is
// a link, name.
const listScript = `cd -- %s 2>/dev/null || { echo "__ERR__no such folder"; exit 0; }
pwd | sed 's/^/__PWD__/'
if find . -maxdepth 0 -printf '' >/dev/null 2>&1; then
  find . -mindepth 1 -maxdepth 1 -printf '%%Y\t%%s\t%%T@\t%%y\t%%f\n' 2>/dev/null
  exit 0
fi
for f in * .[!.]* ..?*; do
  [ -e "$f" ] || [ -L "$f" ] || continue
  t=f; [ -d "$f" ] && t=d
  l=0; [ -L "$f" ] && l=1
  s=0
  if [ -f "$f" ]; then
    s=$(wc -c < "$f" 2>/dev/null || echo 0)
  fi
  m=$(stat -c %%Y "$f" 2>/dev/null || stat -f %%m "$f" 2>/dev/null || echo 0)
  printf '%%s\t%%s\t%%s\t%%s\t%%s\n' "$t" "$s" "$m" "$l" "$f"
done`

// ListRemote reads a folder on a peer, over SSH.
func ListRemote(ctx context.Context, t Target, dir string) (*Listing, error) {
	if dir == "" {
		dir = "~"
	}
	target := dir
	if dir != "~" {
		target = shQuote(dir)
	}

	c, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	args := append(sshOpts(10), "-n", t.dest(), fmt.Sprintf(listScript, target))
	cmd, err := lookCommand("ssh", args)
	if err != nil {
		return nil, err
	}

	var lines []string
	res := fan(c, []Target{t}, func(_, line string) { lines = append(lines, line) },
		func(Target) (*exec.Cmd, error) { return cmd, nil })[0]
	if !res.OK && len(lines) == 0 {
		return nil, fmt.Errorf("%s", res.Error)
	}

	out := &Listing{Path: dir}
	for _, line := range lines {
		if strings.HasPrefix(line, "__ERR__") {
			return nil, fmt.Errorf("%s: %s", dir, strings.TrimPrefix(line, "__ERR__"))
		}
		if strings.HasPrefix(line, "__PWD__") {
			// The shell resolved ~ and any symlinks; use its answer so the
			// path shown is one that can be typed back.
			out.Path = strings.TrimPrefix(line, "__PWD__")
			continue
		}
		f := strings.SplitN(line, "\t", 5)
		if len(f) < 5 {
			continue
		}
		isDir := f[0] == "d"
		size, _ := strconv.ParseInt(strings.TrimSpace(f[1]), 10, 64)
		if isDir {
			size = 0 // find reports the directory inode's size, which means nothing here
		}
		// find prints seconds with a fraction; the fallback prints whole ones.
		modF, _ := strconv.ParseFloat(strings.TrimSpace(f[2]), 64)
		out.Entries = append(out.Entries, Entry{
			Name:  f[4],
			IsDir: isDir,
			Size:  size,
			Mod:   int64(modF),
			Link:  f[3] == "1" || f[3] == "l",
		})
	}
	if out.Path != "/" {
		out.Parent = path.Dir(out.Path)
	}
	sortEntries(out.Entries)
	return out, nil
}

// sortEntries puts folders first, then names, case-insensitively. That is what
// every file manager does, and browsing is muscle memory.
func sortEntries(e []Entry) {
	sort.Slice(e, func(i, j int) bool {
		if e[i].IsDir != e[j].IsDir {
			return e[i].IsDir
		}
		return strings.ToLower(e[i].Name) < strings.ToLower(e[j].Name)
	})
}

// Reachable reports whether a TCP port on a peer answers.
//
// Used before launching a remote-desktop client, because a client started
// against a port with nothing behind it either sits on a timeout or flashes an
// error and vanishes — and either way LocNet has said "launched" and the
// person is left with a button that appears to do nothing. Checking first
// turns that into a sentence explaining what is missing.
func Reachable(ctx context.Context, host string, port uint16, wait time.Duration) bool {
	c, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(c, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
