// Command devserve runs the console page against a made-up network, so every
// page of it can be exercised without a mesh, a second machine, or root.
//
// It is a development tool: `go run ./internal/console/devserve` and open the
// URL it prints. The page is read from disk on every request, so an edit shows
// up on reload. Nothing here touches the real daemon.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mahantsunandan/locnet/docs"
	"github.com/mahantsunandan/locnet/internal/hub"
	"github.com/mahantsunandan/locnet/internal/policy"
)

type mock struct {
	mu       sync.Mutex
	status   map[string]any
	accounts map[string]string
	queue    []map[string]any
	jobs     map[string]*job
	nodes    []map[string]any
	invites  []map[string]any
	audit    []map[string]any
	pol      *policy.Policy
	web      *hub.WebShareView
	seq      int
}

type job struct {
	lines []map[string]string
	done  bool
	sum   string
	pct   int
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8799", "where to listen")
	page := flag.String("page", "internal/console/console.html", "the console page to serve")
	admin := flag.Bool("admin", true, "pretend this machine administers the network")
	flag.Parse()

	m := newMock(*admin)
	const token = "devtoken"
	mux := http.NewServeMux()

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		b, err := os.ReadFile(*page)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(b)
	})

	api := func(pattern string, h func(r *http.Request) (any, error)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Token") != token {
				http.Error(w, `{"error":"bad token"}`, 401)
				return
			}
			out, err := h(r)
			w.Header().Set("Content-Type", "application/json")
			if err != nil {
				w.WriteHeader(400)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			json.NewEncoder(w).Encode(out)
		})
	}
	body := func(r *http.Request) map[string]any {
		var v map[string]any
		json.NewDecoder(r.Body).Decode(&v)
		if v == nil {
			v = map[string]any{}
		}
		return v
	}

	api("GET /api/status", func(r *http.Request) (any, error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.status, nil
	})
	api("GET /api/info", func(r *http.Request) (any, error) {
		return map[string]string{"user": "sono", "downloads": "/home/sono/Downloads", "version": "dev", "os": "linux"}, nil
	})
	api("GET /api/accounts", func(r *http.Request) (any, error) { return m.accounts, nil })
	api("POST /api/account", func(r *http.Request) (any, error) {
		b := body(r)
		m.mu.Lock()
		m.accounts[fmt.Sprint(b["peer"])] = fmt.Sprint(b["user"])
		m.mu.Unlock()
		return b, nil
	})
	api("POST /api/launch", func(r *http.Request) (any, error) {
		b := body(r)
		if b["kind"] == "rdp" && b["peer"] == "hubpc" {
			return nil, fmt.Errorf("hubpc: the RDP server hangs up on every client before anyone can log in. GNOME Remote Desktop does this when RDP is switched on but no RDP username and password have been set. Fix it on that machine, as the person who logs in there: locnet setup rdp")
		}
		return map[string]string{"launched": fmt.Sprintf("%v %v", b["kind"], b["host"])}, nil
	})
	api("GET /api/browse", func(r *http.Request) (any, error) {
		p := r.URL.Query().Get("path")
		if p == "" {
			p = "/home/sono"
			if r.URL.Query().Get("peer") != "." {
				p = "/home/username"
			}
		}
		now := time.Now().Unix()
		return map[string]any{"path": p, "parent": parent(p), "entries": []map[string]any{
			{"name": "Documents", "is_dir": true, "mod": now - 86400},
			{"name": "Projects", "is_dir": true, "mod": now - 3600},
			{"name": "results", "is_dir": true, "mod": now - 600},
			{"name": ".bashrc", "size": 3771, "mod": now - 86400*90},
			{"name": "notes from the meeting.md", "size": 18234, "mod": now - 7200},
			{"name": "run-2026-10-12.tar.gz", "size": 734003200, "mod": now - 86400},
		}}, nil
	})
	api("GET /api/files", func(r *http.Request) (any, error) {
		return []map[string]any{{"name": "papers", "is_dir": true}, {"name": "data.csv", "size": 1048576}}, nil
	})
	api("POST /api/download", func(r *http.Request) (any, error) {
		return map[string]string{"saved": "/home/sono/Downloads/data.csv"}, nil
	})
	api("POST /api/exec", func(r *http.Request) (any, error) {
		b := body(r)
		id := m.newJob(fmt.Sprintf("$ %v → %v", b["command"], b["peers"]), b["peers"], false)
		return map[string]string{"job": id}, nil
	})
	api("POST /api/copy", func(r *http.Request) (any, error) {
		id := m.newJob("sending…", body(r)["peers"], true)
		return map[string]string{"job": id}, nil
	})
	api("POST /api/fetch", func(r *http.Request) (any, error) {
		id := m.newJob("fetching…", body(r)["peers"], true)
		return map[string]string{"job": id}, nil
	})
	api("GET /api/job", func(r *http.Request) (any, error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		j := m.jobs[r.URL.Query().Get("id")]
		if j == nil {
			return nil, fmt.Errorf("no such job")
		}
		since, _ := strconv.Atoi(r.URL.Query().Get("since"))
		if since > len(j.lines) {
			since = 0
		}
		return map[string]any{"lines": j.lines[since:], "next": len(j.lines), "done": j.done, "summary": j.sum, "percent": j.pct}, nil
	})
	api("POST /api/cancel", func(r *http.Request) (any, error) { return map[string]bool{"cancelled": true}, nil })
	api("POST /api/run", func(r *http.Request) (any, error) {
		return map[string]any{"stdout": "16\n", "exit_code": 0, "seconds": 0.02}, nil
	})
	api("GET /api/queue", func(r *http.Request) (any, error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.queue, nil
	})
	api("GET /api/queue/job", func(r *http.Request) (any, error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		for _, j := range m.queue {
			if j["id"] == r.URL.Query().Get("id") {
				cp := map[string]any{}
				for k, v := range j {
					cp[k] = v
				}
				cp["stdout"] = "compiling 214 files…\nlinking\nok: build/app (12.4 MB)\n"
				return cp, nil
			}
		}
		return nil, fmt.Errorf("no such job")
	})
	api("POST /api/queue/submit", func(r *http.Request) (any, error) {
		b := body(r)
		m.mu.Lock()
		defer m.mu.Unlock()
		m.seq++
		j := map[string]any{"id": fmt.Sprintf("j%08x", 0xa1b2c300+m.seq), "state": "queued", "submitter": "linuxbox",
			"command": b["command"], "queued_at": time.Now()}
		m.queue = append([]map[string]any{j}, m.queue...)
		return j, nil
	})
	api("POST /api/queue/cancel", func(r *http.Request) (any, error) {
		b := body(r)
		m.mu.Lock()
		defer m.mu.Unlock()
		for _, j := range m.queue {
			if j["id"] == b["id"] {
				j["state"] = "cancelled"
			}
		}
		return b, nil
	})
	api("POST /api/tunnel", func(r *http.Request) (any, error) {
		b := body(r)
		m.mu.Lock()
		defer m.mu.Unlock()
		m.status["running"] = b["up"]
		return m.status, nil
	})
	api("POST /api/hosts", func(r *http.Request) (any, error) {
		b := body(r)
		m.mu.Lock()
		m.status["manage_hosts"] = b["enabled"]
		m.mu.Unlock()
		return b, nil
	})
	api("POST /api/share/add", func(r *http.Request) (any, error) {
		b := body(r)
		m.mu.Lock()
		defer m.mu.Unlock()
		shares, _ := m.status["shares"].([]any)
		m.status["shares"] = append(shares, b)
		return m.status["shares"], nil
	})
	api("POST /api/share/remove", func(r *http.Request) (any, error) {
		b := body(r)
		m.mu.Lock()
		defer m.mu.Unlock()
		shares, _ := m.status["shares"].([]any)
		var kept []any
		for _, s := range shares {
			if s.(map[string]any)["name"] != b["name"] {
				kept = append(kept, s)
			}
		}
		m.status["shares"] = kept
		return kept, nil
	})
	api("POST /api/compute", func(r *http.Request) (any, error) {
		b := body(r)
		m.mu.Lock()
		m.status["compute"] = b
		m.mu.Unlock()
		return b, nil
	})
	api("POST /api/desktop/stop", func(r *http.Request) (any, error) {
		m.mu.Lock()
		delete(m.status, "desktop")
		m.mu.Unlock()
		return map[string]bool{"stopped": true}, nil
	})
	api("POST /api/wake", func(r *http.Request) (any, error) {
		return map[string]string{"message": "Sent 2 wake-up packet(s) for macbook from hubpc (hubpc is on 192.168.1.20 too)."}, nil
	})
	api("GET /api/diagnose", func(r *http.Request) (any, error) {
		time.Sleep(900 * time.Millisecond)
		return map[string]any{
			"checks": []map[string]string{
				{"level": "ok", "title": "Joined locnet as linuxbox (10.99.0.2)"},
				{"level": "ok", "title": "Tunnel up on locnet0", "detail": "UDP port 41820"},
				{"level": "ok", "title": "Hub answering at 192.168.1.64:8420"},
				{"level": "ok", "title": "Relay sees this machine at 192.168.1.97:41820"},
			},
			"peers": []map[string]any{
				{"name": "lab-gpu", "ip": "10.99.0.5", "path": "relay", "ok": true, "ms": 41.2},
				{"name": "hubpc", "ip": "10.99.0.1", "path": "direct", "ok": true, "ms": 6.8},
			},
			"inbound": map[string]any{"from": "hubpc", "ports": []map[string]any{
				{"port": 22, "name": "ssh", "open": true}, {"port": 3389, "name": "rdp", "open": true},
				{"port": 8421, "name": "locnet", "open": true}}},
		}, nil
	})
	api("GET /api/docs", func(r *http.Request) (any, error) { return docs.List(), nil })
	api("GET /api/docs/{name}", func(r *http.Request) (any, error) {
		text, ok := docs.Read(r.PathValue("name"))
		if !ok {
			return nil, fmt.Errorf("no such document")
		}
		return map[string]string{"name": r.PathValue("name"), "text": text}, nil
	})
	api("POST /api/manage/{op}", func(r *http.Request) (any, error) {
		if !*admin {
			return nil, fmt.Errorf("linuxbox is not allowed to administer this network")
		}
		b := body(r)
		m.mu.Lock()
		defer m.mu.Unlock()
		switch r.PathValue("op") {
		case "nodes":
			return m.nodes, nil
		case "invites":
			return m.invites, nil
		case "audit":
			return m.audit, nil
		case "webshare":
			if m.web == nil {
				m.web = &hub.WebShareView{Domain: "yourname.duckdns.org", AcceptedTOS: true, DuckDNS: true,
					DNS: hub.DNSStatus{At: time.Now(), IP: "203.0.113.27"},
					Sites: []hub.Site{
						{Name: "myapp", URL: "https://myapp.yourname.duckdns.org", Machine: "winpc-01", Target: "127.0.0.1:3000", Port: 8430, State: hub.SiteLive, Live: true, Requests: 182},
						{Name: "photos", URL: "https://photos.yourname.duckdns.org", Machine: "lab-gpu", Target: "127.0.0.1:2342", Port: 8430, State: hub.SiteWaiting},
						{Name: "wiki", URL: "https://wiki.yourname.duckdns.org", Machine: "linuxbox", Target: "127.0.0.1:8080", Port: 8431, State: hub.SiteOff},
					}}
			}
			action, _ := b["action"].(string)
			name, _ := b["name"].(string)
			for i := range m.web.Sites {
				x := &m.web.Sites[i]
				if x.Name != name {
					continue
				}
				switch action {
				case "approve", "on":
					x.State, x.Live = hub.SiteLive, true
				case "off":
					x.State, x.Live = hub.SiteOff, false
				case "remove":
					x.State, x.Live = hub.SiteWaiting, false
				}
			}
			if action != "" {
				m.audit = append([]map[string]any{{"at": time.Now(), "actor": "linuxbox", "action": "webshare." + action, "detail": name}}, m.audit...)
			}
			return m.web, nil
		case "access":
			// The real policy code, on a copy of the live network's policy,
			// so what the page shows is what the hub would do.
			if m.pol == nil {
				m.pol = &policy.Policy{
					Groups: map[string][]string{"home": {"linuxbox", "hubpc", "win-abc123def45"}},
					Rules: []policy.Rule{{Src: []string{"home"}, Dst: []string{"*"}},
						{Src: []string{"winpc-01"}, Dst: []string{"win-abc123def45"}}},
				}
			}
			var names []string
			for _, n := range m.nodes {
				names = append(names, fmt.Sprint(n["name"]))
			}
			action, _ := b["action"].(string)
			if action != "" {
				src, _ := b["src"].(string)
				dst, _ := b["dst"].(string)
				var svcs []string
				if l, ok := b["services"].([]any); ok {
					for _, v := range l {
						svcs = append(svcs, fmt.Sprint(v))
					}
				}
				ports, err := policy.ParseServices(svcs)
				if err != nil {
					return nil, err
				}
				if action == "block" {
					m.pol.Block(src, dst, ports, "set by linuxbox")
				} else if err := m.pol.Allow(src, dst, ports, "set by linuxbox", names); err != nil {
					return nil, err
				}
				m.audit = append([]map[string]any{{"at": time.Now(), "actor": "linuxbox", "action": "access." + action,
					"detail": fmt.Sprintf("%s → %s: %s", src, dst, policy.DescribePorts(ports))}}, m.audit...)
			}
			return m.pol.View(names), nil
		case "invite":
			m.invites = append([]map[string]any{{"id": "Zk3pQ9aB", "label": b["label"], "uses": b["uses"],
				"active": true, "created_at": time.Now()}}, m.invites...)
			return map[string]any{"code": "locnet1_jrhacahjfq5r5wgdb63ls2gxd6nx3exnzq4bh2qk7v6xw3m5t4yfp9a", "uses": b["uses"],
				"expires_at": time.Now().Add(24 * time.Hour)}, nil
		case "remove":
			var kept []map[string]any
			for _, n := range m.nodes {
				if n["name"] != b["node"] {
					kept = append(kept, n)
				}
			}
			m.nodes = kept
			peers := m.status["peers"].([]map[string]any)
			var keptPeers []map[string]any
			for _, p := range peers {
				if p["name"] != b["node"] {
					keptPeers = append(keptPeers, p)
				}
			}
			m.status["peers"] = keptPeers
			m.audit = append([]map[string]any{{"at": time.Now(), "actor": "linuxbox", "action": "node.remove", "detail": b["node"]}}, m.audit...)
			return b, nil
		}
		return b, nil
	})

	log.Printf("console with a made-up network: http://%s/?t=%s#machines", *addr, token)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

func parent(p string) string {
	if p == "/" {
		return ""
	}
	i := strings.LastIndex(strings.TrimRight(p, "/"), "/")
	if i <= 0 {
		return "/"
	}
	return p[:i]
}

func (m *mock) newJob(head string, peers any, transfer bool) string {
	m.mu.Lock()
	m.seq++
	id := fmt.Sprintf("job%d", m.seq)
	j := &job{pct: -1}
	j.lines = append(j.lines, map[string]string{"text": head, "kind": "head"})
	m.jobs[id] = j
	m.mu.Unlock()

	names, _ := peers.([]any)
	go func() {
		for step := 1; step <= 5; step++ {
			time.Sleep(300 * time.Millisecond)
			m.mu.Lock()
			for _, n := range names {
				if transfer {
					j.pct = step * 20
					j.lines = append(j.lines, map[string]string{"target": fmt.Sprint(n),
						"text": fmt.Sprintf("  %d,048,576  %d%%   21.4MB/s", step*12, step*20), "kind": "progress"})
				} else {
					j.lines = append(j.lines, map[string]string{"target": fmt.Sprint(n),
						"text": fmt.Sprintf(" 18:%02d:%02d up 26 days,  load average: 0.%d", 40+step, step*7, step)})
				}
			}
			m.mu.Unlock()
		}
		m.mu.Lock()
		for _, n := range names {
			j.lines = append(j.lines, map[string]string{"target": fmt.Sprint(n), "text": "done in 1.5s", "kind": "ok"})
		}
		j.done, j.sum, j.pct = true, fmt.Sprintf("all %d succeeded", len(names)), 100
		m.mu.Unlock()
	}()
	return id
}

func newMock(admin bool) *mock {
	ago := func(d time.Duration) time.Time { return time.Now().Add(-d) }
	gpu := []map[string]any{{"name": "NVIDIA GeForce RTX 3050 Laptop GPU", "vendor": "nvidia", "mem_total_mb": 4096, "mem_free_mb": 3746}}
	lan := func(mac, net string) []map[string]any {
		return []map[string]any{{"name": "wlan0", "mac": mac, "nets": []string{net}}}
	}
	m := &mock{accounts: map[string]string{"hubpc": "username"}, jobs: map[string]*job{}}
	m.status = map[string]any{
		"registered": true, "running": true, "name": "linuxbox", "os": "linux", "ip": "10.99.0.2",
		"network": "locnet", "hub_addr": "192.168.1.64:8420", "hub_ok": true, "interface": "locnet0",
		"listen_port": 41820, "observed": "192.168.1.97:41820", "relay": "192.168.1.64:8420",
		"agent_version": "0.10.0", "is_admin": admin, "lan": lan("aa:bb:cc:00:11:22", "192.168.1.0/24"),
		"stats": map[string]any{"cpus": 20, "load_percent": 15, "mem_total_mb": 31247, "mem_free_mb": 16433,
			"disk_total_gb": 399, "disk_free_gb": 9, "uptime_hours": 72, "gpus": gpu},
		"services": []map[string]any{{"name": "ssh", "port": 22, "verified": true}, {"name": "rdp", "port": 3389, "verified": true}},
		"shares": []any{map[string]any{"name": "papers", "kind": "files", "target": "/home/sono/papers", "read_only": true,
			"allow": []string{"hubpc"}, "description": "PDFs for the reading group"}},
		"compute": map[string]any{"enabled": true, "allow": []string{"hubpc"}, "run_as": "sono", "label": "test box"},
		"desktop": map[string]any{"enabled": true, "allow": []string{"macbook"}},
		"alerts": []map[string]any{
			{"node": "linuxbox", "level": "critical", "kind": "disk", "message": "linuxbox has 9 GB left (2% of 399 GB)"},
			{"node": "macbook", "level": "critical", "kind": "offline", "message": "macbook has been out of contact for 814h47m0s"},
		},
		"peers": []map[string]any{
			{"name": "hubpc", "ip": "10.99.0.1", "os": "linux", "path": "direct", "addr": "192.168.1.64:41820",
				"latency": "6ms", "online": true, "hub": true, "last_seen": time.Now(),
				"stats": map[string]any{"cpus": 8, "load_percent": 2, "mem_total_mb": 15800, "mem_free_mb": 9200, "disk_total_gb": 1367, "disk_free_gb": 431, "uptime_hours": 633},
				"services": []map[string]any{{"name": "ssh", "port": 22, "verified": true}, {"name": "rdp", "port": 3389, "verified": true,
					"problem": "the RDP server hangs up on every client before anyone can log in. GNOME Remote Desktop does this when RDP is switched on but no RDP username and password have been set. Fix it on that machine, as the person who logs in there: locnet setup rdp"},
					{"name": "vnc", "port": 5900, "verified": true}},
				"shares":  []map[string]any{{"name": "screen", "kind": "port", "port": 5900, "description": "this machine's VNC desktop"}, {"name": "datasets", "kind": "files", "read_only": true, "description": "lab data"}},
				"compute": map[string]any{"max_seconds": 3600, "label": "always on"},
				"lan":     lan("11:22:33:44:55:66", "192.168.1.0/24")},
			{"name": "lab-gpu", "ip": "10.99.0.5", "os": "linux", "path": "relay", "addr": "192.168.1.64:8420",
				"latency": "", "online": true, "last_seen": time.Now(),
				"stats":    map[string]any{"cpus": 32, "load_percent": 91, "mem_total_mb": 128000, "mem_free_mb": 22000, "disk_total_gb": 3700, "disk_free_gb": 2100, "gpus": []map[string]any{{"name": "NVIDIA RTX 4090", "mem_total_mb": 24564, "mem_free_mb": 20100}}},
				"services": []map[string]any{{"name": "ssh", "port": 22, "verified": true}, {"name": "http-alt", "port": 8080, "verified": false}},
				"compute":  map[string]any{"max_seconds": 86400, "label": "the big GPU"}},
			{"name": "macbook", "ip": "10.99.0.3", "os": "darwin", "path": "idle", "online": false, "last_seen": ago(814 * time.Hour),
				"stats": map[string]any{"cpus": 11, "disk_total_gb": 926, "disk_free_gb": 70}, "lan": lan("de:ad:be:ef:00:01", "192.168.1.0/24")},
			{"name": "win-abc123def45", "ip": "10.99.0.4", "os": "windows", "path": "idle", "online": false, "last_seen": ago(588 * time.Hour),
				"stats": map[string]any{"cpus": 6, "disk_total_gb": 62, "disk_free_gb": 34}},
		},
	}
	m.queue = []map[string]any{
		{"id": "j7a21f0c93", "state": "running", "node": "lab-gpu", "submitter": "linuxbox", "command": []string{"python3", "train.py", "--epochs", "40"}, "queued_at": ago(20 * time.Minute)},
		{"id": "j0c93a1f77", "state": "queued", "submitter": "linuxbox", "command": []string{"make", "-j8"}, "need": map[string]any{"cpus": 8}, "queued_at": ago(3 * time.Minute)},
		{"id": "j1b8e44d02", "state": "done", "node": "hubpc", "submitter": "linuxbox", "command": []string{"./build.sh"}, "seconds": 41.2, "output_bytes": 4096, "queued_at": ago(2 * time.Hour)},
		{"id": "j55aa01c2e", "state": "failed", "exit_code": 2, "node": "hubpc", "submitter": "hubpc", "command": []string{"pytest", "-x"}, "queued_at": ago(5 * time.Hour)},
	}
	m.nodes = []map[string]any{
		{"name": "linuxbox", "ip": "10.99.0.2", "os": "linux", "online": true, "approved": true, "admin": true, "last_seen": time.Now(), "created_at": ago(70 * 24 * time.Hour)},
		{"name": "lab-gpu", "ip": "10.99.0.5", "os": "linux", "online": true, "approved": true, "last_seen": time.Now(), "created_at": ago(9 * 24 * time.Hour)},
		{"name": "winpc-01", "ip": "10.99.0.3", "os": "windows", "online": true, "approved": true, "last_seen": time.Now(), "created_at": ago(24 * time.Hour)},
		{"name": "new-laptop", "ip": "10.99.0.6", "os": "windows", "online": true, "approved": false, "last_seen": time.Now(), "created_at": ago(time.Hour)},
		{"name": "win-abc123def45", "ip": "10.99.0.4", "os": "windows", "online": false, "approved": true, "last_seen": ago(588 * time.Hour), "created_at": ago(66 * 24 * time.Hour)},
		{"name": "hubpc", "ip": "10.99.0.1", "os": "linux", "online": true, "approved": true, "hub": true, "admin": true, "last_seen": time.Now(), "created_at": ago(73 * 24 * time.Hour)},
	}
	m.invites = []map[string]any{
		{"id": "yfTqLwUp", "label": "win11-vm", "uses": 0, "active": false, "created_at": ago(66 * 24 * time.Hour)},
		{"id": "NQsL4B7h", "label": "Mac", "uses": 0, "active": false, "created_at": ago(73 * 24 * time.Hour)},
	}
	m.audit = []map[string]any{
		{"at": ago(66 * 24 * time.Hour), "actor": "win-abc123def45", "action": "node.join", "detail": "win-abc123def45 (windows) as 10.99.0.4"},
		{"at": ago(72 * 24 * time.Hour), "actor": "macbook", "action": "node.join", "detail": "macbook (darwin) as 10.99.0.3"},
	}
	return m
}
