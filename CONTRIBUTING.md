# LocNet — notes for working on this code

LocNet is a self-hosted WireGuard mesh (a Tailscale-like overlay) in Go, with
remote access, file and port sharing, compute and a job queue, per-pair access
control, and WebShare (publishing a web app through the hub). Three programs:
`locnet-hub` (one always-on machine), `locnetd` (agent, every machine, root /
SYSTEM), `locnet` (CLI and the `locnet console` web UI). Linux, macOS, Windows.

Start with [docs/GUIDE.md](docs/GUIDE.md) for what it does and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how; the package map is at the
end of ARCHITECTURE.md.

## The rule: documentation moves with the code

Every change to the code updates, **in the same change**:

1. **The document that explains the feature** — see the table below. Behaviour
   a user can see that no document describes is a bug.
2. **[docs/COMMANDS.md](docs/COMMANDS.md)** for any command, subcommand or flag
   added, changed or removed. `go test ./cmd/...` fails if a command in either
   program's help is missing from it.
3. **[docs/CHANGELOG.md](docs/CHANGELOG.md)** — an entry under the version in
   `VERSION` (New / Fixed). Bump `VERSION` when a release goes out.
4. **This file**, when the build, test or deploy procedure, the layout, the
   live network, or a hard-won lesson changes.
5. **README.md**'s *What works* / *What does not, yet* when a capability
   appears or a limitation goes away.

Then `go test ./docs` checks every link between documents (GitHub's anchor
rules). The console's **Docs** page serves `docs/*.md` compiled into the
binary (package `github.com/mahantsunandan/locnet/docs`), so a rebuild is all it takes;
a new document is listed automatically (add it to `docs.Order` to place it).

| Feature | Document |
|---|---|
| install, upgrade, platform setup, troubleshooting | INSTALL.md |
| console, connecting, shares, compute channel, exec/copy/fetch | SHARING.md |
| screens: VNC, RDP, the desktop helper | DESKTOP.md |
| `best`, `job`, Julia, VS Code | COMPUTE.md |
| the queue | QUEUE.md |
| policy, access table, WebShare, approval, admins, alerts, audit, standby hub, wake | OPERATIONS.md |
| threat model, anything that changes what is exposed | SECURITY.md |
| wire formats, endpoints, netmap fields | PROTOCOL.md |
| components, design decisions, package map | ARCHITECTURE.md |

## Build and check

Go 1.26.5 is at `/usr/local/bin/go`. Everything below must pass before a
change is done:

```bash
gofmt -l cmd internal docs                     # prints nothing
go vet ./... && GOOS=windows go vet ./... && GOOS=darwin go vet ./...
go test -race -count=1 ./...                   # 20 packages
./scripts/build.sh                             # every platform into dist/ (rm -rf's dist first)
```

- **Console JS**: extract the last `<script>` of `internal/console/console.html`
  and `node --check` it.
- **Console UI**: `go run ./internal/console/devserve` serves the page against a
  mock network at `http://127.0.0.1:8799/?t=devtoken#<page>` (pages:
  machines, files, run, queue, this, network, docs; `#machine:<name>`,
  `#docs:<NAME>:<anchor>`). Screenshot with
  `google-chrome --headless=new --window-size=1400,1100 --virtual-time-budget=5000 --screenshot=out.png <url>`,
  and at 390px wide. The in-app browser pane can return stale frames and cannot
  click inside `<dialog>`; read state with JS instead. Stop devserve with
  `pgrep -x devserve | xargs -r kill` — `pkill -f` matches its own shell.
- **Windows-only code** is compiled by `GOOS=windows go vet`, but run its tests
  on real Windows: `GOOS=windows go test -c -o node_test.exe ./internal/node`,
  `scp` to winpc-01, run with quoted flags (`"-test.run=X"` — PowerShell 5.1
  splits bare `-test.run`).

## Conventions

- Comments explain **why**, usually with the failure that taught it. Keep that
  density; a fix without its story gets made again.
- Platform code lives in `_windows.go` / `_unix.go` / `_linux.go` / `_darwin.go`
  pairs with identical signatures.
- Messages to users end with the exact command that fixes the problem.
- Nothing changes on a machine without showing the commands first (`setup`), and
  nothing that grants access is switched on remotely (compute, shares, WebShare
  requests are created only on the machine itself).
- Secrets never appear in logs, errors, the API or this repository (see the
  DuckDNS token handling in `internal/hub/webshare_server.go`).
- No new dependencies without a reason; the module uses only x/crypto, x/sys,
  x/net, x/text and wireguard-go.

## Lessons that cost time

- Verify the running thing, not its configuration: `/proc/<pid>/cmdline`,
  listening sockets, a real connection from a peer. Reports of success have
  been wrong many times.
- X lock files belong to any X server; never delete one without checking the pid
  inside it.
- Windows: the tunnel adapter needs its fixed GUID, Private category and the
  `LocNet-locnetd` firewall rule; addresses are Tentative for ~3s (DAD); a
  service has no stderr (log file); adapter creation fails early in boot (retry);
  a process started as another user needs its own window station (empty
  lpDesktop) and, for a filtered admin token, an owner and default DACL of the
  user.
- The packet filter is stateful by design; one-way policies depend on it.
- Every WebShare certificate is public in Certificate Transparency logs;
  scanners arrive within minutes.
