# LocNet

A private mesh network for machines you own. One always-on computer runs the
coordination server; every other machine joins it with a pasteable code and
gets a stable address it keeps forever. Traffic goes peer to peer whenever the
network allows it, and falls back to a relay when it does not.

It is WireGuard for the encryption, and Go for everything WireGuard
deliberately leaves out: who the members are, what address each one has, how
they find each other across NAT, and how a new machine joins without anyone
hand-editing a config file. The mesh itself is about two thousand lines; the
rest is what you can do once machines can reach each other — remote desktop,
file shares, a job queue. Beyond the standard library it uses only
wireguard-go and the `golang.org/x` crypto, sys, net and text packages.

```
$ locnet peers
PEER     ADDRESS      OS       PATH    CPU        FREE DISK  SERVICES      SHARES
unit-01  100.100.0.2  windows  direct  34% of 8   210G/931G  rdp,vnc,http  archive
unit-02  100.100.0.3  windows  relay   91% of 4   18G/465G   rdp,ssh       data,pg
unit-03  100.100.0.4  windows  direct  12% of 4   301G/465G  vnc           -

$ locnet ssh unit-01      # a shell, in your own terminal
$ locnet vnc unit-01      # its screen, in your own viewer
$ locnet console          # or drive the whole thing from a browser —
                          # machines, files, jobs
```

```
$ locnet queue submit -n 240 -cpus 4 -- /srv/render.sh
Queued 240 jobs: j7a21f0c93 j1b8e44d02 …

$ locnet queue
JOB          STATE    WHERE    AGE  FROM         COMMAND
j7a21f0c93   running  unit-01  22s  workstation  /srv/render.sh
j1b8e44d02   running  unit-03  22s  workstation  /srv/render.sh
j0c93a1f77   queued   waiting  22s  workstation  /srv/render.sh
```

```
$ locnet-hub alerts
!!  critical  disk      unit-02 has 12 GB left (3% of 465 GB)
!!  critical  offline   unit-04 has been out of contact for 4h12m
!   warn      load      unit-02 is at 94% CPU across 4 cores
```

```
$ locnet status
network:     homelab (hub.example.org:8420)
this node:   workstation  100.100.0.1
tunnel:      up  on locnet0  udp/41820
seen as:     203.0.113.44:41820
relay:       198.51.100.9:8420

PEER     ADDRESS      OS       PATH    VIA                  LATENCY
unit-01  100.100.0.2  windows  direct  203.0.113.91:41820   18ms
unit-02  100.100.0.3  windows  direct  198.51.100.77:41820  24ms
unit-03  100.100.0.4  windows  direct  198.51.100.78:41820  31ms
unit-04  100.100.0.5  windows  relay   198.51.100.9:8420    —

  direct = peer-to-peer     relay = through the hub     connecting = still probing
```

## Why this exists

Everything here already exists in more mature form — [Headscale][], [NetBird][],
[Nebula][], [Netmaker][]. If you want a private mesh in production today, use
one of those. LocNet is small enough to read in an afternoon, which is the
point: the interesting parts of a mesh VPN are usually buried under a hundred
thousand lines of enterprise features, and here they are not.

[Headscale]: https://github.com/juanfont/headscale
[NetBird]: https://netbird.io
[Nebula]: https://github.com/slackhq/nebula
[Netmaker]: https://www.netmaker.io

## Quick start

Build the release for every platform (Go 1.26 or newer, nothing else):

```bash
git clone https://github.com/mahantsunandan/locnet
cd locnet
./scripts/build.sh                       # into dist/locnet_<version>_<os>_<arch>/
```

Copy the directory for each machine's platform to it, and from inside it, on
the always-on machine:

```bash
sudo ./install.sh --hub
sudo systemctl enable --now locnet-hub
sudo journalctl -u locnet-hub -n 30      # the first-run join code is printed here
```

On every other machine — one command, and it is on the network:

```bash
sudo ./install.sh --join locnet1_jrhacahjfq5r5wgdb63ls2gxd6nx3exn...
```

Windows is the same shape:

```powershell
.\install.ps1 -Join locnet1_jrhacahjfq5r5wgdb63ls2gxd6nx3exn...
```

Full instructions, including Windows and macOS, are in
[docs/INSTALL.md](docs/INSTALL.md).

## How it works

```
                        ┌──────────────────────────┐
                        │   locnet-hub             │
   who is on the        │                          │
   network, and         │  • members and addresses │
   where are they  ────▶│  • signs the network map │
                        │  • relays when it must   │
                        └───────────┬──────────────┘
                                    │  signed netmap, long poll over pinned TLS
                    ┌───────────────┼───────────────┐
                    │               │               │
              ┌─────▼────┐    ┌─────▼────┐    ┌─────▼────┐
              │ locnetd  │    │ locnetd  │    │ locnetd  │
              │ 100.100  │    │ 100.100  │    │ 100.100  │
              │   .0.1   │    │   .0.2   │    │   .0.3   │
              └─────┬────┘    └─────┬────┘    └─────┬────┘
                    └────────────────┴───────────────┘
                       WireGuard, peer to peer,
                       keys the hub never sees
```

Three programs:

| | |
|---|---|
| `locnet-hub` | The coordination server. Members, addresses, join codes, and a UDP relay. Runs on the always-on machine. |
| `locnetd` | The node agent. Holds this machine's keys, keeps the network map current, drives the tunnel. Runs as a system service on every machine. |
| `locnet` | The CLI and web console. Talks to `locnetd` over a local socket; does no networking of its own. |

The parts worth reading are
[`internal/magicsock`](internal/magicsock/magicsock.go), which is the NAT
traversal, and [`internal/disco`](internal/disco/disco.go), which is the
protocol it speaks.

| | |
|---|---|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | the design decisions and why |
| [PROTOCOL.md](docs/PROTOCOL.md) | the wire format |
| [SECURITY.md](docs/SECURITY.md) | the threat model |
| [INSTALL.md](docs/INSTALL.md) | Linux, macOS, Windows |
| [SHARING.md](docs/SHARING.md) | folder shares, port publishing, connecting |
| [DESKTOP.md](docs/DESKTOP.md) | reaching a machine's screen: RDP, VNC, and fixing them |
| [COMPUTE.md](docs/COMPUTE.md) | borrowing one machine's cores or GPU |
| [QUEUE.md](docs/QUEUE.md) | the job queue across the whole fleet |
| [OPERATIONS.md](docs/OPERATIONS.md) | policy, alerts, a standby hub, waking machines |

## What works

**Networking**

- Peer-to-peer WireGuard tunnels with automatic NAT hole punching
- Relay fallback, entered instantly and left as soon as a direct path forms
- Signed network maps, with the hub's identity pinned by the join code
- An encrypted control plane: TLS pinned to that same identity, with no
  certificate authority and nothing to renew
- Join codes with use limits and expiry, revocable from the hub
- Stable addresses that survive reinstalling the agent
- Linux, macOS and Windows, from one static binary per platform
- Optional peer names in `/etc/hosts`, so `ssh unit-02` works

**Remote access and sharing** — see [docs/SHARING.md](docs/SHARING.md) and
[docs/DESKTOP.md](docs/DESKTOP.md)

- **Hand-off to the clients you already have.** `locnet ssh <peer>` opens your
  default terminal with a shell on that machine; `locnet vnc` and `locnet rdp`
  open your own viewer. LocNet's job is to make the machine reachable and to
  know its address — not to reimplement a terminal emulator or a remote-desktop
  client in a web page, which is what it used to do and what it no longer does
- A web console for the whole network: every machine with its load, memory
  and disk, one-click connect, a two-pane file manager, commands across many
  machines, the job queue, this machine's shares and compute, a connection
  check that sends real traffic both ways, and — on an administrator's machine
  — inviting, admitting and removing machines. Light and dark, phone-sized too
- `locnet rdp|vnc|ssh <peer>` — launches your existing client, by peer name
- `locnet setup` installs two things and only two, and only if they are
  missing: an SSH server and a screen-sharing server — including a *working*
  VNC server on Linux, not merely the package for one. No clients are installed
  on your behalf
- Automatic discovery of what each machine is running (RDP, VNC, SSH, HTTP, SMB)
- Folder shares with per-peer access lists, read-only by default, deny by default
- Port publishing: reach a service bound to `127.0.0.1` on one machine from
  another, without rebinding it to the world
- **WebShare**: publish one web app on one machine to the internet at
  `https://<site>.<your domain>` — the hub gets the certificate, keeps a free
  dynamic DNS name pointing home, and passes visitors through the tunnel to
  that one port. Nothing is public until an administrator approves it
- Windows as a full member: OpenSSH, RDP and a password-free VNC (TightVNC)
  set up by `locnet setup`, the firewall opened for the mesh only, and the
  tunnel back by itself after a reboot

**Distributing work** — see [docs/QUEUE.md](docs/QUEUE.md) and
[docs/COMPUTE.md](docs/COMPUTE.md)

- **A job queue on the hub**: submit work, and whichever machines are free take
  it. Requirements (cores, free memory, a GPU with enough VRAM) exclude
  machines that cannot run the job rather than ranking them low
- Workers pull rather than being pushed, so a laptop that is asleep, busy or
  switched off mid-job needs no special handling — its lease lapses and the
  work goes elsewhere
- A machine runs queued work only if its own compute access list already names
  the submitter. The hub schedules; it cannot conscript
- Jobs run as a named, unprivileged account — on Windows too, without LocNet
  ever holding that account's password
- `locnet job` still sends one folder to one machine and brings the results back
  — to Linux, macOS or Windows

**Running a fleet** — see [docs/OPERATIONS.md](docs/OPERATIONS.md)

- **A standby hub**: a warm spare mirrors the register and takes over on
  `locnet-hub promote`. Nodes learn the spare's address from the signed network
  map, so machines that joined long before it existed fail over without being
  touched
- **Wake-on-LAN through the mesh**: `locnet wake unit-02` finds a peer on that
  machine's subnet and has it send the packet

- **Access policy**: named groups and rules. Machines the policy does not
  connect never appear in each other's network map — the isolation is enforced
  by WireGuard, not by a firewall rule someone could forget
- **Port-level rules** enforced by a packet filter in the agent, which
  remembers its own machine's connections — so access can be one-way: A may
  reach B while B reaches nothing on A
- **Switch single connections on and off**: `locnet admin access block laptop
  server ssh`, or click a cell in the console's who-may-connect-to-whom table.
  Blocks always win over rules, and every change is in the audit log
- **Alerts** on low disk, high load, and machines that have gone quiet, with a
  `-quiet` mode that exits non-zero for cron
- **Device approval**: a new machine holds an address but reaches nothing until
  an administrator admits it
- **Administer from your own machine**: `locnet invite`, `locnet admin remove`,
  or the console's Network page, signed with that machine's key — no SSH to
  the hub needed once it has said `locnet-hub admins add <machine>`
- **Audit log** of joins, removals, approvals and policy changes

## What does not, yet

- **IPv6 inside the tunnel.** The overlay is IPv4-only. IPv6 is used for
  transport where available.
- **A real DNS resolver.** The hosts-file block is a stand-in for MagicDNS.
- **Policy on outbound traffic.** The packet filter guards what reaches a
  machine; a machine is not restrained in what it sends.
- **WebShare beyond HTTPS.** Only web apps are published to the internet — no
  raw TCP ports — and only under one domain.
- **Subnet routers and exit nodes.** The netmap carries the routes; nothing
  programs them yet.
- **Mobile clients.** The browser console works on a phone; the agent does not
  run on one.
- **Automatic hub failover.** A standby mirrors the primary and takes over on
  one command, but a human has to give that command. Two hubs signing maps for
  one network with diverging registers is worse than no hub at all, and there
  is no consensus protocol here to prevent it.
- **The physical screen of a Wayland desktop over VNC.** `locnet setup`
  installs and starts a VNC server, but on a GNOME Wayland machine that server
  hosts a *virtual* desktop — a second session, not the one someone is sitting
  in front of. GNOME's own real-screen sharing needs a password in an unlocked
  keyring, so `locnet rdp` is the answer there.

See [docs/SECURITY.md](docs/SECURITY.md) for the threat model, including what a
compromised hub can and cannot do. Every command is in
[docs/COMMANDS.md](docs/COMMANDS.md); [docs/GUIDE.md](docs/GUIDE.md) is the
tour of everything, and [docs/CHANGELOG.md](docs/CHANGELOG.md) what changed.
The same documents are in the console, under **Docs**.

## Building

Go 1.26 or newer. No C compiler, no C libraries.

```bash
go build ./...          # local
./scripts/build.sh      # every platform, into dist/
go test ./...
```

The version is in [VERSION](VERSION), and releases are tagged with it
(`v0.10.4`). How to work on the code — the checks every change must pass, and
the rule that documentation changes with it — is in
[CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

MIT. See [LICENSE](LICENSE).
