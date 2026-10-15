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
PEER     ADDRESS    OS       PATH    CPU        FREE DISK  SERVICES      SHARES
unit-01  10.99.0.2  windows  direct  34% of 8   210G/931G  rdp,vnc,http  archive
unit-02  10.99.0.3  windows  relay   91% of 4   18G/465G   rdp,ssh       data,pg
unit-03  10.99.0.4  windows  direct  12% of 4   301G/465G  vnc           -

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
this node:   workstation  10.99.0.1
tunnel:      up  on locnet0  udp/41820
seen as:     203.0.113.44:41820
relay:       198.51.100.9:8420

PEER     ADDRESS    OS       PATH    VIA                  LATENCY
unit-01  10.99.0.2  windows  direct  203.0.113.91:41820   18ms
unit-02  10.99.0.3  windows  direct  198.51.100.77:41820  24ms
unit-03  10.99.0.4  windows  direct  198.51.100.78:41820  31ms
unit-04  10.99.0.5  windows  relay   198.51.100.9:8420    —

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

## Getting started

This takes a new network from nothing to machines that reach each other by
name, on Linux, macOS and Windows. [docs/INSTALL.md](docs/INSTALL.md) has the
same steps in more depth.

### What you need

| | |
|---|---|
| **One always-on machine for the hub** | Linux with systemd, the recommended choice: the installer sets the hub up as a service there. It needs a fixed LAN address and, if any machine will ever connect from outside your home network, a port forward on your router (step 2). The hub uses little CPU or memory. |
| **The other machines** | Linux (x86-64, ARM64, ARMv7), macOS (Intel or Apple silicon), Windows 10 or 11 (64-bit). No kernel WireGuard module: LocNet carries its own. |
| **Administrator rights** | `sudo` on Linux and macOS, an elevated PowerShell on Windows. The agent creates a network interface. |
| **To build** | [Go](https://go.dev/dl/) 1.26 or newer and `bash`, on any one machine (Linux, macOS, or WSL on Windows). No C compiler. |

The overlay network is `10.99.0.0/16` unless you choose otherwise. Every
machine keeps the address it is given (`10.99.0.1`, `10.99.0.2`, …) for good.

### 1. Build

```bash
git clone https://github.com/mahantsunandan/locnet
cd locnet
./scripts/build.sh
```

`dist/` now holds one directory per platform, each also as a `.tar.gz`:

| Platform | Directory |
|---|---|
| Linux, most PCs | `locnet_<version>_linux_amd64` |
| Linux, Raspberry Pi 4/5 and other 64-bit ARM | `locnet_<version>_linux_arm64` |
| Linux, 32-bit ARM | `locnet_<version>_linux_arm` |
| macOS, Apple silicon | `locnet_<version>_darwin_arm64` |
| macOS, Intel | `locnet_<version>_darwin_amd64` |
| Windows, most PCs | `locnet_<version>_windows_amd64` |
| Windows on ARM | `locnet_<version>_windows_arm64` |

Copy the right one to each machine (`scp`, a USB stick, a shared folder).
Each holds the three programs, the installer and these documents.

### 2. Set up the hub (Linux)

On the always-on machine, inside its directory:

```bash
sudo ./install.sh --hub
sudo nano /etc/locnet/hub.env
```

Set `LOCNET_ADVERTISE` to the addresses your other machines will use to reach
this one, most specific first. A hub behind a home router usually lists its LAN
address and the house's public address, so the same join code works at home
and away:

```ini
LOCNET_ADVERTISE=192.168.1.10:8420,203.0.113.7:8420
LOCNET_LISTEN=:8420
LOCNET_NETWORK=homelab           # first run only
LOCNET_PREFIX=10.99.0.0/16       # first run only; change it if your LAN already uses 10.99.x.x
```

Open port 8420 for TCP and UDP, both, in the hub machine's own firewall:

```bash
sudo ufw allow 8420/tcp && sudo ufw allow 8420/udp                                         # Ubuntu, Debian
sudo firewall-cmd --permanent --add-port=8420/tcp --add-port=8420/udp && sudo firewall-cmd --reload   # Fedora, RHEL
```

#### Port forwarding: reaching the hub from outside your network

If every machine stays on the same home or office network, skip this. If any
machine will connect from anywhere else, such as a laptop on the road, a
machine at work or a phone hotspot, it has to reach the hub through your
router, and the router must forward the port. **Only the hub needs a port
forward.** The other machines need none: they make outgoing connections, and
LocNet punches through NAT between them by itself.

1. **Give the hub a fixed LAN address.** In the router's DHCP settings, reserve
   an address for the hub's network card (often called "DHCP reservation" or
   "static lease"). A forward that points at an address the hub no longer has
   breaks silently.
2. **Forward port 8420, TCP *and* UDP, to that address.** It is usually under
   "Port forwarding", "Virtual servers" or "NAT" in the router's admin page.
   Use the same port outside and inside:

   | Protocol | External port | Internal address | Internal port | Used for |
   |---|---|---|---|---|
   | TCP | 8420 | the hub's LAN address | 8420 | joining, the network map, administration (encrypted) |
   | UDP | 8420 | the hub's LAN address | 8420 | the relay, and telling each machine its public address |

   Forgetting UDP is the classic mistake. Machines then join, but every
   connection between networks stays on `connecting` or `relay`.

   Only if you publish web apps with WebShare, also forward TCP 80 and 443 to
   the hub ([OPERATIONS.md](docs/OPERATIONS.md#publishing-a-site-to-the-internet-webshare)).
3. **Find the public address** (what `curl -4 ifconfig.me` prints on the hub)
   and put it in `LOCNET_ADVERTISE` after the LAN address, as above. If your
   provider changes it from time to time, use a free dynamic-DNS name instead
   (DuckDNS, No-IP, or one built into the router), e.g.
   `LOCNET_ADVERTISE=192.168.1.10:8420,myhome.duckdns.org:8420`. The hub's
   WebShare feature can keep a DuckDNS name up to date for you.
4. **Test from outside**, for example from a phone hotspot:
   `curl -k https://203.0.113.7:8420/healthz` should print `ok`. Testing from
   inside the house is misleading: most home routers cannot reach their own
   public address from inside (no "NAT hairpinning"). That is why the code
   carries the LAN address too, and why the hub's log saying it `could not
   reach itself` at the public address is normal.

**If there is no public address to forward.** Some providers, especially mobile
and some fibre or satellite ones, put the house behind carrier-grade NAT. A
forward then has no effect: the router's WAN address starts with `100.64`–
`100.127`, or differs from what `ifconfig.me` reports. Ask the provider for a
public IPv4 address, or run the hub on a machine that has one, such as a small
cloud server. The hub needs little, holds no tunnel keys, and cannot read
traffic between machines.

Start it, and read the first join code from its log:

```bash
sudo systemctl enable --now locnet-hub
sudo journalctl -u locnet-hub -n 30
```

```
hub: network "homelab" on 10.99.0.0/16, advertising 192.168.1.10:8420, 203.0.113.7:8420
hub: fingerprint e92c3b1ed8c30fb6b968d71f9b7d92ed
hub: reachable at 192.168.1.10:8420
 No machines have joined yet, so here is a join code.
 Good for 10 machines, expires in 24 hours.

   locnet1_qkzgeaaaaaaqbcdefghijklmnopqrstuvwxyz234567…
```

The hub machine is a member too. Join it with that code:

```bash
sudo locnet join locnet1_…
```

Mint more codes whenever you need them:

```bash
sudo locnet-hub invite -label "office laptop" -uses 1 -ttl 24h
```

A join code carries the hub's addresses, a fingerprint of the hub's key, and a
one-time token. A machine refuses any hub whose key does not match the
fingerprint, and talks to it only over TLS pinned to that key, so the code is
safe to paste into a chat. Treat it like a password anyway: until it is used up
or revoked (`sudo locnet-hub revoke <start of code>`), it lets a machine in.

> The hub runs on macOS and Windows too (`./install.sh --hub`,
> `install.ps1 -Hub`), but there the installer only puts `locnet-hub` in place,
> with no service. You start `locnet-hub serve -advertise <addresses>` yourself
> and keep it running.

### 3. Join every other machine

**Linux** (Ubuntu, Debian, Mint, Fedora, RHEL and others):

```bash
tar xzf locnet_<version>_linux_amd64.tar.gz
cd locnet_<version>_linux_amd64
sudo ./install.sh --join locnet1_…
```

**macOS:**

```bash
tar xzf locnet_<version>_darwin_arm64.tar.gz      # _darwin_amd64 on Intel
cd locnet_<version>_darwin_arm64
sudo ./install.sh --join locnet1_…
```

The agent runs as a launchd daemon. If macOS asks whether `locnetd` may accept
incoming connections, allow it.

**Windows 10 / 11:** open PowerShell **as Administrator**, then:

```powershell
tar -xzf locnet_<version>_windows_amd64.tar.gz
cd locnet_<version>_windows_amd64
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Join locnet1_…
```

`-ExecutionPolicy Bypass` applies to this one run only; Windows otherwise
refuses unsigned scripts. The installer downloads the WireGuard tunnel driver
(`wintun.dll`) from wintun.net and checks it against a pinned SHA-256. It then
installs `locnetd` as a Windows service that starts at boot, and marks the
tunnel as a Private network with one firewall rule for the mesh. See
[docs/INSTALL.md](docs/INSTALL.md#windows) to install with no download.

On every platform the installer joins as its last step, so the machine is on
the network when it finishes. On Linux and macOS it also adds you to the
`locnet` group. Log out and back in once, and `locnet` commands work without
`sudo`.

### 4. Check it works

```bash
locnet status        # this machine, the hub, and every peer with its path
locnet peers         # peers with their services, shares and load
ping 10.99.0.1       # the hub, through the tunnel
locnet doctor        # tests each piece — hub, encryption, relay, every peer — and says what to fix
```

A new peer shows `connecting` for a few seconds while the machines find a path,
then `direct` (peer to peer) or `relay` (through the hub, when the networks in
between allow nothing else). `locnet doctor` should say `control plane
encrypted, pinned to the hub's key`.

To reach peers by name (`ssh office-laptop`, `ping homeserver`):

```bash
sudo locnet hosts on
```

### 5. Use it

**Remote access.** `locnet setup` checks what this machine needs in order to be
reached: an SSH server and a screen-sharing server (VNC, or RDP on Windows).
With `-install`, it installs only what is missing and shows each command before
running it:

```bash
locnet setup                 # what is missing
sudo locnet setup -install   # install it (an elevated prompt on Windows, without sudo)
```

Then, from any other machine, these open the client you already have, already
pointed at the right address:

```bash
locnet ssh office-laptop     # a shell, in your terminal
locnet vnc office-laptop     # its screen, in your VNC viewer
locnet rdp office-laptop     # Windows Remote Desktop
locnet console               # everything in a browser: machines, files, jobs, admin
```

**Share a folder or a local service** with named machines (nothing is shared
until you say who with):

```bash
locnet share add papers ~/papers -allow office-laptop   # read-only folder
locnet share add db :5432 -allow office-laptop          # a service bound to 127.0.0.1
locnet files homeserver papers                          # browse a peer's share
```

**Run work on other machines**, once they allow it. Only someone at the
machine can turn this on:

```bash
sudo locnet compute enable -allow office-laptop -user builder   # on the machine lending its cores
locnet run homeserver -- make -j8                               # from office-laptop
locnet queue submit -n 100 -cpus 4 -- ./render.sh               # spread jobs over every free machine
```

More in [SHARING.md](docs/SHARING.md), [DESKTOP.md](docs/DESKTOP.md),
[COMPUTE.md](docs/COMPUTE.md) and [QUEUE.md](docs/QUEUE.md). Every command is
in [COMMANDS.md](docs/COMMANDS.md).

### 6. Lock it down

By default every machine may reach every machine, and any valid code admits a
machine. Before the network grows:

```bash
sudo locnet-hub health set -require-approval=true   # new machines wait until you admit them
sudo locnet-hub approve <machine>
sudo locnet-hub policy example > policy.json         # groups and who may reach whom
sudo locnet-hub policy set policy.json
sudo locnet-hub admins add office-laptop             # administer from that machine, not over SSH to the hub
```

[OPERATIONS.md](docs/OPERATIONS.md) covers policies, the access table, alerts,
the audit log, a standby hub, waking machines, and publishing a web app to the
internet. [SECURITY.md](docs/SECURITY.md) covers what is and is not protected.

### Upgrading

Build the new version and run the same installer again. Use `--hub` on the
hub, and the elevated `install.ps1` on Windows. Each machine keeps its keys,
address and membership. Upgrade the hub first, then the other machines.

### Uninstalling

```bash
sudo ./install.sh --uninstall                                   # Linux, macOS
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Uninstall   # Windows, elevated
sudo locnet-hub remove <machine>                                # on the hub, to drop it from the network
```

The machine's state stays behind, so reinstalling rejoins with the same
address. [INSTALL.md](docs/INSTALL.md#uninstalling) shows how to remove that
too.

### When something does not work

Run `locnet doctor` on the machine first; it names what is wrong and, usually,
the command that fixes it. The usual causes:

- **Joining times out.** The machine cannot reach any address in the code.
  Check the hub's log for `reachable at …`, the firewall (TCP and UDP 8420),
  and from outside the house, the router's port forward. Many home routers
  cannot reach their own public address from inside the house, so test the
  public address from another network.
- **Peers stay on `relay`.** UDP between the two networks is blocked or
  heavily NATed. Relayed traffic works, just more slowly. Opening UDP 41820 on
  either machine usually gives a direct path.
- **`timestamp is … away from hub time`.** The machine's clock is wrong; turn
  on network time.

[INSTALL.md](docs/INSTALL.md#troubleshooting) lists the rest.

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
              │  10.99   │    │  10.99   │    │  10.99   │
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
  certificate authority, nothing to renew, and no plain-HTTP fallback
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
  client in a web page
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
