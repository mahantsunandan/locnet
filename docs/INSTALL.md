# Installing LocNet

A working private network from nothing: one coordination server, then as many
machines as you like on Linux, macOS and Windows.

Read [Before you start](#before-you-start) first — one decision there decides
whether everything else works.

---

## Contents

1. [Before you start](#before-you-start)
2. [Build the binaries](#1-build-the-binaries)
3. [Set up the hub](#2-set-up-the-hub)
   · [Port forwarding](#port-forwarding-reaching-the-hub-from-outside-your-network)
4. [Add a machine](#3-add-a-machine)
   · [Ubuntu / Debian](#ubuntu--debian) · [Fedora / RHEL](#fedora--rhel)
   · [macOS](#macos) · [Windows](#windows)
5. [Install the remote-access pieces](#4-install-the-remote-access-pieces)
6. [Check it works](#5-check-it-works)
7. [Lock it down](#6-lock-it-down)
8. [Day-to-day operation](#day-to-day-operation)
9. [Troubleshooting](#troubleshooting)
10. [Uninstalling](#uninstalling)

---

## Before you start

**You need one machine that is always on** to run the hub. A Raspberry Pi is
plenty — it does no heavy work. What it needs is an address the other machines
can reach.

That is the decision that matters:

| Your situation | What to do |
|---|---|
| The hub has a public IP, or you can forward ports to it | Forward **TCP and UDP port 8420** ([how](#port-forwarding-reaching-the-hub-from-outside-your-network)). Advertise the LAN and the public address. Best case: the relay works for everyone and hole punching has a reliable rendezvous. |
| Everything is on one LAN already | Advertise the hub's LAN address. Nothing to forward. |
| The hub is behind NAT you cannot control | Put the hub on a cheap VPS instead and let the always-on machine at home be an ordinary member. A hub nobody can reach coordinates nobody. |

> **Both protocols on the same port.** TCP carries the control plane; UDP
> carries the relay and the address discovery that hole punching depends on.
> Forwarding only TCP is the single most common way to end up with a network
> where every peer sits in `connecting` forever.

**Address range.** LocNet hands out `10.99.0.0/16` by default, chosen to miss
the ranges that collide in practice: Tailscale claims all of `100.64.0.0/10`,
Docker takes `172.17`, Podman `10.88`, k3s `10.42`. Override with `-prefix` on
first run if it still clashes with your LAN — you cannot change it afterwards
without re-addressing every machine.

**Running alongside Tailscale is fine.** Different interface, different UDP
port (41820 vs Tailscale's 41641), and now a non-overlapping range. Both stay
up. `locnet doctor` checks for route and address overlaps on every machine and
names anything it finds.

**Privileges.** The agent creates a network interface, so it runs as root
(Linux/macOS) or as a service (Windows). The hub needs no privileges at all and
the installer runs it under its own unprivileged user.

---

## 1. Build the binaries

Go 1.26 or newer and `bash` (Linux, macOS, or WSL on Windows). No C compiler,
no libraries.

```bash
git clone https://github.com/mahantsunandan/locnet
cd locnet
go test ./...
./scripts/build.sh
```

`dist/` now holds one archive per platform, each with `locnet`, `locnetd`,
`locnet-hub` and the right installer. Copy the correct one to each machine.

---

## 2. Set up the hub

On the always-on machine (Linux example):

```bash
tar xzf locnet_<version>_linux_amd64.tar.gz
cd locnet_<version>_linux_amd64
sudo ./install.sh --hub
sudo nano /etc/locnet/hub.env
```

```ini
# Must be reachable from every machine that will join.
LOCNET_ADVERTISE=hub.example.org:8420

LOCNET_LISTEN=:8420
LOCNET_NETWORK=homelab
LOCNET_PREFIX=10.99.0.0/16
```

`LOCNET_NETWORK` and `LOCNET_PREFIX` are read on first run only.

```bash
sudo systemctl enable --now locnet-hub
sudo journalctl -u locnet-hub -n 30
```

The log ends with your first join code:

```
16:14:05 hub: network "homelab" on 10.99.0.0/16, advertising hub.example.org:8420
16:14:05 hub: fingerprint e92c3b1ed8c30fb6b968d71f9b7d92ed

────────────────────────────────────────────────────────────────
 No machines have joined yet, so here is a join code.

   locnet1_jrhacahjfq5r5wgdb63ls2gxd6nx3exnht4m67nphswj4xucbb…
────────────────────────────────────────────────────────────────
```

The TCP port carries the control plane encrypted: TLS whose certificate key is
the hub's identity key, which every machine checks against the fingerprint in
its join code. There is no certificate to obtain or renew. (`curl -k
https://hub.example.org:8420/healthz` answers `ok`; without `-k` curl refuses
the self-signed certificate, which is expected.)

Open the firewall — **both protocols**:

```bash
sudo ufw allow 8420/tcp && sudo ufw allow 8420/udp          # Ubuntu/Debian
```

```bash
sudo firewall-cmd --permanent --add-port=8420/tcp --add-port=8420/udp && sudo firewall-cmd --reload
```

### Port forwarding: reaching the hub from outside your network

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
   the hub ([OPERATIONS.md](OPERATIONS.md#publishing-a-site-to-the-internet-webshare)).
3. **Find the public address** (what `curl -4 ifconfig.me` prints on the hub)
   and put it in `LOCNET_ADVERTISE` after the LAN address. If your
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

---

## 3. Add a machine

Get a code from the hub. The first-run code covers ten machines; after that:

```bash
locnet-hub invite -label "unit-01" -uses 1 -ttl 24h
```

A join code carries the hub's address, a fingerprint of the hub's identity key,
and the token. The fingerprint makes it safe to send over a channel you do not
fully control — an agent refuses any hub whose key does not match. Treat it
like a password anyway: anyone holding one can add a machine until it is spent
or revoked.

### Ubuntu / Debian

```bash
tar xzf locnet_<version>_linux_amd64.tar.gz
cd locnet_<version>_linux_amd64
sudo ./install.sh
sudo locnet join locnet1_…
```

No kernel WireGuard module needed — LocNet has its own userspace
implementation built in. Works on Ubuntu, Debian, Mint and Pop!_OS.

### Fedora / RHEL

Identical, and the installer picks the right package manager:

```bash
tar xzf locnet_<version>_linux_amd64.tar.gz
cd locnet_<version>_linux_amd64
sudo ./install.sh
sudo locnet join locnet1_…
```

If SELinux is enforcing and `locnetd` cannot create the interface, check
`sudo ausearch -m avc -ts recent`.

### macOS

```bash
tar xzf locnet_<version>_darwin_arm64.tar.gz    # or _amd64 on Intel
cd locnet_<version>_darwin_arm64
sudo ./install.sh
sudo locnet join locnet1_…
```

The interface will be `utun3` or similar — macOS picks the number. On first run
macOS may ask you to allow an incoming connection; allow it, or the relay
cannot tell the machine its public address.

### Windows

Windows 10 or later, 64-bit. Windows 7 and 8 are not supported and the
installer stops rather than leaving you with a service that cannot start.

From an **elevated** PowerShell prompt (Run as Administrator):

```powershell
tar -xzf locnet_<version>_windows_amd64.tar.gz
cd locnet_<version>_windows_amd64
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Join locnet1_…
```

`tar` ships with Windows 10 and 11. `-ExecutionPolicy Bypass` lets this one
unsigned script run without changing the machine's policy; a plain
`.\install.ps1` is refused on a default Windows install.

That is the whole install: one command leaves the machine on the mesh.

Windows needs `wintun.dll`, the tunnel driver, and the installer downloads it
from [wintun.net](https://www.wintun.net) and checks it against a pinned SHA256
before use. It is not bundled in the archive, because redistributing someone
else's signed kernel driver raises a licensing question that a checksummed
download does not.

To keep the installer off the network entirely, fetch the archive yourself, put
`bin\amd64\wintun.dll` in `C:\Program Files\LocNet\`, and run with
`-SkipWintun`.

`locnetd` installs as a real Windows service, so it starts at boot before
anyone logs in and survives logout. It logs to
`C:\ProgramData\LocNet\logs\locnetd.log`.

Windows files every new network adapter under the **Public** firewall
profile, where most inbound rules — including the OpenSSH server's — do not
apply. So at every start `locnetd` marks its adapter as a **Private** network,
as Tailscale does with its own, and keeps one inbound rule, `LocNet-locnetd`,
that admits traffic from the overlay prefix only to `locnetd` itself (its
share server and any port shares). Peers then reach this machine the way a
machine on your home LAN would; LocNet's own share and port policy still
decides what they may use. The adapter keeps a fixed identity, so Windows
remembers the setting across restarts.

To re-run the installer is to upgrade: it stops the service, replaces the
binaries and starts it again, keeping the machine's identity and membership.

Upgrade the hub first, then the other machines, so that no machine expects
something its hub does not offer yet. A standby hub goes after its primary.

Optional, for more reliable direct paths:

```powershell
New-NetFirewallRule -DisplayName "LocNet" -Direction Inbound `
    -Protocol UDP -LocalPort 41820 -Action Allow
```

---

## 4. Install the remote-access pieces

LocNet makes machines reachable and then launches what your system already has
— RDP, VNC, SSH. On a fresh machine those are often missing, and hunting down
the right package name per distribution is exactly the tedium that stops people
finishing a setup.

```bash
locnet setup
```

That prints what is missing and the exact commands that would fix it. Nothing
changes until you say so:

```bash
sudo locnet setup -install
```

```
LocNet setup — Ubuntu 26.04 LTS

  · SSH server             so `locnet ssh <this machine>` works from a peer
      $ apt-get install -y openssh-server
      $ systemctl enable --now ssh
  · Screen sharing         so peers can watch this machine (VNC on :1)
      $ apt-get install -y tigervnc-standalone-server
      $ apt-get install -y openbox xterm
      + map display :1 to your account in /etc/tigervnc/vncserver.users
      + write ~/.vnc/config — bound to localhost, running openbox
      + enable and start the tigervnc service for :1
  ✓ Remote desktop client  already installed
  ✓ VNC client             already installed

  2 step(s) would run.
```

Lines beginning `$` are commands; lines beginning `+` are files LocNet writes
itself. Both are shown before anything runs.

Useful variants:

```bash
locnet setup -role client     # only what you need to connect *from*
locnet setup -role server     # only what you need to be connected *to*
sudo locnet setup -install -yes   # unattended provisioning
```

### What it does per platform

| | Linux | macOS | Windows |
|---|---|---|---|
| SSH server | installs + enables `openssh-server` | turns on Remote Login | adds the OpenSSH Server capability |
| Screen sharing | installs, configures **and starts** a VNC server | tells you where to enable it | puts an installed TightVNC on loopback, password-free, behind the `screen` share |
| Remote desktop | — | — | enables RDP + firewall rule |
| RDP client | `freerdp` / `remmina` | tells you to install Windows App | built in (`mstsc`) |
| VNC client | `remmina` | built in | tells you to install one |

### What screen sharing sets up on Windows

If TightVNC is installed, setup moves it to `127.0.0.1:5901` (loopback only),
turns its VNC password off, restarts it, checks it is really listening there,
and publishes it as the `screen` share on overlay port 5900 — the same shape as
Linux. The share checks each peer's identity before connecting anything, so
the password was only another secret to lose; loopback-only is what makes
dropping it safe, since TightVNC otherwise listens on every network. Without
TightVNC, setup says how to install it (`winget install -e --id
GlavSoft.TightVNC`). Viewers see the real console screen, including the
Windows lock screen if the session is locked.

### What screen sharing sets up on Linux

Setup does not stop at installing a VNC package. A package that is present
with nothing listening on the port is, from a peer, indistinguishable from a
machine with no VNC at all — so setup also starts the server and publishes it.

It creates a **virtual desktop** — Xvnc hosting a display of its own on `:1` —
rather than sharing the screen you are sitting in front of. That is not a
preference, it is the only thing that works: a Wayland session cannot be handed
to a VNC server, GNOME removed its VNC backend in GNOME 46, and `wayvnc` only
speaks to wlroots compositors. A virtual desktop works on X11 and Wayland
alike, survives logout, and needs no graphical session to already exist — which
is what a headless field unit wanted anyway.

Three things make that safe:

- **The server binds to `127.0.0.1`.** It is invisible to your LAN regardless
  of how the firewall is set.
- **Peers reach it through a LocNet port share**, which checks the caller's
  identity against an access list before forwarding a byte. Inside the tunnel
  that identity is a WireGuard key, not a source address anyone can claim.
- **Hence no VNC password.** A second secret in front of a door already locked
  by a keypair is one more thing to lose, not more security.

Setup publishes the share to *everyone on your network* and prints how to
narrow it:

```bash
locnet share add screen :5901 -allow workstation,laptop   # only these two
locnet share remove screen                                # stop sharing
```

If the machine has no X session installed — normal on a Wayland-only desktop —
setup installs `openbox` and `xterm` for the virtual display to run. Install a
fuller desktop such as `xfce4` first and it will use that instead.

**To see the physical screen instead**, use `locnet screen <peer>` or the
console's **Screen** button. That path captures the real desktop, needs no VNC
server and nothing installed at the viewing end — but on Wayland it needs a
VNC server to bridge, which is what the above provides. See
[DESKTOP.md](DESKTOP.md).

### One thing it deliberately will not do

**On macOS it will not enable Screen Sharing for you.** That grants access to
specific users, and the right answer differs per machine. Turn it on in
System Settings → General → Sharing → Screen Sharing.

---

## 5. Check it works

```bash
locnet status      # this machine and its peers
locnet peers       # peers with services, shares and load
locnet console     # the web console
```

```
PEER     ADDRESS    OS       PATH    CPU        FREE DISK  SERVICES      SHARES
unit-01  10.99.0.2  windows  direct  34% of 8   210G/931G  rdp,vnc,http  archive
unit-02  10.99.0.3  windows  relay   91% of 4   18G/465G   rdp,ssh       data,pg
```

`connecting` for a few seconds after a machine joins is normal — that is the
probing. Services take up to 5 minutes to appear; that scan is deliberately
infrequent.

Then use it:

```bash
ping 10.99.0.2
locnet rdp unit-01
locnet ssh unit-02
```

### Names instead of addresses

```bash
sudo locnet hosts on
```

Writes a marked block into `/etc/hosts` with one line per peer, refreshed on
every change. Now `ssh unit-02` works. Everything outside the markers is left
alone.

---

## 6. Lock it down

Worth doing before the network grows past a handful of machines.

### Require approval for new machines

```bash
locnet-hub health set -require-approval=true
```

A machine that joins now holds an address but appears in nobody's network map
until you admit it:

```bash
locnet-hub nodes            # shows WAITING
locnet-hub approve unit-01
```

Existing machines stay approved — the setting governs what happens next.

### Restrict who can reach what

By default every machine reaches every machine. For a fleet that is usually
wrong: a field unit has no business reaching another field unit.

```bash
locnet-hub policy example > policy.json
nano policy.json
locnet-hub policy set policy.json
```

```json
{
  "groups": {
    "field-units":  ["unit-01", "unit-02", "unit-03"],
    "operators": ["workstation", "laptop"]
  },
  "rules": [
    {"src": ["operators"], "dst": ["field-units"], "ports": ["*"]},
    {"src": ["collector"], "dst": ["field-units"], "ports": ["8421"]},
    {"src": ["operators"], "dst": ["operators"]}
  ]
}
```

No rule connects two field-units, so **they never appear in each other's network
map** — no WireGuard peer, no key, no path. That isolation is enforced by the
cryptography, not by a firewall rule somebody could forget. See
[OPERATIONS.md](OPERATIONS.md#access-policy) for the details.

To switch one connection off without editing the policy — say, one machine may
be reached but may not reach others — use the access table, from any
administrator machine or the console's Network page:

```bash
locnet admin access                          # who may connect to whom
locnet admin access block laptop server ssh vnc
locnet admin access allow laptop server vnc
```

### Set alert thresholds

```bash
locnet-hub health set -disk-warn 15 -disk-critical 5 -offline-after 30m
locnet-hub alerts
```

`locnet-hub alerts -quiet` prints nothing when all is well and exits 1 when it
is not, which makes it a one-line cron check.

---

## Day-to-day operation

### On any machine

```bash
locnet status              locnet peers              locnet console
locnet ssh|rdp|vnc <peer>  locnet open <peer>
locnet share list|add|remove
locnet files <peer> …      locnet doctor
locnet exec <cmd> -on all              # one command on every machine
locnet copy <files> -to all [-dest …]  # send files/folders to many at once
locnet fetch <path> -from all          # collect a file from many at once
locnet up | down | leave   locnet setup
locnet webshare add <site> <port>      # publish a local web app (needs approval)
locnet admin access | webshare | audit # on an administrator machine
```

### On the hub

```bash
locnet-hub nodes                        locnet-hub alerts
locnet-hub invite -label "new laptop"   locnet-hub audit
locnet-hub approve <machine>            locnet-hub policy [edit]
locnet-hub remove <machine>             locnet-hub health [set …]
locnet-hub revoke <code-start>         locnet-hub webshare [domain …]
```

To publish web apps to the internet through the hub, see
[OPERATIONS.md](OPERATIONS.md#publishing-a-site-to-the-internet-webshare). The
hub's service unit grants it one capability, `CAP_NET_BIND_SERVICE`, so it can
take ports 80 and 443 for that; it opens neither until a domain is set.

### Reinstalling an agent

Reinstalling on a machine that already joined keeps its identity key, so
rejoining gives it the same address and the same record. No need to remove it
from the hub first.

---

## Troubleshooting

```bash
locnet doctor
```

Checks each link in the chain and says what to do about the first broken one.

### Every peer is stuck in `connecting`

Nine times out of ten this is **UDP not reaching the hub**. The relay is what
tells each machine its own public address, and without that nothing can be
probed.

```bash
nc -zvu hub.example.org 8420
```

Check the hub's firewall and your router forward **UDP** as well as TCP.

### Peers connect but stay on `relay`

Relayed peers work, just slower. Common causes:

- **Both ends behind symmetric NAT** — some corporate networks, most mobile
  hotspots. Forwarding UDP 41820 to *one* of the two machines fixes the pair.
- **UDP blocked outbound** on one side.
- **Both on the same LAN with client isolation on** at the access point.

### A peer vanished after a policy change

That is the policy working. Check it:

```bash
locnet-hub policy
```

If a machine should be visible, add a rule connecting its group to yours. The
hub refuses a policy that would isolate every machine from every other, but it
will happily isolate one.

### `create tunnel interface: operation not permitted`

`locnetd` is not running as root. `systemctl status locnetd` on Linux; on macOS
the plist must be in `/Library/LaunchDaemons`, not `~/Library`.

### `locnet rdp` says no client found

```bash
sudo locnet setup -install
```

### `the hub at X is not the one this code was issued for`

The hub's identity key changed — usually because `hub.json` was deleted and
recreated. Every existing join code is now invalid; mint new ones.

If you did **not** expect the key to change, stop. Something is answering on
the hub's address that is not your hub. Do not use the code.

### `the hub presented identity …, but this machine trusts …`

The TLS handshake reached something holding a different key than the hub this
machine joined. Either the hub's key was regenerated (`hub.json` recreated —
rejoin with a fresh code: `sudo locnet join <code>`), or something is answering
on the hub's address in its place. LocNet sent it nothing.

### `the hub at X answered without TLS, so it is not the hub this machine joined`

Something at the hub's address answered in plain HTTP. A LocNet hub never
does that to another machine, so it is a different program on that port — a
wrong port forward, another service on 8420 — or someone in the way. Nothing
was sent. Check what is listening on the hub: `sudo ss -ltnp | grep 8420`.

### `this hub is reached only over TLS pinned to its key`

Something spoke plain HTTP to the hub from another machine — a browser, a
script, or curl without `https://`. LocNet's own programs never do. To look at
the hub by hand: `curl -k https://<hub>:8420/healthz`.

### `timestamp is 8m21s away from hub time`

The machine's clock is wrong. Requests are signed with a timestamp and rejected
outside a five-minute window.

```bash
sudo timedatectl set-ntp true          # Linux
sudo sntp -sS time.apple.com           # macOS
w32tm /resync                          # Windows
```

### A peer shows `offline` but is switched on

The hub marks a node offline after 90 seconds without contact. Run
`locnet doctor` on that machine.

---

## Uninstalling

```bash
sudo ./install.sh --uninstall     # Linux, macOS
.\install.ps1 -Uninstall          # Windows, elevated
```

Binaries and services go; state stays, so reinstalling rejoins the same network
with the same address. To make a machine forget everything:

```bash
sudo rm -rf /var/lib/locnet                         # Linux
sudo rm -rf "/Library/Application Support/LocNet"   # macOS
Remove-Item -Recurse "$env:ProgramData\LocNet"      # Windows
```

Then remove it on the hub:

```bash
locnet-hub remove <name>
```
