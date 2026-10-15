# Command reference

Every command of the two programs: `locnet`, on every machine, and
`locnet-hub`, on the hub. Each entry says what it does, its flags, and where
the longer explanation lives. `locnet <command> -h` prints the same help on
the machine itself.

Most `locnet` commands talk to the local agent, `locnetd`. On Linux and macOS
the account must be in the `locnet` group (or use `sudo`); on Windows, run them
from an elevated prompt where noted.

Contents: [Network](#network) · [Connect](#connect) · [Share](#share) ·
[Several machines at once](#several-machines-at-once-over-ssh) ·
[Borrowing compute](#borrowing-another-machines-compute) ·
[Compute channel](#compute-channel) · [Queue](#queue) ·
[Running the network](#running-the-network-from-an-administrator-machine) ·
[Other](#other) · [locnet-hub](#locnet-hub)

---

## Network

### `locnet join <code>`

Joins the network with a join code from an administrator, brings the tunnel
up, installs the SSH and screen servers this machine is missing (as `locnet
setup -install` would), and asks a peer to check that it can actually get in.

| Flag | |
|---|---|
| `-no-up` | join, but leave the tunnel down |
| `-no-setup` | join, and install nothing |

The installers do this in one step: `sudo ./install.sh --join <code>` on Linux
and macOS, `.\install.ps1 -Join <code>` on Windows. See
[INSTALL.md](INSTALL.md).

### `locnet up` · `locnet down`

Bring the tunnel up or take it down. The agent also brings it up by itself at
start, retrying until it works; a manual `up` or `down` ends those retries, so a
`down` stays down.

### `locnet status [-json]`

This machine — name, address, tunnel, hub (and whether the control plane to it
is encrypted), how the relay sees it — and every
peer, with the path (direct or relay), the address it is reached on and the
latency.

### `locnet peers`

Every peer with its services, shares, CPU, free disk and memory. Services
marked `?` were found on that machine but not yet confirmed reachable — neither
a peer it asked nor this machine has connected to them; `!` means a server
answers but will not let anyone in, with the reason.

### `locnet ip`

This machine's overlay address, alone, for scripts.

### `locnet leave [-yes]`

Forget the network. The machine keeps its identity; its record stays on the
hub until an administrator removes it. Asks for confirmation unless `-yes`.

---

## Connect

### `locnet console [-port N] [-no-open] [-downloads <dir>]`

Opens the web console: machines, files, running commands, the queue, this
machine's settings, the network (on an administrator machine) and these
documents. Bound to `127.0.0.1` with a token that changes every run. See
[SHARING.md](SHARING.md#the-console).

### `locnet ssh <peer>` · `locnet vnc <peer>` · `locnet rdp <peer>`

Open your own terminal, VNC viewer or RDP client on that machine, by name.
Before opening a viewer LocNet checks the far server will let you in, and says
what is wrong if it will not. `locnet vnc` reaches the machine's `screen`
share on port 5900. See [DESKTOP.md](DESKTOP.md).

### `locnet open <peer> [service]`

Open whatever that machine serves — a web page in the browser, or the client
for the named service.

### `locnet login <peer> <account>`

Remember which account to use on that machine, for `ssh`, `exec`, `copy`,
`fetch` and `job`. Needed when the account name differs from yours, as with a
Windows machine.

### `locnet ssh-key <peer>`

Install your SSH key on one machine, asking for its password once.

### `locnet ssh-keys …`

Exchange SSH keys over the mesh, with no passwords and no host-key prompts.

| | |
|---|---|
| `locnet ssh-keys` | what is published and what is trusted |
| `locnet ssh-keys publish` | offer this account's public key to the network |
| `locnet ssh-keys accept <peer>\|all` | let that peer's operator log in here |
| `locnet ssh-keys revoke <peer>\|all` | stop letting them |
| `locnet ssh-keys sync` | install peers' host keys, and accepted peers' user keys |

On Windows, an administrator's keys go in
`C:\ProgramData\ssh\administrators_authorized_keys`, which is the file Windows'
sshd reads for administrators.

---

## Share

### `locnet share list|add|remove`

| | |
|---|---|
| `locnet share list` | this machine's shares |
| `locnet share add <name> <path>` | share a folder |
| `locnet share add <name> :<port>` | publish a local service on the overlay |
| `locnet share remove <name>` | stop |

| Flag (add) | |
|---|---|
| `-allow a,b` or `-allow "*"` | who may use it (default: nobody) |
| `-rw` | allow uploads to a folder share (default: read-only) |
| `-on <port>` | overlay port for a service share (default: the local one) |
| `-desc <text>` | description shown in the console |

See [SHARING.md](SHARING.md).

### `locnet files <peer> [<share> [path]]`

| | |
|---|---|
| `locnet files <peer>` | the shares you may use there |
| `locnet files <peer> <share> [path]` | list a directory |
| `locnet files <peer> <share> <path> -get` | download to the current directory |
| `locnet files <peer> <share> <path> -put <file>` | upload a local file |

### `locnet webshare …`

Publish a web app on this machine to the internet at
`https://<site>.<the hub's domain>`, through the hub.

| | |
|---|---|
| `locnet webshare` | this machine's sites, their state and address |
| `locnet webshare add <site> <port>` | ask to publish `localhost:<port>` (or `host:port`) |
| `locnet webshare remove <site>` | stop publishing it |

`-on <port>` picks the overlay port the hub reaches it on (default: the first
free one from 8430). Nothing is public until an administrator approves the
name: `locnet admin webshare approve <site>`. See
[OPERATIONS.md](OPERATIONS.md#publishing-a-site-to-the-internet-webshare).

---

## Several machines at once (over SSH)

These use your SSH account on each machine (see `locnet login` and `locnet
ssh-keys`) and never prompt for a password. Targets are comma-separated names,
or `all`.

### `locnet exec <command> -on <machines>`

Run a shell command everywhere at once, output tagged by machine. Default
`-on all`.

### `locnet copy <file|folder>… -to <machines> [-dest <path>]`

Send files and folders (rsync where possible, scp to Windows). `-dest` defaults
to the home directory. Also `locnet send`.

### `locnet fetch <remote-path> -from <machines> [-into <dir>]`

Collect one path from many machines, each into its own subfolder of `-into`
(default `.`).

---

## Borrowing another machine's compute

### `locnet best [-gpu] [-cpus N] [-mem GB] [-vram GB] [-disk GB] [-json]`

Rank machines by free CPU, memory and GPU, and say why. Requirements exclude
machines that cannot run the job rather than ranking them low.

### `locnet job [flags] -- <command>`

Send this folder to the best machine (or `-on <peer>`), run the command there
with output streaming back, and copy the folder back.

| Flag | |
|---|---|
| `-on <peer>` | pick the machine |
| `-dir <path>` | folder to send (default `.`) |
| `-back=false` | do not copy back |
| `-keep` | leave the remote copy |
| `-exclude a,b` | patterns not to send |
| `-env K=V,…` | environment for the command |
| `-gpu -cpus -mem -vram -disk` | requirements, as for `best` |

On Windows the command runs in PowerShell. See
[COMPUTE.md](COMPUTE.md#running-a-job-elsewhere).

### `locnet julia [-on <machines>] [-procs N] [-exename julia] [-machine-file <path>]`

Print the `addprocs()` call that gives Julia's Distributed workers on those
machines.

---

## Compute channel

LocNet's own way to run a command on another machine: no SSH account, opt-in
on the machine that runs it, and no shell — the words after `--` are executed
exactly as written.

### `locnet compute`

| | |
|---|---|
| `locnet compute` | this machine's setting |
| `locnet compute enable [flags]` | accept jobs from named peers |
| `locnet compute disable` | stop |
| `locnet compute peers` | who will run work for this machine |

| Flag (enable) | |
|---|---|
| `-allow a,b` or `"*"` | peers that may submit (required) |
| `-user <account>` | local account jobs run as (required unless `-allow-privileged`) |
| `-label <text>` | shown to peers, e.g. "16 cores, CUDA" |
| `-max <seconds>` | time limit per job (default 3600) |
| `-dir <path>` | working directory (default: the account's home) |
| `-allow-privileged` | without `-user`, run as root / SYSTEM; with `-user` on Windows, keep an administrator's elevated token |

Only someone at the machine can enable it. On Windows, `-user` works without
the account's password, and an administrator account runs unelevated. See
[SHARING.md](SHARING.md#sharing-compute).

### `locnet run …`

| | |
|---|---|
| `locnet run <peer> -- <command> [args…]` | on one machine |
| `locnet run -group <name> -- …` | on every machine in a policy group |
| `locnet run -idle -- …` | on whichever accepting machine is least busy |

`-timeout <seconds>` (never more than the machine allows), `-dir <path>`
(absolute, on the far machine).

---

## Queue

Work that waits on the hub until a machine that fits is free. See
[QUEUE.md](QUEUE.md).

| | |
|---|---|
| `locnet queue` | what is waiting and running (`-all` includes finished, `-mine` only yours) |
| `locnet queue submit [flags] -- <command>` | add a job |
| `locnet queue log <id>` | one job's output |
| `locnet queue cancel <id>` | cancel it |
| `locnet queue workers` | machines that will take queued work |

| Flag (submit) | |
|---|---|
| `-on <peer>` | that machine and no other |
| `-cpus N` `-mem GB` `-disk GB` `-gpu` `-vram GB` | requirements |
| `-dir <path>` | working directory where it runs |
| `-max <seconds>` | time limit for one attempt |
| `-priority N` | higher runs first |
| `-label <text>` | a name to recognise it by |
| `-n N` | submit N copies, e.g. for a sweep |
| `-wait` | stay until it finishes and print the output |

---

## Running the network (from an administrator machine)

Signed with this machine's own key; the hub accepts them only from machines it
has made administrators (`sudo locnet-hub admins add <machine>` on the hub).
The console's **Network** page does the same.

| | |
|---|---|
| `locnet admin` | every machine, as the hub sees it |
| `locnet admin invite [-uses N] [-ttl 24h] [-label text]` | a join code (also `locnet invite`) |
| `locnet admin invites` | join codes, and which still work |
| `locnet admin revoke <id>` | stop a join code working |
| `locnet admin approve <machine>` | admit a machine that is waiting |
| `locnet admin remove <machine> [-yes]` | take a machine off the network |
| `locnet admin audit` | who joined, left and changed what |

### `locnet admin access …`

Who may open connections to whom, per service. See
[OPERATIONS.md](OPERATIONS.md#switching-single-connections-on-and-off).

| | |
|---|---|
| `locnet admin access` | the table: rows connect to columns |
| `locnet admin access block <from> <to> [service…]` | stop `<from>` opening those on `<to>` |
| `locnet admin access allow <from> <to> [service…]` | let it again |

Services are `ssh` (22), `vnc` (5900), `rdp` (3389), `smb` (445), `locnet`
(8421 — files, compute and shares), `all`, or port numbers and ranges; none
means all. `<from>` and `<to>` are machine names, policy groups or `*`.

### `locnet admin webshare …`

| | |
|---|---|
| `locnet admin webshare` | every site, its machine, state and address |
| `locnet admin webshare approve <site> [-machine <m>]` | publish it |
| `locnet admin webshare off <site>` / `on <site>` | stop / resume answering |
| `locnet admin webshare remove <site>` | forget the approval |

The domain and DNS token are set on the hub: `locnet-hub webshare domain`.

---

## Other

### `locnet setup [-install] [-yes]` · `locnet setup rdp [-new]`

Shows what this machine is missing to be reachable — an SSH server and a
screen server — and with `-install` installs it, after showing the exact
commands. On Windows that is OpenSSH, Remote Desktop and, if TightVNC is
installed, putting it behind LocNet with no VNC password. `locnet setup rdp`
gives GNOME Remote Desktop a login so peers can see the real screen. See
[INSTALL.md](INSTALL.md#4-install-the-remote-access-pieces).

### `locnet doctor`

Checks for the usual causes of a network that will not form — daemon, tunnel,
hub, address conflicts, the path to each peer — and asks a peer the access
policy lets in to connect back and confirm this machine's services are
reachable. Ports the asking peer is not allowed to reach are marked "not
checked", not reported as a firewall problem.

### `locnet wake <peer> [-via <peer>] [-wait <duration>]`

Wake a machine that is off, by having a peer on its network send the packet.
Wake-on-LAN must be enabled in that machine's firmware and adapter settings.

### `locnet hosts on|off`

Add or remove a block of peer names in the system hosts file, so `ssh hubpc`
works without LocNet.

### `locnet desktop …`

LocNet's own screen-sharing protocol (no viewer ships for it any more; use
`locnet vnc`/`rdp`). `locnet desktop`, `share -allow <who> [-control] [-label]
[-fps] [-quality]`, `stop`, `serve [-vnc <addr>] [-vnc-password-file <f>]`,
`autostart [off]`.

### `locnet version`

---

## locnet-hub

Run on the hub machine. Commands other than `serve` talk to the running hub's
admin API with the token in its state directory, so they need `sudo`. Common
flags: `-hub <url>` (default `http://127.0.0.1:8420`), `-state-dir <dir>`,
`-token <token>` (or `LOCNET_HUB_ADMIN_TOKEN`).

### `locnet-hub serve [flags]`

Runs the hub: the control plane (TCP — TLS pinned to the hub's key, and plain
HTTP for agents older than 0.10.4) and relay (UDP) on `-listen`, and WebShare on
80/443 once a domain is set.

| Flag | |
|---|---|
| `-listen :8420` | API and relay address |
| `-advertise a,b` | addresses nodes should use, most specific first |
| `-state-dir <dir>` | where the network database lives |
| `-network <name>` `-prefix <cidr>` | first run only |
| `-follow <addr> -follow-token <t> [-follow-fingerprint <fp>] [-follow-every 1m]` | run as a standby mirroring a primary, over TLS pinned to `<fp>` (`locnet-hub fingerprint` on the primary; needed only before the first copy) |
| `-require-tls` | refuse plain HTTP from other machines, once every agent is 0.10.4 or later |
| `-standby a,b` | standby hubs, told to every node |
| `-web-http :80` `-web-https :443` | WebShare listeners |
| `-acme-directory <url>` | certificate authority (default Let's Encrypt production) |

### Membership

| | |
|---|---|
| `locnet-hub invite [-label] [-uses N] [-ttl 24h]` | a join code |
| `locnet-hub invites` | join codes |
| `locnet-hub revoke <code-start>` | disable one |
| `locnet-hub nodes [-json]` | machines on the network, and any still talking to the hub without TLS |
| `locnet-hub approve <machine>` | admit a waiting machine |
| `locnet-hub remove <machine>` | take one off |
| `locnet-hub admins [add\|remove <machine>]` | who may administer from their own machine |

### Access control

| | |
|---|---|
| `locnet-hub policy` | the policy, rendered: groups, rules, blocks |
| `locnet-hub policy edit` | edit in `$EDITOR`, applied on save |
| `locnet-hub policy set <file.json>` | replace it |
| `locnet-hub policy example` | a worked example |

See [OPERATIONS.md](OPERATIONS.md#access-policy).

### `locnet-hub webshare …`

| | |
|---|---|
| `locnet-hub webshare` | sites, their state, the domain and DNS |
| `locnet-hub webshare domain <name> -accept-tos [-duckdns-token <t>] [-email <a>]` | turn WebShare on |
| `locnet-hub webshare domain -off` | turn it off and forget the token |
| `locnet-hub webshare approve <site> [-machine <m>]` | publish a site |
| `locnet-hub webshare off\|on\|remove <site>` | as for `locnet admin webshare` |

`-accept-tos` is agreement to Let's Encrypt's subscriber agreement. The router
must forward TCP 80 and 443 to the hub, and its firewall let them in.

### Operations

| | |
|---|---|
| `locnet-hub alerts [-quiet] [-json]` | what is wrong now; `-quiet` exits 1 when something is |
| `locnet-hub health` | thresholds and the approval setting |
| `locnet-hub health set [-disk-warn %] [-disk-critical %] [-load-warn %] [-mem-warn %] [-offline-after 30m] [-mute a,b] [-require-approval=true\|false]` | change them |
| `locnet-hub audit [-n 40]` | membership, policy, access and WebShare changes |
| `locnet-hub promote [-state-dir <dir>]` | turn the standby running here into the hub |
| `locnet-hub fingerprint [-state-dir <dir>]` | the hub's identity fingerprint, as join codes carry it — for a standby's `-follow-fingerprint` |
| `locnet-hub version` | |
