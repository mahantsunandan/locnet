# Remote access and resource sharing

Once machines can reach each other, the useful part begins: opening a desktop,
pulling a file off a field unit, reaching a database that only listens on
localhost. This is how.

---

## The console

```bash
locnet console
```

Opens the LocNet console in your browser. It has seven pages:

| | |
|---|---|
| **Machines** | Every machine — online or not, direct or relayed, CPU, memory and disk, what it runs and shares, when it was last seen. Click one for its details and to connect: a terminal, its screen over RDP or VNC, its files, a web page it serves, or *Wake it up* when it is off. Tick several to run a command on all of them or copy files to all of them. |
| **Files** | Two panes, this computer and another, copying in either direction over SSH (rsync where it is installed, with a progress bar; scp to and from Windows). |
| **Run** | One command on many machines at once — in your own shell over SSH, or through LocNet's compute channel with no account needed. |
| **Queue** | Jobs that wait on the hub until a machine that fits is free, their output, and which machines take work. |
| **This machine** | Bring the tunnel up or down; check that connections really work, in both directions; share a folder or a port; offer compute; peer names in the hosts file. |
| **Network** | Invite a machine (a join code, with the command to paste on the new machine), admit one that is waiting, remove one that was reset or lost; **who may connect to whom** — a table of every machine against every other, where clicking a cell switches SSH, VNC, RDP, SMB or LocNet's own port on or off for that pair; **WebShare** — approve, turn off or remove sites published to the internet; and see what changed. Only on a machine the hub has made an administrator — see [OPERATIONS.md](OPERATIONS.md#administering-from-your-own-machine). |
| **Docs** | Every document here, compiled into the program so it always matches the version you are running: a start-here guide, the full command reference, how each feature works, and what changed. Searchable. |

It follows the system's light or dark setting (or pick one), works at phone
width, stops polling while its tab is in the background, and takes
`/` (filter), `Esc` and `g` then a page letter from the keyboard.

It binds to `127.0.0.1` only, with a token that is new every run and travels in
a header rather than a cookie. Another page in your browser cannot drive it
even if it guesses the port, because the server answers no CORS preflights.

Use `-no-open` to print the URL instead of launching a browser, and
`-downloads <dir>` to change where downloaded files land.

---

## Is this a TeamViewer replacement?

For the cases that matter, yes.

TeamViewer's value is two things: it gets through NAT so you can reach a machine
that has no public address, and it gives you a desktop with nothing installed at
either end. LocNet now does both — the second one is
[`locnet screen`](DESKTOP.md), which paints the far machine's desktop onto a
canvas in your browser.

|  | LocNet | TeamViewer |
|---|---|---|
| Reaches machines behind NAT | yes | yes |
| Traffic stays inside your network | **yes** | no — relayed through their servers |
| Unattended access | yes | yes |
| Account or subscription | none | required |
| Desktop in a browser, nothing installed | **yes** | yes |
| Sound, printers, clipboard, drive redirection | no | yes |
| File transfer | yes | yes |
| Commercial-use detection nagging you | no | famously yes |

Where the built-in viewer stops: it is pixels, keyboard and mouse. No sound, no
printer or clipboard redirection, no multi-monitor separation. When you want a
real Windows session with all of that, `locnet rdp` still hands off to RDP,
which Microsoft has been tuning since 1998 and which no reasonable amount of
work here would beat.

The other limit is the far machine. Capture needs somebody logged in with the
session helper running, and needs an Xorg session rather than Wayland on Linux.
[DESKTOP.md](DESKTOP.md) says why, and what to do instead.

---

## Connecting to a machine

```bash
locnet peers                  # who is out there, and what they offer
locnet screen unit-01         # its desktop, in your browser, nothing installed
locnet rdp unit-01            # remote desktop, with an RDP client
locnet vnc unit-02             # screen sharing, with a VNC client
locnet ssh unit-03             # shell
locnet ssh admin@unit-03       # shell as a specific user
locnet open unit-01           # whatever that machine offers
locnet open unit-01 http      # a specific service
```

Peers are named, so you never type an address. Under the hood each command
resolves the name to an overlay address and launches the local client.

---

## Doing something to several machines at once

Once a machine is reachable and you have an account on it, `ssh` and `scp` are
better at shells and file transfer than anything LocNet could reasonably write.
What was missing is doing it to *all* of them.

```bash
locnet exec 'uptime' -on all                 # one command, every machine
locnet exec 'sudo dnf upgrade -y' -on lab-1,lab-2
locnet copy report.pdf notes/ -to all        # send files and folders
locnet copy build.tar -to lab-1,lab-2 -dest /opt/staging
locnet fetch /var/log/syslog -from all -into ./logs
```

Every machine runs at once, output is tagged with the machine it came from, and
the run ends with a line saying which ones failed. `fetch` gives each machine
its own subfolder — six machines' copies of `syslog` in one directory would
leave one file and five silent overwrites.

Ctrl-C stops everything, including the `ssh` processes `scp` forks off.

The same three actions are in the web console's right-hand rail, where the file
and folder pickers are the operating system's own — a web page is never told a
real path, so the console asks the OS to open the dialog instead.

### What it needs

An account on each machine, and a key so nothing prompts for a password:

```bash
locnet login lab-1 yourname     # remember the account (the console has a box for this too)
locnet ssh-key lab-1            # copy your key over, once
```

These commands never prompt. A web console has no terminal to type a password
into, and a fan-out that stops on machine three waiting for input is worse than
one that fails. So a missing key fails immediately and says
`SSH refused the login. Set up a key: locnet ssh-key <peer>`.

### Why this is separate from `locnet run`

`locnet run` uses LocNet's own compute channel: the far machine has to opt in,
it runs no shell, and it needs no account. That is for lending cycles to
colleagues. `locnet exec` uses the account you already have and gives you a
real shell. Both are useful; they are not the same thing.

### How services are found

Every agent periodically dials **its own overlay address** on a short list of
well-known ports — 22, 3389, 5900, 5901, 80, 443, 8080, 445 — and reports what
answers.

Dialling its own overlay address rather than localhost is the important detail.
A service bound only to `127.0.0.1` is invisible to peers, and probing loopback
would advertise an SSH server nobody can actually reach. The scan tests exactly
what a peer would experience.

The scan runs every five minutes, so a service you have just started takes a
few minutes to appear. You can always connect by address in the meantime.

A machine dialling itself does not cross its own firewall, so what it finds is
only a claim until someone else connects. Two things confirm it: the machine
asks a peer to connect back, and every machine tries the unconfirmed services
of the peers it can see, on the same five-minute round. A service either one
reached is shown plainly; one nobody has reached yet is shown with `?`. The
second matters under a one-way policy: a laptop that may open no connections
can never ask anyone, but the machines allowed to reach it confirm its
services for themselves — which is also the question someone looking at the
list is asking.

### Clients LocNet will look for

| | Linux | macOS | Windows |
|---|---|---|---|
| RDP | `xfreerdp3`, `xfreerdp`, `remmina`, `rdesktop` | Microsoft Remote Desktop | `mstsc.exe` (built in) |
| VNC | `remmina`, `vncviewer`, `vinagre` | Screen Sharing (built in) | `vncviewer.exe` |
| SSH | `ssh` | `ssh` | OpenSSH client |

If none is installed, LocNet tells you which package to install rather than
just reporting "command not found".

---

## Sharing a folder

```bash
locnet share add data /srv/data -allow workstation,laptop
locnet share add drop /srv/incoming -allow "*" -rw
locnet share list
locnet share remove data
```

Shares are **deny by default**. A share created without `-allow` is visible to
nobody, and LocNet says so rather than leaving you to discover it. `-allow "*"`
means every member of the network; otherwise it is a list of peer names.

Folders are read-only unless you pass `-rw`.

### Reading someone else's share

```bash
locnet files unit-01                          # what may I use?
locnet files unit-01 archive                    # list the share root
locnet files unit-01 archive 2026/07            # list a subdirectory
locnet files unit-01 archive 2026/07/a.csv -get # download here
locnet files unit-01 drop report.pdf -put ./report.pdf
```

Or click through it in the console.

### How access is enforced

Two things are worth understanding.

**The machine that owns a resource is the one that enforces access to it.** The
hub distributes what each node has declared, but the check happens on the
sharing machine. A compromised hub can lie to you about what is on offer; it
cannot grant itself a folder on your machine.

**The authenticator is the overlay source address.** That is not the usual weak
"trust the source IP". The share server binds the overlay address only, so the
only way to reach it is through the tunnel, and WireGuard's allowed-IP check
means a packet from `100.100.0.3` was decrypted with that node's private key.
There is no token to steal, because the tunnel already answered the question.

A peer is never told the name of a share it may not use. An access list that
leaks the names of the things it protects is only half a control.

---

## Sharing compute

A machine can offer to run commands for named peers. This is what turns a
network of computers into a pool of them: the fast desktop in the office can
build for the laptop, and a batch job can land wherever there is capacity.

It is also remote code execution, and the design treats it that way.

```bash
# On the machine offering capacity:
locnet compute enable -allow workstation,laptop -user buildbot -label "16 cores"

# From anywhere allowed:
locnet run buildbox -- make -j16
locnet run -idle -- ./nightly.sh          # wherever there is capacity
locnet run -group field-units -- uptime   # everywhere in a group at once
locnet compute peers                      # who will run work for me
```

### The controls, and what each one buys

| | |
|---|---|
| **Off by default** | There is no way to enable it remotely. Somebody has to sit at the machine. |
| **Explicit access list** | No default, no implicit "everyone". `-allow "*"` is possible and the CLI says plainly what you just did. |
| **No shell** | The words after `--` are exec'd exactly as written. `;`, `&&`, `$(…)` and `*` are literal characters. There is no injection to worry about because there is no interpreter. |
| **Runs as a named user** | On Unix the process drops to `-user` before exec, with only that user's groups. On Windows it runs under a token for `-user` obtained without a password (below). Enabling without `-user` is refused unless you pass `-allow-privileged`. |
| **Deadline** | Every job is killed at the limit, together with everything it started — a process group on Unix, a job object on Windows. A caller may lower the limit, never raise it. |
| **Bounded output** | 4 MB, then truncated. A command that prints forever cannot exhaust the machine running it. |
| **Clean environment** | Jobs inherit nothing from the daemon — just `PATH`, `HOME` and `LOCNET_JOB_FROM`. |

### What it is not

**Not a sandbox.** A job runs as a real user with that user's real
permissions. If `buildbot` can read a file, so can any peer you allowed. The
protections above are a reasonable set of controls for machines you own; they
are not isolation, and none of this should be pointed at code you do not trust.

### On Windows

```powershell
locnet compute enable -allow linuxbox,hubpc -user winpc-01
```

`-user` names a **local** account (`name`, `.\name` or `COMPUTER\name`;
domain accounts are not supported). locnetd, which runs as SYSTEM, asks
Windows for a token for that account by name — an S4U logon — so LocNet never
holds or asks for its password. What a job gets:

- **The account's own environment and profile**: its `PATH` (a per-user Python
  is found by name), `%USERPROFILE%`, `%APPDATA%`. Commands are looked up in
  the account's `PATH`, not SYSTEM's. With no `-dir`, jobs start in the
  profile folder. `LOCNET_JOB_FROM` and friends are set as on Unix; `HOME` is
  not, because on Windows it would mislead git and ssh.
- **No network credentials.** A token obtained this way can use the machine
  as the account but cannot reach file shares elsewhere as it.
- **Never elevated.** If the account is an administrator, the job runs with
  the token UAC gives it at the desktop: Administrators deny-only, no admin
  privileges, medium integrity — the same as a program you start without
  "Run as administrator". `whoami /groups` in a job shows it. To run elevated,
  pass `-allow-privileged` as well.
- **Its own hidden window station**, tied to the job's logon session, so
  programs that load user32 start normally and cannot see SYSTEM's.

Without `-user`, `-allow-privileged` runs jobs as SYSTEM, which gives every
allowed peer complete control of the machine. Prefer `-user`.

**No scheduling, queueing or retries.** A job runs now or fails now.

### Choosing where to run

`-idle` ranks machines that accept your work by load, breaking ties on free
memory — a machine at 5% CPU with no RAM left is not actually available. The
figures come from the network map, so they can be a minute or two old.

---

## Publishing a local-only service

Suppose Postgres is on a field unit, listening on `127.0.0.1:5432`. You want a
colleague to reach it. The usual answer is to rebind it to `0.0.0.0`, which
exposes it to the entire LAN.

Instead:

```bash
locnet share add pg :5432 -on 15432 -allow workstation
```

Now `100.100.0.2:15432` reaches it — but only from the tunnel, and only from
`workstation`. Every accepted connection is checked against the access list
before anything is dialled. Postgres itself never changes its binding.

`-on` sets the overlay port; leave it off and the local port is reused.

---

## Seeing machine load

`locnet peers` and the console show CPU load, memory and free disk for each
machine, so you can tell which one is busy before you send it work — or notice
that a field unit's disk is filling up before it stops recording.

```
PEER     ADDRESS      OS       PATH    CPU        FREE DISK  SERVICES      SHARES
unit-01  100.100.0.2  windows  direct  34% of 8   210G/931G  rdp,vnc,http  archive
unit-02   100.100.0.3  windows  relay   91% of 4   18G/465G   rdp,ssh       data,pg
```

Every field is best-effort and varies by platform. Linux reports everything.
macOS does not expose a free-memory figure that means the same thing, so that
column is blank there rather than approximated. Windows reports no load
average, so CPU is blank.

Stats are folded into the network map rather than pushed separately, and they
only trigger an update when they move materially — load by more than 10 points,
memory by 5, disk by 2. Without that filter, every machine reporting its load
every thirty seconds would wake every long poll in the network, forever, for
nothing.

Because of that rounding, a peer's stats can be a minute or two old. That is a
deliberate trade: a fleet that is quiet when nothing is happening.

---

## What this does not do

- **No clipboard or audio forwarding.** The browser viewer is pixels, keyboard
  and mouse; anything richer is whatever your RDP or VNC client does.
- **No screen capture on Wayland.** See [DESKTOP.md](DESKTOP.md).
- **No sharing to non-members.** Everything here is inside the tunnel by
  construction; there is no public link to hand out.
- **No per-directory permissions inside a share.** The unit of access control
  is the share.
- **No bandwidth limits or quotas.**
- **Uploads are capped at 8 GiB per file** and there is no resume.

Waking a machine that is off *is* possible — `locnet wake <peer>` asks a peer on
that machine's subnet to broadcast a magic packet. See
[OPERATIONS.md](OPERATIONS.md).

---

## Building something on top

`locnet status -json` emits the whole picture — peers, paths, latencies,
services, shares, load — which is enough to drive a fleet dashboard without
touching LocNet's internals:

```bash
locnet status -json | jq '.peers[] | select(.stats.disk_free_gb < 50) | .name'
```

The share server is plain HTTP on `<overlay-ip>:8421`, so anything that can
make an HTTP request from inside the tunnel can read a share it has been
granted. See [PROTOCOL.md](PROTOCOL.md).
