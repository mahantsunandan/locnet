# LocNet: start here

LocNet joins your computers into one private network — wherever each one is,
behind whatever router — and then makes them easy to use from each other:
shells, screens, files, commands on many machines at once, borrowed compute,
a job queue, and publishing a web app to the internet. This page walks through
every feature in the order you would meet them, with the commands; each
section links to the document that explains it fully. Every command is in
[COMMANDS.md](COMMANDS.md).

---

## The pieces

| | Runs on | Does |
|---|---|---|
| **locnet-hub** | one always-on machine | keeps the list of members and their addresses, signs the network map everyone follows, relays traffic when two machines cannot reach each other directly, holds the job queue, and serves WebShare sites |
| **locnetd** | every machine | the agent: a WireGuard tunnel to every peer it is allowed to see, the port filter, shares, compute |
| **locnet** | every machine | the command line, and `locnet console`, the web interface |

Every machine gets a fixed address in the overlay (e.g. `10.99.0.3`) that
stays the same wherever it is. Traffic between two machines goes directly
whenever their networks allow it, and through the hub's relay otherwise —
encrypted end to end either way, with the hub unable to read it.

How it works inside: [ARCHITECTURE.md](ARCHITECTURE.md). The wire formats:
[PROTOCOL.md](PROTOCOL.md). What is and is not protected:
[SECURITY.md](SECURITY.md).

---

## Joining a machine

On an administrator machine, or the hub:

```bash
locnet invite -label "new laptop"          # prints a join code
```

On the new machine, from an unpacked release:

```bash
sudo ./install.sh --join <code>            # Linux, macOS
.\install.ps1 -Join <code>                 # Windows, elevated PowerShell
```

That installs the agent as a service, joins, installs an SSH server and a
screen server if missing, and has a peer confirm it can get in. Re-running the
installer later upgrades in place. See [INSTALL.md](INSTALL.md).

Check it:

```bash
locnet status          # this machine and every peer, direct or relayed
locnet doctor          # the usual reasons a network will not form, checked
```

---

## Using the other machines

```bash
locnet ssh winpc-01        # a shell, in your own terminal
locnet vnc hubpc           # its screen, in your VNC viewer
locnet rdp winpc-01        # a Windows desktop, in your RDP client
locnet console             # all of it in the browser
```

LocNet opens the clients you already have; it does not draw screens itself.
Before opening a viewer it checks that the far server will let you in.

- **SSH without passwords:** `locnet ssh-keys publish` here, `locnet ssh-keys
  accept <this machine>` there. `locnet login <peer> <account>` when the
  account name differs (a Windows machine, for instance).
- **Screens:** RDP shows a Windows machine's real screen. VNC shows a Linux
  machine's virtual desktop, a Mac's real screen, or — with TightVNC and
  `locnet setup -install` — a Windows machine's real screen, with no VNC
  password. See [DESKTOP.md](DESKTOP.md).
- **Missing servers:** `locnet setup` lists what a machine needs to be
  reachable; `-install` installs it after showing the exact commands.

---

## Files and services

```bash
locnet share add data ~/data -allow hubpc          # a read-only folder share
locnet files winpc-01                              # shares you may use there
locnet files winpc-01 data report.pdf -get         # download one
locnet share add pg :5432 -allow linuxbox          # a local-only service, on the mesh
```

A share does nothing until it names who may use it. The console's **Files**
page is a two-pane copy between this machine and any other, over SSH. See
[SHARING.md](SHARING.md).

---

## Many machines at once

```bash
locnet exec "df -h /" -on all
locnet copy build/ -to hubpc,winpc-01 -dest ~/deploy
locnet fetch ~/results.csv -from all -into ./collected
```

These use your SSH account on each machine and never prompt; a machine
without a key fails at once with the fix. Windows machines get `scp` instead of
rsync and PowerShell instead of a POSIX shell.

---

## Borrowing compute

```bash
locnet best                           # which machine is most free, and why
locnet job -- python train.py         # send this folder, run, bring results back
locnet job -gpu -vram 8 -- python train.py
```

Or LocNet's own channel, with no SSH account — opt-in on the machine that
runs the work, and no shell:

```bash
locnet compute enable -allow linuxbox,hubpc -user winpc-01   # on the worker
locnet run winpc-01 -- whoami                                 # from elsewhere
```

On Windows, `-user` runs jobs as that account without LocNet holding its
password, and an administrator account runs unelevated. See
[COMPUTE.md](COMPUTE.md) and [SHARING.md](SHARING.md#sharing-compute).

## A queue for the whole fleet

```bash
locnet queue submit -cpus 8 -n 20 -- ./render.sh
locnet queue                     # waiting and running
locnet queue log <id>
```

The hub holds the jobs; machines that have agreed (their compute setting
allows you) take them when free. See [QUEUE.md](QUEUE.md).

---

## Who may reach what

By default every machine reaches every machine. The hub's **policy** narrows
that: machines no rule connects never even learn each other exist, and port
rules are enforced by a filter in each agent.

The everyday tool is the **access table** — from any administrator machine,
or the console's Network page:

```bash
locnet admin access                               # who may connect to whom
locnet admin access block winpc-01 hubpc ssh vnc
locnet admin access allow winpc-01 hubpc vnc
```

Access is one-way: blocking A from B leaves B able to reach A, with replies
flowing back. Every change is in the audit log. See
[OPERATIONS.md](OPERATIONS.md#access-policy).

---

## Publishing a web app (WebShare)

One web app on one machine, reachable by anyone at
`https://<site>.<your domain>`, through the hub:

```bash
locnet webshare add myapp 3000            # on the machine running it
locnet admin webshare approve myapp       # by an administrator
```

The hub gets the certificate, keeps a free dynamic DNS name pointing at your
house, and passes visitors through the tunnel to that one port — nothing else
is exposed. Setup (once, on the hub) and everything it does and does not
protect: [OPERATIONS.md](OPERATIONS.md#publishing-a-site-to-the-internet-webshare).

---

## Running the network

From an administrator machine (`sudo locnet-hub admins add <machine>` on the
hub makes one), or the console's **Network** page:

```bash
locnet admin                     # every machine, as the hub sees it
locnet admin approve <machine>   # when new machines need approval
locnet admin remove <machine>    # a machine that was reset or lost
locnet admin audit               # who joined, left and changed what
```

On the hub: alerts for low disk and silent machines, a standby hub, health
thresholds, device approval. See [OPERATIONS.md](OPERATIONS.md).

---

## Windows

A Windows machine is a full member, with a few things to know:

- Install from an elevated PowerShell; re-running `install.ps1` upgrades.
- The agent marks its adapter as a Private network and lets peers in through
  the firewall from the overlay only. Its log is
  `C:\ProgramData\LocNet\logs\locnetd.log`.
- After a reboot the tunnel comes back by itself, retrying while Windows
  finishes starting.
- Over SSH its shell is usually PowerShell, so `locnet exec` commands are
  PowerShell commands there.

---

## When something is wrong

| Symptom | Look at |
|---|---|
| a peer stays `connecting` or `relay` | `locnet doctor`; [INSTALL.md](INSTALL.md#troubleshooting) |
| a service shows `?` or `!` in `locnet peers` | `locnet doctor` on that machine |
| a viewer opens and closes | the message `locnet vnc`/`rdp` prints; [DESKTOP.md](DESKTOP.md#when-it-does-not-work) |
| a machine reaches nothing after a policy change | `locnet admin access` |
| a WebShare site does not answer | its state in `locnet admin webshare` |
| the agent on Windows | `C:\ProgramData\LocNet\logs\locnetd.log` |
| the agent on Linux | `sudo journalctl -u locnetd -n 50` |

What changed recently: [CHANGELOG.md](CHANGELOG.md).
