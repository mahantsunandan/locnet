# Changes

Newest first. Every change to the code adds an entry here, under the version
it ships in (the `VERSION` file).

## 0.10.4 — October 2026

### New

- **The control plane is encrypted.** Agents reach the hub over TLS 1.3 whose
  certificate key is the hub's own identity key, and accept it only if it
  hashes to the fingerprint in their join code — no certificate authority, no
  Let's Encrypt, nothing to renew. Join codes minted through the API, every
  machine's endpoints and LAN addresses, queue jobs and their output, and a
  standby's copy of the hub's signing key no longer cross the network
  readable. The hub serves TLS and plain HTTP on the same port, so machines can
  be upgraded in any order: older agents keep working in plain HTTP, newer ones
  switch to TLS by themselves and — once a join code, a signed netmap or a
  working handshake has told them the hub does TLS — never fall back.
  `locnet-hub nodes` and the hub's log name machines still using plain HTTP;
  `locnet-hub serve -require-tls` (on Linux `LOCNET_HUB_FLAGS=-require-tls` in
  `/etc/locnet/hub.env`) then refuses it. `locnet doctor` and the console say
  whether a machine's control plane is encrypted.
- **The standby copies over pinned TLS too.** `locnet-hub serve -follow` pins
  the primary's fingerprint (`-follow-fingerprint`, printed by the new
  `locnet-hub fingerprint`; a standby that already holds a copy pins that),
  sends the admin token only after the handshake, never falls back to plain
  HTTP, and refuses a snapshot of any other hub. The primary never sends the
  snapshot over plain HTTP to another machine. Upgrade the primary first.

- **Peers confirm each other's services.** Every machine now tries the
  services its peers offer that nobody has confirmed, and shows the ones it
  reached without `?`. A machine under a one-way policy — allowed to open no
  connections — could never ask anyone to confirm its own, so its SSH, SMB,
  RDP and VNC showed `?` everywhere forever, even while working.
- **Signed requests are accepted once.** Agents add a nonce to every signed
  request, and the hub refuses a signature it has already seen on anything
  that changes state. Over plain HTTP, which agents before this release still
  use, someone who could watch the traffic could otherwise resend an
  administrator's remove, approve or cancel, or a queue submission, for five
  minutes.

### Fixed

- **The queue ignored device approval.** A machine waiting to be admitted
  could submit, list and cancel jobs, and — by allowing `"*"` in its own
  compute setting — be handed anybody's job and report any result. It now
  takes no part until approved.
- **Any machine could cancel anyone's job.** Only the submitter or an
  administrator can now.
- **The queue showed every job's environment and output to every machine.**
  Values and output are now shown only to the submitter, the machine that ran
  the job, and administrators.
- **A read-write share could be turned against its own machine.** Uploads used
  a predictable temporary name opened with truncation, as root; a local user
  able to write in the share's folder could plant a symlink there and have the
  next upload overwrite any file. Uploads now use a random, exclusive name, and
  all share reads and writes go through `os.Root`, which cannot leave the
  share.
- **Downloaded file names with quotes broke the download header.**
- **WebShare's rate limit counted IPv6 visitors per address**, so one
  connection could rotate through its /64. It now counts the /64.

## 0.10.3 — October 2026

### New

- **WebShare** — publish one web app on one machine to the internet at
  `https://<site>.<domain>`, through the hub: `locnet webshare add <site>
  <port>`, approval with `locnet admin webshare approve` or the console, the
  domain and a DuckDNS token set with `locnet-hub webshare domain`. The hub
  gets Let's Encrypt certificates itself, keeps the DuckDNS name pointing at
  the house, rate-limits each visitor, and passes requests through the tunnel
  to that one port. The hub's service gains `CAP_NET_BIND_SERVICE` and opens
  80/443 only once a domain is set.
- **Switching single connections on and off** — `locnet admin access
  [block|allow <from> <to> service…]` and a who-may-connect-to-whom table on
  the console's Network page. Policies gain **blocks**, which always win over
  rules. Services by name: ssh, vnc, rdp, smb, locnet.
- **Windows compute as a normal account** — `locnet compute enable -user
  <account>` on Windows runs jobs as that account through an S4U logon, with no
  password held; an administrator's token is reduced to its unelevated form;
  each job gets its own window station and a job object that takes its whole
  process tree down at the deadline.
- **Password-free VNC on Windows** — `locnet setup -install` puts an installed
  TightVNC on loopback behind the `screen` share, as on Linux.
- **Documentation in the console** — a Docs page with every document,
  searchable, compiled into the program. New: GUIDE.md, COMMANDS.md, this
  file; CONTRIBUTING.md for working on the code.

### Fixed

- **One-way policies opened the reverse direction completely.** A pair that
  may reach no ports was sent as an empty list, which agents read as "every
  port". It is now sent as port 0 only, which agents of any version enforce.
- **The packet filter dropped replies.** It is now stateful: connections this
  machine opens to a restricted peer are remembered and their replies let in.
- **Windows: peers could not reach SSH or the share port.** The tunnel adapter
  was a new "Public" network on every start. It now has a fixed identity, is
  marked Private, and locnetd keeps a firewall rule for itself scoped to the
  overlay. `locnet setup` checks a firewall rule's profile, not just that it
  exists.
- **Windows: the share server never started** — it bound before duplicate
  address detection finished. DAD is off on the tunnel and the agent waits for
  the address.
- **Windows: no log at all.** The service now writes
  `C:\ProgramData\LocNet\logs\locnetd.log`.
- **Windows: the tunnel stayed down after a reboot** — adapter creation fails
  while Windows is still starting, and the agent tried once. It now retries
  with backoff until it works (on every platform).
- **Windows: re-running install.ps1 failed** because it copied over the running
  service. It now stops the service first.
- **Windows: `locnet ssh-keys` failed** when the account and the computer share
  a name — the lookup found the computer.
- **`locnet copy`, `fetch` and `job` failed against Windows** — they used rsync
  and POSIX shell commands. Windows targets now get scp and PowerShell.
- **`locnet doctor` blamed a firewall for the access policy**, and the
  background service check asked whichever peer came first. Both now ask a
  peer the policy lets in, and mark other ports "not checked".
- **`locnet setup` suggested a flag that does not exist** (`-port`) for editing
  the screen share; it is `-on`.
- A data race in the VNC tests.

## Earlier

Changes before 0.10.3 were not recorded here.
