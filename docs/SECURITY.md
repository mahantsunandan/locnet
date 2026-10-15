# Security model

What LocNet protects, what it does not, and what an attacker in each position
can actually do.

This is version 0.1 of a project written to be read and understood. It has not
been audited. Read this document before putting it anywhere that matters.

---

## What is protected

**Traffic between nodes.** WireGuard, with keys generated on each machine that
never leave it. The hub cannot decrypt tunnel traffic, and neither can the
relay, because neither ever holds the material.

**Network map integrity.** Every map is Ed25519-signed by the hub and verified
against a fingerprint that arrived in the join code. Nobody who is not the hub
can add a peer, change a peer's key, or move a peer's address.

**The control plane in transit.** Since 0.10.4 agents reach the hub over TLS
1.3 whose certificate key *is* the hub's identity key, and accept the handshake
only if that key hashes to the fingerprint their join code carried — no CA, no
Let's Encrypt, nothing to renew. Join codes, every machine's endpoints and LAN
addresses, the queue's environments and output, and a standby's copy of the
hub are no longer readable on the wire. Once an agent knows the hub speaks TLS
(the join code says so, a verified netmap says so, or one pinned handshake
worked) it never talks plain HTTP to it again, so nobody on the path can switch
the encryption off by pretending the hub is too old for it. Details in
[PROTOCOL.md](PROTOCOL.md#transport).

**Control-plane requests.** Signed with the node's identity key over method,
path, timestamp and body digest. A captured request cannot be replayed against
a different endpoint, goes stale after five minutes, and a request that changes
anything is accepted once: agents make each body unique with a nonce, and the
hub refuses a signature it has already seen.

**Relay bindings.** Signed, and cross-checked against the hub's records so a
member cannot bind another member's WireGuard key and intercept its relayed
traffic.

**Local control channel.** A mode-0660 Unix socket in a root-owned directory,
or on Windows a loopback port with a token in a 0600 file. Controlling the
network requires privileged access to the machine.

**Shares.** Enforced by the machine that owns the resource, never by the hub.
The authenticator is the overlay source address, which inside the tunnel is a
WireGuard-verified identity rather than a guess. Shares deny by default, are
read-only by default, and a peer is never told the name of a share it may not
use. Path traversal and symlink escape out of a share are both refused and
both covered by tests.

**The console.** Bound to `127.0.0.1` with a token that is new every run and
carried in a header. Cross-origin pages cannot set that header without a
preflight, and the server refuses preflights.

**Access policy.** Machine-level rules are enforced by omission from the signed
network map, so an isolated pair has no key material for each other at all.
Port-level rules are enforced by a packet filter between WireGuard and the
kernel on the receiving machine.

**Audit log.** The hub records joins, removals, approvals, token issuance and
policy changes. Connections between peers are deliberately *not* logged: they
never touch the hub, and a log claiming to cover them would be lying the moment
two machines went direct.

---

## What is not protected

### Agents older than 0.10.4 still speak plain HTTP

The hub serves TLS and plain HTTP on the same port so that machines can be
upgraded in any order. Until every agent is 0.10.4 or later, the older ones
talk in the clear, and a passive observer on their path can read:

- every node's name, overlay address, OS, and public keys
- every node's endpoint addresses, which is roughly a map of where your
  machines physically are
- who is online and when
- join codes an administrator mints on that machine (`locnet admin invite`)

Nothing can be *forged* over plain HTTP — maps are signed, requests are signed
and accepted once — but it is not private. `locnet-hub nodes` lists the
machines still using it, and the hub logs each one the first time it is seen.
Once none are left, run the hub with `-require-tls`: plain HTTP is then refused
from every other machine (loopback and `/healthz` still answer).

The standby snapshot is the exception from the start: it holds the hub's
signing key, and the hub never sends it over plain HTTP to another machine,
whether or not `-require-tls` is set.

Two edges remain while plain HTTP is allowed:

- **A first join with a code minted before 0.10.4.** Such a code carries no
  TLS flag. A new agent still tries TLS first, but someone actively on the path
  could answer as an old plain-HTTP hub, and the agent would then send the join
  token in the clear. Codes minted from 0.10.4 on carry the flag and are never
  redeemed in plain HTTP. Mint fresh codes after upgrading the hub.
- **An agent that has never reached the hub over TLS** can be held on plain
  HTTP by the same attacker until a signed netmap reaches it — which tells it
  the hub speaks TLS, after which it refuses plain HTTP. Holding it there
  means blocking its netmaps, which an attacker on the path can do anyway.

A hub behind a TLS reverse proxy can still be advertised as
`https://hub.example.org:8420`; agents then check the proxy's certificate the
usual way instead of the pin. An explicit `http://` address is spoken to in
plain HTTP — that is the operator's choice, and it travels in the signed
netmap, so nobody else can make it.

### The default policy allows everything

A new network starts with one explicit rule: every machine may reach every
machine. That is a deliberate choice — a mesh that silently refuses the first
ping teaches people to distrust the tool before they have learned it — but it
means access control is opt-in. Set a policy before the network grows:

    locnet-hub policy example > policy.json
    locnet-hub policy set policy.json

### Rules allow, blocks refuse, and both act on who may *start* a connection

Traffic is permitted if some rule permits it and no block refuses it; blocks
always win, and order means nothing. `locnet admin access block|allow` and the
console's access table edit only the rules and blocks written for one pair, so
an exception can be carved out of a broad allow without rewriting it.

The packet filter that enforces port rules runs on the destination, on inbound
traffic, and is stateful: it remembers connections its own machine opened to a
restricted peer and lets their replies back in. That is what makes one-way
access work — A may reach B, B may reach nothing on A — and it is also its
limit: a machine is protected from what reaches it; it is not restrained in
what it sends. A compromised member can still attempt connections to anything
the policy lets it reach. Remembered connections expire after an hour idle
(TCP) or three minutes (UDP), and the table is capped at 65,536 entries.

Agents before 0.10.3 enforce "no ports" but do not remember connections, so a
one-way rule also cuts the allowed direction on them. Hubs before 0.10.3 sent
"no ports" as an empty list, which agents read as "every port" — a one-way
rule then opened the reverse direction completely. Run 0.10.3 or later
everywhere a one-way rule matters.

It is also IPv4-only. The overlay is IPv4, so this matters only if you add IPv6
addressing on top yourself.

### Machine-level and port-level rules are enforced differently

Machine-level isolation is strong: a peer the policy forbids is absent from the
network map, so there is no WireGuard peer and no key. Nothing to bypass.

Port-level rules are weaker in kind: they are a filter in the agent on that
machine. An attacker with root on the *destination* machine can disable it.
That is a smaller concern than it sounds — root on the destination already
means the destination is lost — but it is not the same guarantee.

### WebShare puts one service on the internet

A WebShare site is reachable by anyone. What limits the exposure:

- Three parties must agree — the machine asks (only someone at it can), an
  administrator approves the name on the hub, and the access policy lets the
  hub machine reach the site's port — and any of them can withdraw.
- Only HTTPS on 443 is served; port 80 answers certificate challenges and
  redirects. The hub passes requests to the one overlay port of the one share
  approved, which only the hub machine may use. Nothing else on the mesh is
  reachable from outside.
- Certificates are requested only for live, approved names, so a scanner
  guessing names under the domain gets a failed handshake and cannot spend the
  Let's Encrypt allowance. The names that do get certificates are public:
  Certificate Transparency logs list every one, and scanners arrive within
  minutes of issuance.
- Each visitor is rate limited (20 requests a second, bursts of 100), counted
  per IPv4 address and per IPv6 /64 — one IPv6 connection is handed a whole
  /64, and counting single addresses let a visitor rotate past the limit.

What it does not do: authenticate visitors (that is the site's job), filter
what the site serves, or protect against a flood larger than a home
connection. TLS ends on the hub machine; the request continues to the site's
machine inside WireGuard, so it is readable in the clear only on those two
machines. The router forwards 80 and 443 to the hub, and the house's public
address is in DNS. The DuckDNS token is stored in the hub's state file
(readable by the hub's service account only), is never sent to members or
shown by the API, and is kept out of logs.

### Compute on Windows runs under a token obtained without a password

`locnet compute enable -user <account>` on Windows has locnetd, which runs as
SYSTEM, log the account on with an S4U logon: a token for a local account by
name, with no password and no network credentials. An administrator account's
token is reduced to what UAC gives it at the desktop — Administrators
deny-only, admin privileges removed, medium integrity — unless
`-allow-privileged` is given. Each job gets a window station of its own and a
job object that is terminated, with every process in it, at the deadline.
Without `-user`, `-allow-privileged` runs jobs as SYSTEM.

### Everything names machines, and the hub names machines

A policy rule allows `"workstation"`. A share allows `"workstation"`. Both names
come from the netmap, which the hub signs.

A share allows `"workstation"`. That name comes from the netmap, which the hub
signs. A compromised hub could register a *new* machine and call it
`workstation`, and your share would let it in — the original `workstation` is
still there under a deduplicated name, but the access list matched on the
string.

This is a real consequence of trusting the hub for naming. Mitigations that
exist: turn on approval so a new machine reaches nothing until you admit it,
check `locnet-hub audit` for joins you did not expect, and prefer explicit
lists over `"*"` for anything sensitive.

    locnet-hub health set -require-approval=true

### Files shares run as the agent

`locnetd` runs as root, so a files share can serve anything the root user can
read, and a read-write share can write anywhere inside it as root. Share
directories that exist for the purpose, not `/` or a home directory.

Every read and write goes through Go's `os.Root`, which refuses to leave the
share at the moment the file is opened, so a symlink placed inside the share —
before or during a request — cannot redirect it. Uploads go to a random,
exclusively created temporary name. Before 0.10.4 the temporary name was
predictable and opened with truncation, so a local user who could write in a
read-write share's folder could plant a symlink there and have the next upload
overwrite any file on the machine as root.

### A shared screen is the most access anything here grants

`locnet desktop share` hands over a live view of a session somebody is already
logged in to, and with `-control` it hands over that session's keyboard and
mouse. That is more access than a files share and, in practice, more than
compute: compute runs one command as an account you chose, and a desktop is
already whoever is sitting there.

It is off by default, view-only when turned on, and controllable only with a
second explicit flag. There is no way to enable any of it remotely and the hub
cannot enable it. The access list is enforced by locnetd on the machine being
watched, exactly like a file share; the hub only says who exists.

The capture itself runs as the logged-in user in `locnet desktop serve`, not as
root in the daemon. That is a real reduction: the process that can read your
screen has your permissions and no more. It listens on loopback with a
per-run token that only locnetd is given, so nothing else on the machine — and
nothing on the network — can ask it for a frame.

Frames cross the network inside the tunnel like everything else. They are not
stored anywhere at either end.

### A standby hub is a second copy of the hub's key

`locnet-hub serve -follow` copies the primary's whole register, including its
identity key, so that the maps it signs after promotion verify against the
fingerprint every node already pinned. That is what makes failover invisible.

It also means a standby is exactly as sensitive as the primary, and that the
snapshot endpoint puts a signing key on the wire. It is behind the admin token
and belongs on a network you control. Do not run a standby on a machine you
would not run the hub on.

### A compromised hub is serious

The hub cannot read your traffic. It can:

- **add a node**, giving an attacker-controlled machine full access, because
  every member trusts a signed map
- **deny service** by refusing to serve maps or relay packets
- **learn the metadata above**, continuously
- **schedule jobs**, but only onto machines whose own compute access list
  already names the submitter — it cannot conscript a machine, and it cannot
  add itself to anyone's list

It cannot decrypt anything, past or future. WireGuard keys are generated on
each node and only public halves are ever sent.

Treat the hub as the most security-sensitive machine you have. The installer
runs it as an unprivileged user with a hardened systemd unit for this reason —
a bug in the hub should not become root on the machine.

### A stolen join code is a member

Anyone holding an unspent code can add a machine. The fingerprint stops them
redirecting the code to a hub of their own, but not from using it against
yours.

Mitigations that exist: use limits (`-uses 1`), expiry (`-ttl 24h`), and
revocation (`locnet-hub revoke`). Use them. Check `locnet-hub nodes` after
handing a code out.

### Nothing is protected against a compromised node

A node holds its own keys and a valid identity. An attacker with root on a
member machine has that machine's network access. Remove it from the hub
(`locnet-hub remove`) — its peers drop it within seconds.

Note that `locnet leave` does *not* remove the node record from the hub. That
is deliberate: a machine that has been stolen should not be able to erase its
own membership before you notice.

### Control-plane signatures outlive the connection

WireGuard rekeys and has forward secrecy for tunnel traffic, and so does the
control plane's TLS 1.3 (ephemeral key exchange): a recording of it cannot be
decrypted later, even with the hub's key. The signatures inside it are another
matter: anyone holding a recorded *plain-HTTP* request from an old agent can
check it against the node's public key forever. That proves who sent it; it
reveals nothing that was not already on the wire.

### The hub's identity key is also its TLS key

Using one Ed25519 key for both is safe because of what each signs. Netmaps are
JSON objects starting with `{`; a TLS 1.3 CertificateVerify signature covers 64
spaces, a context string and a transcript hash, which no netmap can be. TLS 1.2
is refused on both sides, because there the server signs the client's random
bytes first. The consequence to keep in mind is the existing one: whoever holds
`hub.json` is the hub, for TLS as for netmaps — guard it, and the standby that
copies it, accordingly.

### Denial of service

The hub does not rate-limit registration attempts. A public hub can be made to
do Ed25519 verifications and JSON parses by anyone who can reach it. Bodies are
capped at 64 KB and unauthenticated endpoints do little work, but there is no
real defence. Put the hub behind something that rate-limits if it is exposed to
the internet.

---

## Key handling

| Key | Where it lives | Mode |
|---|---|---|
| Node machine, WireGuard, disco | `node.json` in the state directory | 0600 in a 0700 directory |
| Hub identity, admin token | `hub.json` in the hub state directory | 0600, owned by `locnet-hub` |
| Desktop helper token | never on disk; generated per run, given to locnetd over the control socket | — |

A standby hub is the one deliberate exception to "never copy a key". See the
section above; it is a decision, not an oversight.

Neither file should ever be copied to another machine. A cloned `node.json`
means two machines fighting over one identity and one address.

Rotating a node's keys means `locnet leave` then rejoining with a fresh code —
the hub matches on the identity key, so a new key is a new node.

Rotating the **hub's** identity key invalidates every join code ever issued and
every node's pinned fingerprint. There is no supported path for this short of
rebuilding the network.

---

## Reporting

This is a personal project without a security team. Open an issue for anything
non-sensitive; for anything you would rather not publish, contact the
maintainer directly before disclosing.

---

## If you need better than this

Use [Headscale](https://github.com/juanfont/headscale) or
[NetBird](https://netbird.io). Both are mature, both have ACLs and SSO, both
have had far more eyes on them than this has. LocNet is worth running when
understanding your infrastructure completely is worth more to you than the
features and the audit history — which is a real trade-off, but it is a
trade-off, and you should make it deliberately.
