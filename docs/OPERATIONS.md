# Running a fleet

The features that matter once a network stops being three computers and starts
being something an organisation depends on: who may reach what, what is wrong
right now, who joined, and who let them in.

---

## Access policy

By default every machine reaches every machine. For a fleet that is usually
wrong — a field unit has no business reaching another field unit, and a
laptop that gets stolen should not be a key to everything.

### The model

Named groups of machines, and a list of accept rules over them. There are no
deny rules and no ordering: traffic is permitted if some rule permits it, and
refused otherwise. Policies that read top-to-bottom with shadowing rules are
how people end up with a firewall nobody can explain.

```bash
locnet-hub policy example > policy.json
nano policy.json
locnet-hub policy set policy.json
```

```json
{
  "groups": {
    "field-units":   ["unit-01", "unit-02", "unit-03", "unit-04"],
    "operators":  ["workstation", "laptop"],
    "monitoring": ["collector"]
  },
  "rules": [
    {
      "src": ["operators"], "dst": ["field-units"], "ports": ["*"],
      "comment": "operators get full access to every field unit"
    },
    {
      "src": ["monitoring"], "dst": ["field-units"], "ports": ["8421"],
      "comment": "the collector may read shares and nothing else"
    },
    {
      "src": ["operators"], "dst": ["operators"],
      "comment": "operators can reach each other"
    }
  ]
}
```

`locnet-hub policy edit` opens the current policy in `$EDITOR` and applies it on
save, validating first — a syntax error changes nothing.

Groups may contain other groups. A name that is not a group is treated as a
machine name, so you can write a policy before the machine joins.

### How it is enforced

Two mechanisms, and the difference matters when you are reasoning about what an
attacker can do.

**Machine-level rules are enforced by omission.** Note what the example above
does *not* contain: any rule between two field-units. They therefore never appear
in each other's network map — no map entry means no WireGuard peer, no key
exchange, and no path. The isolation is a property of the cryptography, not of
a check somewhere that could be skipped. A field unit cannot even enumerate the
other field-units.

**Port-level rules are enforced by a packet filter** in the agent, sitting
between WireGuard and the kernel, because WireGuard's allowed-IPs cannot
express a port. The hub resolves the policy into a per-peer port list and sends
each node only the rules about peers it can see.

**Rules are one-way, and replies are not connections.** A rule from A to B
lets A *start* connections to B. If no rule goes the other way, B is still in
A's map — the tunnel has to exist — but B may reach no port on A, and A's
filter lets B's packets in only as replies to connections A opened. So to give
a machine access to others without giving them access back:

```json
{ "groups": { "home": ["workstation", "server"] },
  "rules":  [ { "src": ["home"], "dst": ["*"], "comment": "home reaches everything; laptop reaches nothing" } ] }
```

### Switching single connections on and off

Rules are for the shape of a network. For "winpc-01 may not SSH to hubpc",
from any administrator machine:

```bash
locnet admin access                               # who may connect to whom
locnet admin access block winpc-01 hubpc ssh vnc
locnet admin access allow winpc-01 hubpc vnc
locnet admin access block winpc-01 linuxbox        # no service named: every port
```

The console's **Network** page shows the same table — one row per machine
connecting, one column per machine connected to — and clicking a cell gives a
switch per service. Services are `ssh` 22, `vnc` 5900, `rdp` 3389, `smb` 445
and `locnet` 8421 (LocNet's files, compute and shares, which share one port),
or any port number or range.

Both act on the policy, and only on the parts written for that one pair:

- **block** takes the ports out of any rule written for exactly that pair, and
  records a *block* for them. Blocks are a second list in the policy
  (`"blocks"`, same shape as rules) and always win over rules, whatever their
  order — so a block survives a group rule added later.
- **allow** removes blocks written for exactly that pair, and adds a rule for
  the pair if nothing grants the ports yet. A block you wrote by hand for a
  group or `*` is left alone, and allow says so instead of going around it.

Every change is checked like a whole policy, applied within seconds, and kept
in the audit log under the machine that made it (`locnet admin audit`). Each
machine still decides for itself whether it shares files or runs jobs at all;
the hub decides who may connect.

That second mechanism is weaker in kind: it runs on the destination machine, so
root there can disable it. Root on the destination already means the
destination is lost, but it is not the same guarantee as the first.

Two more limits worth knowing:

- **Inbound only.** A machine is protected from what reaches it, not restrained
  in what it sends.
- **IPv4 only.** The overlay is IPv4, so this matters only if you add IPv6
  addressing yourself.
- **ICMP is never filtered by port rules.** A policy that blocked ping while
  permitting SSH would be a miserable thing to debug.

### Checking your work

```bash
locnet-hub policy          # the current rules, rendered
locnet peers               # from a machine: who it can actually see
```

If a peer vanished after a policy change, that is the policy working. The hub
refuses a policy that would isolate *every* machine from every other, but it
will happily isolate one — including the one you are administering from.

---

## Publishing a site to the internet (WebShare)

WebShare is LocNet's counterpart to Tailscale Funnel: one web service on one
machine, reachable by anyone at `https://<site>.<your domain>`, with the hub
as the front door. Visitors see the hub's public address; the machine itself
stays unreachable from the internet, and only the one port is published.

**One-time setup, on the hub machine.** You need a name that points at your
house. Without a domain of your own, a free dynamic DNS name is enough —
for example at [duckdns.org](https://www.duckdns.org): sign in, pick a name,
and copy the token it shows. The name stays fixed; the hub keeps it pointing
at your current home address. Then:

```bash
sudo locnet-hub webshare domain yourname.duckdns.org -duckdns-token <token> -accept-tos
```

`-accept-tos` is your agreement to Let's Encrypt's subscriber agreement
(https://letsencrypt.org/repository/), which issues the certificates. The
token is kept in the hub's state file and is never sent to any other machine
or shown by the console. Within 15 seconds the hub listens on 80 and 443.
Forward both from the router to the hub machine, and let them through its
firewall — on Fedora:

```bash
sudo firewall-cmd --permanent --add-service=http --add-service=https && sudo firewall-cmd --reload
```

**Publishing a site, on the machine serving it:**

```bash
locnet webshare add myapp 3000        # the app on localhost:3000
locnet webshare                        # its state and address
```

and then, by an administrator (CLI, or the Network page of the console):

```bash
locnet admin webshare                  # every site and its state
locnet admin webshare approve myapp
locnet admin webshare off myapp        # stop answering, keep the approval
locnet admin webshare remove myapp     # forget the approval
```

The first visit to a newly approved site takes a few seconds while the hub
gets its certificate.

**What has to be true for a site to answer**, and the state it shows when
something is not:

| State | Meaning |
|---|---|
| `live` | it answers |
| `waiting for approval` | the machine asked; nobody has approved it |
| `turned off on the hub` | approved, then turned off |
| `name taken by another machine` | approved for a different machine |
| `machine offline` | the machine is not connected |
| `no domain set on the hub` | WebShare is not configured |
| `the access policy keeps the hub machine out of its port` | the access table blocks the hub machine from that machine |

**What is and is not exposed.**

- Only HTTPS, on 443; port 80 answers only certificate challenges and
  redirects to HTTPS. The hub talks to the site over the tunnel, so the
  traffic is encrypted end to end except inside the hub machine itself.
- Only approved, live names get certificates or answers. Any other name under
  the domain gets no certificate — the HTTPS handshake fails — and a plain
  404 over HTTP, so guessing names finds nothing and cannot make the hub spend
  its certificate allowance on made-up names.
- **A site's name is public from its first certificate.** Every certificate
  is recorded in the public Certificate Transparency logs, and scanners watch
  them: within minutes of the first one, strangers' machines try the name. A
  site must protect itself (a login, if it has anything private) and never
  rely on its name being unknown. The hub does not log these refused
  handshakes, which would otherwise fill its journal.
- Each visitor is limited to 20 requests a second (bursts of 100), counted per
  IPv4 address and per IPv6 /64.
  Request counts and the last failure per site are in `locnet admin webshare`;
  individual requests are not logged.
- The site sees the visitor's address in `X-Forwarded-For`, and its public
  name in `Host`.
- Visitors on your home network cannot use the public name: most routers do
  not loop traffic for their own public address back in. Use the site on its
  machine directly, or through LocNet, from home.
- The connection is your home internet connection: its upload speed is the
  site's speed, and the hub machine must be on.

To turn WebShare off entirely: `sudo locnet-hub webshare domain -off`.

## Device approval

Off by default, because it is the right setting for an organisation and the
wrong one for a person with three computers.

```bash
locnet-hub health set -require-approval=true
```

A machine that joins now completes registration and holds an address, but
appears in nobody's network map until admitted:

```bash
locnet-hub nodes
# NAME     ADDRESS    OS       STATUS   GROUPS  DISK        LAST SEEN
# unit-01  10.99.0.7  windows  WAITING  -       210G free   just now

locnet-hub approve unit-01
```

Turning it on leaves existing machines approved — it governs what happens next,
not a retroactive audit of what already joined.

This pairs well with a reusable join code: bake one into your provisioning
image, and every machine that comes up still needs a human to admit it.

---

## Administering from your own machine

Everything above uses `locnet-hub`, which reads the admin token from the hub's
state file and so runs only on the hub machine, as root. That is the right
default and a poor everyday tool: the machine you sit at is rarely the hub.

A member machine can be made an administrator. On the hub machine, once:

```bash
sudo locnet-hub admins add workstation
```

From then on, on `workstation`:

```bash
locnet invite                    # a join code for a new machine
locnet admin                     # every machine, as the hub sees it
locnet admin approve unit-01     # admit one that is waiting
locnet admin remove old-laptop   # take one off the network
locnet admin invites             # join codes, and which still work
locnet admin revoke <id>
locnet admin audit
```

— or the **Network** page of `locnet console`, which does the same with
buttons. The requests are signed with that machine's own identity key, the same
signature it already puts on every netmap poll, so there is no new secret to
copy around; the hub checks it against its list and records in the audit log
which machine did what. The machine running the hub is always an
administrator. `locnet-hub admins remove workstation` withdraws the right at
once, and removing a machine from the network removes it from the list too.

---

## Alerts

A mesh VPN tells you a machine is reachable. It does not tell you that the disk
on a machine that records overnight has four gigabytes left. Those are
different questions, and operators need both — usually at 2am.

```bash
locnet-hub alerts
```

```
!!  critical  disk      unit-02 has 12 GB left (3% of 465 GB)
!!  critical  offline   unit-04 has been out of contact for 4h12m
!   warn      load      unit-02 is at 94% CPU across 4 cores
```

### Thresholds

```bash
locnet-hub health
locnet-hub health set -disk-warn 15 -disk-critical 5 -offline-after 30m
locnet-hub health set -mute laptop,spare-desktop
```

Defaults are deliberately loose — 10% disk to warn, 3% to alert, 30 minutes
offline. Thresholds that cry wolf get ignored, and an ignored alert is worse
than no alert.

Mute the machines that are legitimately off most of the time. A laptop shut for
the night is not an incident.

### Wiring it into monitoring

```bash
locnet-hub alerts -quiet
```

Prints nothing when all is well, exits 1 when it is not. That is a complete
Nagios/Icinga check, or a cron line:

```bash
*/15 * * * * /usr/local/bin/locnet-hub alerts -quiet || mail -s "LocNet" you@example.org
```

`-json` gives machine-readable output for anything more involved.

### Where alerts are computed

Both on the hub and on every machine, from the same rules. The thresholds ride
in the network map — they are configuration, not a secret — so `locnet status`
and the console show alerts for the peers they can see without needing an admin
token.

Alerts are derived from current state, never stored. A stored alert has to be
cleared, and something has to decide when, which is a second source of truth
and a second thing to get wrong. Deriving them means an alert disappears
exactly when the condition does.

One consequence: a peer's stats can be a minute or two old, because a report
only updates the network map when something moves materially — load by more
than 10 points, disk by 2. Without that filter, every machine reporting every
thirty seconds would wake every long poll in the network, forever, for nothing.

---

## Audit log

```bash
locnet-hub audit -n 20
```

```
2026-07-31 16:14:05  admin        token.create     "unit-01", 1 use(s)
2026-07-31 16:15:22  unit-01      node.join        unit-01 (windows) as 10.99.0.7 — awaiting approval
2026-07-31 16:16:01  admin        node.approve     unit-01 (10.99.0.7)
2026-07-31 16:20:44  admin        policy.set       3 group(s), 3 rule(s)
```

Membership and rule changes only. **Connections between peers are deliberately
not recorded** — they never touch the hub, and a log claiming to cover them
would be lying the moment two machines went direct. If you need connection
logging, it belongs on the machines being connected to: `sshd` and RDP both log
sessions already.

The in-state log keeps the most recent 500 entries so that `locnet-hub audit`
works on a machine with no log infrastructure at all. Every entry is also
printed to the hub's stdout as it happens, so tail that into your collector for
real retention.

---

## A second hub

The hub is a single point of failure for *joining and finding*, not for
traffic. While it is down, tunnels that already exist keep working — every node
caches the last map it was given. What stops is anything that needs the
register: a new machine joining, a machine that moved being found again, a
policy change reaching anyone.

A standby fixes that. It is a warm spare, not a cluster.

```bash
# on the primary: its fingerprint, the same one every join code carries
locnet-hub fingerprint

# on the spare machine
locnet-hub serve -follow hub.example.org:8420 \
                 -follow-token "$(cat /var/lib/locnet-hub/admin-token)" \
                 -follow-fingerprint <the primary's fingerprint> \
                 -listen :8420

# on the primary, so every node learns where the spare is
locnet-hub serve -advertise hub.example.org:8420 -standby spare.example.org:8420
```

The spare copies the primary's whole register every minute, over TLS pinned
to the primary's fingerprint, and **serves nothing**. It sends the admin token
only after the handshake has proved it is talking to that hub, never falls back
to plain HTTP, and refuses a snapshot of any other hub. `-follow-fingerprint` is
needed only the first time: a spare that already holds a copy pins the key in
it. Nodes learn its address from the signed network map, so machines
that joined a year before the spare existed pick it up without anyone touching
them.

When the primary is really gone:

```bash
# on the spare
locnet-hub promote
```

The standby takes over within a few seconds. Nodes already have its address in
their candidate list and try it when the primary stops answering; the maps it
signs verify against the fingerprint they already trust, because it is signing
with the same identity key.

Two things about this are worth saying plainly rather than burying.

**The spare holds a copy of the hub's signing key.** That is what makes
failover invisible to every node — the alternative, a separate identity per
hub, means every join code and every node's pinned fingerprint has to carry
both. So the spare is exactly as sensitive as the primary and belongs on a
machine you trust the same amount. `-follow-token` is the primary's admin
token, and the snapshot endpoint it reads is behind that token for the same
reason.

**Promotion is manual.** Automatic failover sounds better and is worse. Two
hubs serving the same identity with diverging registers is a worse outcome than
no hub at all: both sign maps, nodes believe whichever answers first, and the
two halves of the network stop agreeing about who is a member — a disagreement
that is invisible until something stops working. A human deciding "the primary
is really gone" costs a minute and removes the failure mode entirely.

What a standby does **not** do: it is not a second relay. Nodes that cannot
reach each other directly still go through whichever hub is serving, so
promoting a spare in another country will make relayed pairs slower. And it
does not load-balance — exactly one hub is live at a time, by design.

---

## Running work across the fleet

`locnet queue` distributes jobs to whichever machines are free, using the same
per-machine consent as `locnet run`. See [QUEUE.md](QUEUE.md).

```bash
locnet compute enable -allow workstation -user builder   # on each worker
locnet queue submit -n 240 -cpus 4 -- /srv/render.sh     # from your desk
locnet queue workers                                      # who will take it
```

---

## Waking a machine that is off

Every node reports its hardware addresses and the subnets it sits on while it
is awake. That is enough for a peer on the same piece of Ethernet to wake it
later:

```bash
locnet wake unit-02
locnet wake unit-02 -wait 3m      # and block until it is back
```

LocNet picks the sender: this machine if it is on the right subnet, otherwise a
peer that is. A magic packet is a broadcast and does not cross a router, so if
nothing on that subnet is up, the command says so instead of pretending.

Wake-on-LAN still has to be enabled in the target's firmware and network
adapter settings. Nothing here can check that from the outside.

---

## A worked setup

Fourteen Windows measurement field-units, two operator workfield-units, one collector
that pulls data nightly.

```bash
# 1. Nothing joins without a human saying so.
locnet-hub health set -require-approval=true

# 2. Alert thresholds suited to machines that record continuously.
locnet-hub health set -disk-warn 20 -disk-critical 8 -offline-after 20m

# 3. Field units cannot reach each other; the collector reads shares only.
cat > policy.json <<'JSON'
{
  "groups": {
    "field-units":  ["unit-01","unit-02","unit-03","unit-04"],
    "operators": ["workstation","laptop"]
  },
  "rules": [
    {"src":["operators"],"dst":["field-units"],"ports":["*"]},
    {"src":["collector"],"dst":["field-units"],"ports":["8421"]},
    {"src":["operators"],"dst":["operators"]},
    {"src":["operators"],"dst":["collector"]}
  ]
}
JSON
locnet-hub policy set policy.json

# 4. One reusable code for provisioning; approval is the real gate.
locnet-hub invite -label "provisioning image" -uses -1 -ttl ""

# 5. On each field unit, once joined:
#      locnet share add data D:\measurements -allow collector,workstation
```

What this buys you: a compromised field unit reaches nothing but the hub. The
collector can read data and cannot open a desktop. Every new machine is
visible in `locnet-hub nodes` as `WAITING` before it can do anything, and
`locnet-hub alerts -quiet` in cron tells you when a disk is filling before it
stops recording.
