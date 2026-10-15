# Architecture

What LocNet is made of, and why each piece is shaped the way it is.

## The shape of the problem

WireGuard gives you an encrypted tunnel between two peers whose public keys and
IP addresses you already know. That last clause is the whole difficulty. In any
real network:

- addresses change — DHCP leases expire, laptops move between wifi and LTE
- most machines have no reachable address at all, only a NAT mapping that
  exists while traffic flows through it
- adding a machine means editing a config file on every other machine

Everything in LocNet exists to remove that clause. The result is that you
address a peer by *identity* and the system works out where that identity
currently lives.

## Components

```
   ┌────────────────────────────────────────────────────────────────┐
   │  locnet-hub                    always-on machine, unprivileged │
   │                                                                │
   │   store.go    members, addresses, join codes  →  hub.json      │
   │   server.go   HTTP: register, netmap long poll, admin          │
   │   relay.go    UDP: address discovery + packet forwarding       │
   │   webshare*   public HTTPS sites: certificates, proxy, DNS     │
   │               (TCP 80/443, only once a domain is set)          │
   └────────────────────────────────────────────────────────────────┘
                    ▲                              ▲
       signed netmap│ HTTP/TCP 8420                │ UDP 8420
       long poll    │                              │ bind + forward
                    ▼                              ▼
   ┌────────────────────────────────────────────────────────────────┐
   │  locnetd                        every machine, root/Administrator │
   │                                                                │
   │   engine.go     registration, netmap sync, applies config      │
   │   filter.go     port policy between WireGuard and the kernel,  │
   │                 remembering this machine's own connections     │
   │   shareserver   serves folders and forwards ports to peers     │
   │   exec*.go      compute jobs as a named user (S4U on Windows)  │
   │   magicsock/    the UDP socket WireGuard rides on              │
   │   disco/        probe and relay protocol                       │
   │   wireguard-go  the tunnel itself (vendored library)           │
   └────────────────────────────────────────────────────────────────┘
                    ▲
       unix socket  │ /run/locnet/locnetd.sock
                    ▼
   ┌────────────────────────────────────────────────────────────────┐
   │  locnet          the CLI. No networking of its own.            │
   └────────────────────────────────────────────────────────────────┘
```

Splitting the CLI from the daemon is not ceremony. The daemon owns a network
interface and must survive logout, so it is a system service; the CLI is run by
a person and should not need to be. The socket between them is the privilege
boundary, and it is enforced by the operating system rather than by code we
wrote.

## Design decisions

### Every peer is addressed by key, not by IP

`magicsock` implements wireguard-go's `conn.Bind` interface. When WireGuard
asks it to send to a peer, the endpoint it passes is a `peerEndpoint` — an
object holding a WireGuard public key and nothing else. The address is resolved
at send time, from whatever path is currently working.

This is what makes roaming free. A laptop moving from wifi to LTE changes its
address; nothing in WireGuard's configuration mentions the old one, so nothing
needs to change. The next probe finds the new path and traffic follows it.

It is also what makes relay fallback invisible. `Send` picks the direct address
if a recent probe proved it works, and wraps the packet for the relay
otherwise. WireGuard sees a successful send either way.

### Discovery shares WireGuard's UDP port

A NAT mapping is created for a specific source port. If discovery ran on its
own socket, the hole it punched would be for a port WireGuard never sends from,
and the tunnel would still fail.

So `magicsock` owns one socket and multiplexes. Telling the two protocols apart
is unambiguous rather than heuristic: a WireGuard packet starts with a
little-endian `uint32` message type of 1 to 4, so its first byte is `0x01`
through `0x04`; every LocNet packet starts with the four bytes `LNd1`. There is
no overlap and no guessing.

### The relay is used first and abandoned quickly

A peer that has just appeared has no proven path. Rather than block until one
is found, `Send` uses the relay from the first packet, so a connection works
immediately. Probes run in parallel, and the moment one comes back the peer is
promoted to direct.

Ordering it the other way — probe first, relay if probing fails — would mean
every new connection stalls for however long the probe timeout is.

### A direct path must prove itself in both directions

A path is adopted only after a sealed probe sent to that address comes back
sealed. Receiving *something* from an address is not enough: it could be a
reply to a probe we never sent, or traffic from a middlebox.

The address adopted is the one we **sent to**, not the one the reply arrived
from. Under symmetric NAT those differ, and only the former is somewhere we can
send again. Both are recorded for identifying inbound traffic.

A path that stops answering for 35 seconds is dropped and the peer falls back
to the relay. That number is three missed probes at the established interval —
long enough to ride out a hiccup, short enough that a genuinely dead path does
not strand a connection.

### The hub signs, and its TLS is pinned rather than certified

Every network map is signed with the hub's Ed25519 identity key, and every node
verifies it against a fingerprint that came in its join code. Every request a
node makes is signed with the node's own key over a canonical summary of the
request.

That made the control plane safe over plain HTTP — an attacker who can read
and rewrite the wire still cannot add a peer, move a peer's address, or hand a
node a key it will trust — but not private: join codes, endpoints and a
standby's copy of the hub key were all readable. Since 0.10.4 it is TLS 1.3,
and the same fingerprint does the job a certificate authority would: the hub's
certificate is self-signed with its identity key, and a node accepts the
handshake only if that key hashes to the fingerprint it already pins
(`internal/hubtls`). No CA, no trust-on-first-use, no public DNS name, nothing
to renew. Signing stays underneath, unchanged, so a map or request is just as
trustworthy whichever way it arrived.

The hub serves TLS and plain HTTP on one port, told apart by the first byte, so
agents can be upgraded in any order; once a node knows the hub does TLS it
never falls back, and `-require-tls` ends the transition. See
[PROTOCOL.md](PROTOCOL.md#transport) and [SECURITY.md](SECURITY.md).

### The hub stores JSON, not SQL

A hub with a thousand nodes has a state file of a few hundred kilobytes, held
in memory and written atomically on change. SQLite would add a dependency
(cgo, or a large pure-Go driver) to solve a problem this project does not have.

If LocNet ever needs concurrent writers or partial reads, that decision should
be revisited. It does not today.

### Long polling instead of WebSockets

Nodes fetch the network map with `GET /v1/netmap?since=N`, which the hub holds
open for up to 25 seconds and answers early if anything changes. Updates arrive
in milliseconds; an idle network costs one held connection per node.

WebSockets would do the same thing with a dependency and a reconnection state
machine. Long polling is plain HTTP, works through every proxy and middlebox
that exists, and needs no library.

### Addresses are the lowest free one

Not random. In a network of a dozen machines, `10.99.0.3` is something you
can remember and write into a firewall rule; a random address in a /16 is not.

Nodes are matched on their identity key at registration, so a machine that
re-registers keeps its address — which is what makes reinstalling the agent a
non-event.

## The path a packet takes

Sending to `10.99.0.2` from an application:

1. The kernel routes it to `locnet0`, matching the route for the overlay
   prefix.
2. wireguard-go reads it from the TUN device, finds the peer whose
   `allowed_ip` covers `10.99.0.2`, and encrypts it.
3. It calls `magicsock.Send` with that peer's `peerEndpoint`.
4. `magicsock` looks up the peer's current path:
   - a direct address confirmed within the last 35 seconds → send there;
   - otherwise wrap in a `forward` frame and send to the relay.
5. On the far side, either the packet arrives directly and is passed straight
   to WireGuard, or it arrives inside a `forwarded` frame, is unwrapped,
   attributed to the sending peer, and then passed to WireGuard.
6. WireGuard decrypts and writes to its TUN device.

Meanwhile, every two seconds, both ends are sending sealed probes to every
address they know for each other. The first one that round-trips becomes the
direct path, and step 4 starts taking the first branch.

## Layout

```
cmd/
  locnet/          CLI
  locnetd/         node agent, including the Windows service wrapper
  locnet-hub/      coordination server and its admin commands
internal/
  key/             Ed25519 identity, Curve25519 WireGuard and disco keys
  joincode/        the pasteable code: encode, parse, redact
  netmap/          the network map and its signature envelope
  hubapi/          wire types and the request-signing scheme
  hubtls/          the control plane's TLS: certificate from the hub key, pinned verification, TLS/plain on one port
  hub/             store, HTTP server, UDP relay, job queue, audit,
                   standby mirror, WebShare (sites, proxy, ACME, DuckDNS)
  policy/          groups, rules and blocks; port-set arithmetic; the access
                   matrix and its allow/block edits
  node/            agent engine, per-OS interface config and firewall,
                   packet filter, hosts file, share server, compute jobs
                   (S4U logon and job objects on Windows)
  resource/        shares, access lists, service detection, machine stats
  shareclient/     the other end of the share server
  remote/          exec, copy, fetch and job over SSH (rsync or scp;
                   PowerShell on Windows targets)
  placement/       ranking machines for a job
  setup/           installs the SSH and screen servers, per OS
  sshkeys/         publishing and accepting keys over the mesh
  launch/          finds and starts the local RDP, VNC, SSH or browser client
  console/         the local web interface, and devserve, its mock network
  screen/          a VNC client, for the desktop helper and checks
  deskserve/       the desktop session helper
  wake/            Wake-on-LAN
  peercfg/         per-user preferences (login names per peer)
  magicsock/       the conn.Bind: path selection, probing, relay fallback
  disco/           probe and relay wire format
  ipc/             CLI ↔ daemon channel
  paths/           per-OS locations
  integration/     hub + relay + two sockets, end to end
scripts/           build, installers, service units
docs/              these documents — also compiled into the console's Docs page
editors/vscode/    run the current file on another machine
```

## Where to start reading

`internal/magicsock/magicsock.go` — it is the part that does the thing that is
hard. `internal/disco/disco.go` next, for the packets it sends.
`internal/integration/mesh_test.go` shows the whole system assembled in about
four hundred lines and is the fastest way to see how the pieces connect.
