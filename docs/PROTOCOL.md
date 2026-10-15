# Protocol

Wire formats and exchanges, at the level of detail you would need to write a
second implementation.

Version 1. All multi-byte integers are big-endian.

---

## 1. Keys

Three kinds, deliberately distinct:

| Name | Algorithm | Held by | Purpose |
|---|---|---|---|
| Machine | Ed25519 | node, hub | Identity. Signs control-plane requests; the hub's signs network maps. |
| WireGuard | Curve25519 | node | The tunnel's own key. Never leaves the machine. |
| Disco | Curve25519 | node | Seals NAT-traversal probes. |

Only public halves ever reach the hub.

Disco is separate from the WireGuard key so that the probe path — which is
reachable by anyone who can send UDP to the port — has no relationship to
tunnel key material.

---

## 2. Join code

A join code is everything a machine needs to join, in one pasteable token.

```
locnet1_<base32-lower-nopad(payload)>
```

Payload:

| Offset | Size | Field |
|---|---|---|
| 0 | 2 | magic `"LN"` |
| 2 | 1 | version, `2` |
| 3 | 1 | flags, reserved, `0` |
| 4 | 16 | hub fingerprint: first 16 bytes of `SHA-256(hub Ed25519 public key)` |
| 20 | 16 | join token |
| 36 | 1 | number of hub addresses, 1 to 8 |
| 37 | … | each address: 1 byte length *n*, then *n* bytes, e.g. `hub.example.org:8420` |
| end − 4 | 4 | CRC-32 (IEEE) of every byte before it |

Addresses are tried in order, most specific first: a hub behind NAT lists its
LAN address and its public one, so the same code works at home and away.

Base32 uses the lowercase alphabet `abcdefghijklmnopqrstuvwxyz234567` with no
padding. A parser must accept surrounding whitespace, embedded dashes and
spaces, and any case — codes get read aloud and pasted out of chat clients.

The CRC catches truncation, which is the common failure. It is not a security
mechanism; the fingerprint is.

A bare `host:port` address is reached as described under
[Transport](#transport). It may instead carry an `https://` prefix, for a hub
behind a TLS proxy with a real certificate, or `http://`, to choose plain HTTP
explicitly. The relay is always raw UDP on the same host and port.

---

## 3. Control plane (HTTP)

Base path `/v1`. All bodies are JSON.

### Transport

One TCP port (8420). The hub reads the first byte of each connection: `0x16`
(a TLS handshake record) starts TLS; anything else is plain HTTP, which is
answered only from the hub's own machine (and on `GET /healthz`). From any
other machine a plain-HTTP request gets `426 Upgrade Required`. HTTP/1.1 in
both cases.

**TLS.** TLS 1.3 only, ALPN `http/1.1`. The certificate is self-signed, made
fresh at every start, and its key is the hub's Ed25519 identity key. The client
skips chain validation and instead accepts the handshake only if
`SHA-256(leaf public key)[:16]` equals the pinned fingerprint (checked on every
handshake, resumed or not); TLS 1.3's CertificateVerify proves the server holds
the private key. Nothing else in the certificate — names, validity — is
checked.

**Agents.** A bare `host:port` — what join codes and netmaps carry — is always
reached over pinned TLS: during a join with the code's fingerprint, afterwards
with the stored one. A server that answers the ClientHello in plain HTTP gets
nothing; there is no fallback. An address written `https://…` is a TLS proxy
checked against the system's certificate authorities; one written `http://…`
is plain HTTP by the operator's choice.

**Standby.** `locnet-hub serve -follow host:port` pins the primary's
fingerprint the same way and sends the admin token only after the handshake;
see [OPERATIONS.md](OPERATIONS.md#a-second-hub).

### Request authentication

Every request except `GET /v1/info` and `POST /v1/register` carries:

```
X-LocNet-Node:      <node id>
X-LocNet-Timestamp: <unix seconds>
X-LocNet-Signature: <base64 Ed25519 signature>
```

The signature covers this exact string:

```
<METHOD>\n<path>\n<unix timestamp>\n<lowercase hex SHA-256 of the body>
```

`<path>` excludes the query string. The body digest is of the empty string for
requests with no body.

The hub rejects a timestamp more than **5 minutes** from its own clock. Binding
the signature to method and path means it cannot be replayed against a
different endpoint; the timestamp bounds how long a captured request stays
useful.

**Replays.** Agents add a `"nonce"` member — 24 random hex characters — to
every signed JSON body, so no two requests carry the same signature. The hub
accepts a signature on a `POST` once: a second request with the same
`X-LocNet-Signature` within eleven minutes gets `409 Conflict`. The hub
otherwise ignores the nonce.

### `GET /v1/info`

Unauthenticated. Lets a joining machine confirm the hub's identity before
sending anything.

```json
{
  "hub_key": "<base64 Ed25519 public key>",
  "version": "0.10.4",
  "relay":   "hub.example.org:8420"
}
```

The client **must** check `SHA-256(hub_key)[:16]` against the fingerprint in
its join code and abort if it differs.

### `POST /v1/register`

Authenticated by the join token rather than a signature — the machine has no
node ID yet.

```json
{
  "token":       "<base64 of the 16-byte join token>",
  "hostname":    "workstation",
  "os":          "linux",
  "machine_key": "<base64>",
  "wg_key":      "<base64>",
  "disco_key":   "<base64>"
}
```

Response:

```json
{
  "node_id": "n-x7f2a91b",
  "ip":      "10.99.0.3",
  "name":    "workstation",
  "netmap":  { "payload": "<base64>", "sig": "<base64>", "hub_key": "<base64>" }
}
```

If a node with the same `machine_key` already exists, its record is updated and
its address is reused. Otherwise a new record is created, the lowest free
address is assigned, and the token's remaining uses are decremented.

Failures return **403** whether the token is unknown, spent, expired or
revoked. Distinguishing them would let someone probe for valid codes.

### `GET /v1/netmap?since=<version>`

Long poll. The hub holds the request open for up to 25 seconds and answers as
soon as the version exceeds `since`.

```json
{ "changed": false }
```

```json
{ "changed": true, "netmap": { "payload": "…", "sig": "…", "hub_key": "…" } }
```

### `POST /v1/report`

A node's periodic account of itself — one request rather than four, because all
of it is refreshed on the same schedule and all of it lands in the same netmap.

```json
{
  "local":    ["192.168.1.50:41820", "10.0.0.4:41820"],
  "observed": "203.0.113.44:41820",
  "services": [{"name": "ssh", "port": 22}, {"name": "rdp", "port": 3389}],
  "shares":   [{"name": "data", "kind": "files", "read_only": true, "allow": ["workstation"]}],
  "stats":    {"cpus": 8, "load_percent": 34, "mem_total_mb": 16384,
               "mem_free_mb": 9200, "disk_total_gb": 931, "disk_free_gb": 210}
}
```

The hub **discards** `target` on any files share before storing it. Where a
shared folder lives on disk is not something peers, or the hub, need to know.

The hub bumps the netmap version only when something a peer would act on has
changed. Stats are compared after rounding — load to 10 points, memory to 5,
disk to 2 — so an idle fleet does not churn.

The hub **overrides** `observed` with what its relay actually saw from this
node, when it has a binding. A node behind NAT cannot know its own public
address, and a hostile one should not get to choose what its peers dial.

Loopback, unspecified, multicast and link-local addresses are dropped, and the
list is capped at 8.

### Admin endpoints

`POST /v1/admin/invite`, `POST /v1/admin/revoke`, `GET /v1/admin/nodes`,
`GET /v1/admin/invites`, `POST /v1/admin/remove`, `POST /v1/admin/approve`,
`GET|POST /v1/admin/policy`, `GET /v1/admin/alerts`, `GET /v1/admin/audit`,
`GET|POST /v1/admin/health`, `GET /v1/admin/snapshot`,
`GET|POST /v1/admin/admins`, `GET|POST /v1/admin/webshare`. Authenticated with
`Authorization: Bearer <admin token>`, compared in constant time. The token is
generated at first run and stored in the hub's state file.

### Management endpoints (signed by an administrator machine)

`POST /v1/manage/<op>`, signed like every node request and accepted only from
nodes the hub lists as administrators (the node on the hub machine always is).
`op` is one of `nodes`, `invite`, `invites`, `revoke`, `remove`, `approve`,
`audit`, `access`, `webshare`. The agent forwards these from its local control
channel without interpreting them.

- `access` — body `{}` returns the access matrix:
  `{"machines": [...], "services": [{"name","port","desc"}], "pairs":
  [{"src","dst","all","ports":[{"lo","hi"}],"desc"}], "policy": {...}}`.
  With `{"action": "allow"|"block", "src", "dst", "services": ["ssh", ...]}`
  it changes one pair and returns the matrix afterwards.
- `webshare` — body `{}` returns `{"domain", "accepted_tos", "duckdns",
  "dns": {"at","ip","error"}, "sites": [{"name","url","machine","node_id",
  "share","target","port","state","live","requests","last_error"}]}`. With
  `{"action": "approve"|"off"|"on"|"remove", "name", "machine"}` it changes one
  site. Setting the domain (`"action": "domain"`) is refused here: it needs the
  admin token.

---

## 4. Network map

The signed envelope:

```json
{
  "payload": "<base64 of the JSON below>",
  "sig":     "<base64 Ed25519 signature over the payload bytes>",
  "hub_key": "<base64 Ed25519 public key>"
}
```

The payload travels as opaque bytes rather than a nested object so that the
bytes verified are exactly the bytes signed. Re-encoding a decoded struct to
check a signature is a reliable way to build a verifier that disagrees with the
signer about field order or number formatting.

Verification, in order:

1. `SHA-256(hub_key)[:16]` equals the pinned fingerprint.
2. `sig` verifies over `payload` under `hub_key`.
3. Parse.

Skipping step 1 would let any hub sign a map. Both checks are load-bearing.

Payload:

```json
{
  "version":   42,
  "issued_at": "2026-07-31T16:14:05Z",
  "network": {
    "id": "homelab", "name": "homelab",
    "prefix": "10.99.0.0/16", "domain": "locnet.private", "mtu": 1280,
    "hubs": ["192.168.1.10:8420", "hub.example.org:8420"]
  },
  "self":  { "…": "this node" },
  "peers": [ { "…": "every other node" } ],
  "relays": [ { "id": "hub", "addr": "hub.example.org:8420" } ]
}
```

Each node:

```json
{
  "id": "n-x7f2a91b", "name": "unit-02", "os": "windows",
  "machine_key": "<base64>", "wg_key": "<base64>", "disco_key": "<base64>",
  "ip": "10.99.0.3",
  "endpoints": ["192.168.1.50:41820", "198.51.100.77:41820"],
  "services": [{"name": "rdp", "port": 3389}],
  "shares":   [{"name": "data", "kind": "files", "read_only": true}],
  "stats":    {"cpus": 8, "disk_total_gb": 931, "disk_free_gb": 210},
  "last_seen": "2026-07-31T16:13:58Z",
  "online": true
}
```

`shares` is filtered per recipient: each node's map lists only the shares that
node is allowed to use. A peer is never told the name of a share it may not
reach. A share may carry `"web": "<site>"`, a request to publish it through
WebShare.

`inbound_ports` (on a peer entry) is what that peer may open on the node
receiving the map, as `[{"lo": 22, "hi": 22}, ...]`. Absent means every port;
`[{"lo": 0, "hi": 0}]` means none — the peer is present only because the
receiving node may reach it, and its packets are admitted only as replies.

The node's own `self` entry may carry `"sites": [{"name", "url", "state",
"live"}]`: how its WebShare sites stand. Only a node's own entry has it.

`network.hubs` is every control-plane address, standbys included.

`version` increases on every change a node would care about. Reporting
unchanged endpoints does not bump it, so a large idle fleet does not wake every
long poll in the network.

---

## 5. Discovery and relay (UDP)

Shares the WireGuard port on nodes; on the hub, the relay uses the same port
number as the API but the UDP protocol.

### Framing

```
+--------+--------+--------+--------+--------+---------------+
|  'L'   |  'N'   |  'd'   |  '1'   |  type  |    body …     |
+--------+--------+--------+--------+--------+---------------+
     0        1        2        3        4         5 …
```

A WireGuard packet begins with a little-endian `uint32` message type of 1–4, so
byte 0 is `0x01`–`0x04`. `0x4c` (`'L'`) cannot collide. Anything not starting
with `LNd1` is passed to WireGuard untouched.

| Type | Name | Direction |
|---|---|---|
| 1 | `bind` | node → relay |
| 2 | `bind-reply` | relay → node |
| 3 | `forward` | node → relay |
| 4 | `forwarded` | relay → node |
| 5 | `ping` | node → node |
| 6 | `pong` | node → node |

Addresses are encoded as 18 bytes: a 16-byte v4-mapped address followed by a
2-byte port. All-zero decodes to "none".

### `bind` (1)

Registers a node's current source address with the relay, and asks what that
address looks like from outside. This is LocNet's STUN.

```
body: | nodeIDLen (2) | nodeID | wgPublicKey (32) | nonce (8) | signature (64) |
```

The signature is Ed25519 over `magic ‖ type ‖ nodeIDLen ‖ nodeID ‖ wgKey ‖
nonce` under the node's machine key.

The relay verifies the signature **and** that the claimed WireGuard key belongs
to the claimed node in its own records. Without the second check, one valid
member could bind another member's key and capture its relayed traffic.

Nodes re-bind every 20 seconds. Bindings expire after 5 minutes.

### `bind-reply` (2)

```
body: | nonce (8) | observedAddr (18) |
```

The node ignores a reply whose nonce does not match its outstanding bind.

### `forward` (3) and `forwarded` (4)

```
forward   body: | dstWGKey (32) | srcWGKey (32) | payload … |
forwarded body: | srcWGKey (32) | payload … |
```

The relay forwards only if the sender has a live binding **and** the packet
arrives from the address it bound at. It cannot read the payload: it is either
a WireGuard packet or a sealed disco box.

The payload may itself be a disco packet. A probe that arrives this way is
handled but never counted as evidence of a direct path.

### `ping` (5) and `pong` (6)

```
body: | senderDiscoPublicKey (32) | nacl_box(nonce ‖ ciphertext) |
```

The sender's disco public key is in the clear so the receiver knows which key
to open the box with. The box is NaCl `box` between the two disco keys, with
the 24-byte nonce prepended.

Ping plaintext:

```
| txid (8) | senderWGKey (32) |
```

Pong plaintext:

```
| txid (8) | senderWGKey (32) | observedSrcAddr (18) |
```

`observedSrcAddr` is where the responder saw the ping come from — a second,
peer-derived view of one's own public address. It is only used when the relay
has not supplied one.

### Path selection

Each node, per peer:

- **No direct path:** every 2 seconds, send a ping to every candidate address
  from the netmap, *and* one through the relay. Sending to all candidates at
  once is what makes hole punching work: both ends must have packets in flight
  at the same moment.
- **On a pong** matching an outstanding txid with a real address: record the
  round-trip time and adopt the address *sent to*. Replace the current path if
  there is none, if it is the same address, or if the new round trip is faster.
- **Direct path established:** probe every 15 seconds to hold the NAT mapping
  open and notice failure.
- **35 seconds with no answer:** drop the direct path; traffic returns to the
  relay and fast probing resumes.
- A write error on a direct path drops it immediately.

Probes to one's own observed address are skipped. Unanswered probes are
forgotten after 30 seconds. Candidate lists are capped at 16.

---

## 6. Share server

Each node serves its shares over plain HTTP on `<its-overlay-address>:8421`,
bound to that address alone. There is no authentication header: the connection
arrived through the tunnel, so its source address is a WireGuard-verified
identity. The server maps that address to a peer name using the current netmap
and checks the share's access list.

| Method | Path | Meaning |
|---|---|---|
| GET | `/shares` | Shares this caller may use, as `Advert` objects |
| GET | `/files/<share>/<path>` | Directory listing (JSON) or file contents |
| PUT | `/files/<share>/<path>` | Upload, refused on a read-only share |

Path segments are URL-escaped. Every path is cleaned to remove `..` **and**
resolved through symlinks, then checked to be inside the share root — a link
inside a share that points outside it is refused, which is the subtler half of
the problem.

Uploads are written to a temporary name and renamed into place, and are capped
at 8 GiB.

**Port shares** are not HTTP. Each listens on `<overlay-address>:<port>` and
proxies to a local address after checking the caller against the access list.

## 7. Local control channel

Unix (`/run/locnet/locnetd.sock`, mode 0660) or, on Windows, a loopback TCP
port and token in `%ProgramData%\LocNet\control.json` (mode 0600). HTTP/JSON
either way.

| Method | Path | Body |
|---|---|---|
| GET | `/status` | — |
| POST | `/join` | `{"code": "locnet1_…", "up": true}` |
| POST | `/up` | — |
| POST | `/down` | — |
| POST | `/leave` | — |
| POST | `/hosts` | `{"enabled": true}` |
| POST | `/share/add` | a `Share` object |
| POST | `/share/remove` | `{"name": "data"}` |

On Windows every request carries `X-LocNet-Control: <token>`.

---

## 8. Constants

| | |
|---|---|
| Hub API and relay port | 8420 (TCP and UDP); TCP is TLS 1.3 |
| Node WireGuard/disco port | 41820 (UDP) |
| Node share server port | 8421 (TCP, overlay address only) |
| Overlay prefix | `10.99.0.0/16` |
| Tunnel MTU | 1280 |
| WireGuard keepalive | 25 s |
| Relay re-bind | 20 s |
| Relay binding TTL | 5 min |
| Probe interval, searching | 2 s |
| Probe interval, established | 15 s |
| Direct path timeout | 35 s |
| Netmap long poll | 25 s |
| Node report interval | 30 s |
| Service scan interval | 5 min |
| Node considered offline after | 90 s |
| Max control-plane clock skew | 5 min |
