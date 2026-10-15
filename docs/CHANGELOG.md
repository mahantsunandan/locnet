# Changes

Newest first. Every change to the code adds an entry here, under the version
it ships in (the `VERSION` file).

## 0.10.4 — October 2026

The first public release.

LocNet is a self-hosted WireGuard mesh: one always-on hub, an agent on every
Linux, macOS and Windows machine, and a CLI with a web console. Machines join
with a pasteable code, keep a fixed address, and reach each other peer to peer
with NAT traversal and a relay as fallback. On top of that: SSH, VNC and RDP
handed to your own clients, folder and port shares, compute and a job queue,
per-pair access control, device approval, alerts and an audit log, a standby
hub, wake-on-LAN, and publishing a web app to the internet (WebShare).

The control plane is TLS 1.3 pinned to the hub's identity key — no certificate
authority, nothing to renew, no plain-HTTP fallback — and every network map and
request is signed as well.

See [README.md](../README.md) for what works and how to set it up, and
[SECURITY.md](SECURITY.md) for what is and is not protected.
