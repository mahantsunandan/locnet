# Reaching a machine's screen

```bash
locnet rdp hubpc      # its real screen, in your RDP client
locnet vnc hubpc      # its VNC desktop, in your VNC client
```

— or **Screen (RDP)** and **VNC** in a machine's details in `locnet console`.

LocNet makes the machine reachable and opens the client you already have
(Remmina or xfreerdp on Linux, Microsoft Remote Desktop or Screen Sharing on a
Mac, mstsc on Windows). It does not draw the screen itself. Before it opens a
client, it checks that the server on the far machine will actually let someone
log in, and if not it says what is wrong and how to fix it — instead of
starting a client that flashes and vanishes.

---

## Which one to use

| | RDP | VNC |
|---|---|---|
| What you see | the machine's **real screen**, whatever is on the monitor | on Linux, a **second, virtual desktop** of its own; on a Mac, the real screen |
| Windows | built in (Pro editions): Settings → System → Remote Desktop | install TightVNC, then `locnet setup -install` puts it behind LocNet: the **real screen**, no VNC password, reachable only through the mesh |
| Linux with GNOME | built in (GNOME Remote Desktop) — needs a login set once, see below | `sudo locnet setup -install` creates the virtual desktop |
| Other Linux desktops | install xrdp | `sudo locnet setup -install` |
| macOS | none | built in: System Settings → General → Sharing → Screen Sharing |

On GNOME with Wayland, RDP is the way LocNet shows what is actually on the
monitor, and VNC is a separate desktop that is there whether or not anyone is
logged in at the machine. (GNOME Remote Desktop can also share the real screen
over VNC, but only with a VNC password kept in an unlocked keyring — which an
automatic login never unlocks — so LocNet does not set it up.)

On Windows with TightVNC, `locnet setup -install` moves TightVNC to
`127.0.0.1:5901`, turns its own password off and publishes it as the `screen`
share on port 5900, so `locnet vnc <machine>` opens with no password while the
machine's Wi-Fi and LAN addresses do not answer VNC at all. The share's allow
list and the access policy decide who may connect. Viewers see the Windows
lock screen if the session is locked.

---

## RDP on a GNOME machine: `locnet setup rdp`

GNOME Remote Desktop has a trap. With RDP switched on but no RDP username and
password set, it listens on port 3389, accepts every connection — and hangs up
on every client before the first step of the login, logging only `Credentials
are not set, denying client` in its own journal. Port checks pass; nothing
works. LocNet shows it as **rdp ⚠** and refuses to start a client at it.

To fix it, on that machine, as the person who logs in at its desktop and
*without* sudo (over SSH is fine — `locnet ssh <machine>` first):

```bash
locnet setup rdp
```

It asks for a username and a password — GNOME's own prompts, so the password
goes from your keyboard into GNOME's keyring and LocNet never sees it — turns on
remote control, and checks the server now answers the way a working one does.
Then, from your own machine, connect and log in with those. Remmina offers to
remember the password.

GNOME shows the screen exactly as it is: if it is locked, you see the lock
screen and unlock it as you would at the machine.

---

## VNC: the black window

The virtual desktop on a Linux machine has its own screensaver, which blanks it
after a few idle minutes and locks it. A VNC client connecting to it then shows
**a black window**. That is not a failure: click inside the window, and the
desktop wakes and asks for that machine's account password.

The VNC server itself has no password of its own, by design: it listens only
on the machine's loopback, and the only way to it is LocNet's port share, which
checks each peer against its access list — a WireGuard key check — before
connecting anything. The desktop's lock screen is the login. The share that
`locnet setup -install` creates for this is called **screen**; it is what the
VNC button opens, and the console shows it as such.

---

## When it does not work

`locnet doctor` on the far machine lists servers there that answer but will not
let anyone in, and `locnet peers` marks them with `!`. The usual causes:

| Symptom | Cause | Fix |
|---|---|---|
| **rdp ⚠** — "hangs up on every client" | GNOME Remote Desktop has no RDP login | `locnet setup rdp` on that machine |
| RDP: "requires network-level authentication" | the client could not offer it | update the client; Remmina and xfreerdp 3 both do |
| VNC window is black | the virtual desktop is asleep | click inside it |
| VNC: "closes the connection before saying anything" | nothing behind the share, or TigerVNC's blacklist | `sudo locnet setup -install` there; it disables the blacklist |
| "nothing is listening on port …" | no server at all | the table above |

---

## No viewer of its own

LocNet has no screen viewer or screen protocol of its own: RDP and VNC clients
do that job better, and `locnet screen` says so and points at them.
`locnet desktop` manages the setting that offers this machine's screen to named
peers; `locnet desktop stop` turns it off, and the console's This machine page
offers the same whenever it finds it on.
