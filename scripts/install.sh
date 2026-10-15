#!/usr/bin/env bash
# LocNet installer for Linux and macOS.
#
#   sudo ./install.sh                    install the node agent (locnetd + locnet)
#   sudo ./install.sh --join <code>      install, then join the network in one step
#   sudo ./install.sh --hub              also install the coordination server
#   sudo ./install.sh --uninstall        remove everything except the state directory
#
# Run it from an unpacked release directory, or from a source checkout after
# `scripts/build.sh` has produced dist/.
set -euo pipefail

BIN_DIR="${BIN_DIR:-/usr/local/bin}"
WITH_HUB=0
UNINSTALL=0
JOIN_CODE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --hub)       WITH_HUB=1 ;;
        --uninstall) UNINSTALL=1 ;;
        # Installing and joining are one action from the operator's point of
        # view — a machine that has the software but is on no network is not
        # set up. Accepting both spellings because a copied command should
        # work whichever way it was written down.
        --join)      shift; JOIN_CODE="${1:-}" ;;
        --join=*)    JOIN_CODE="${1#--join=}" ;;
        -h|--help)   sed -n '2,10p' "$0" | sed 's/^# \?//'; exit 0 ;;
        *)           echo "install.sh: unknown option $1" >&2; exit 2 ;;
    esac
    shift
done

if [ -n "$JOIN_CODE" ] && [ "$UNINSTALL" -eq 1 ]; then
    echo "install.sh: --join and --uninstall do not go together" >&2
    exit 2
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh must run as root — it installs a system service that owns a network interface." >&2
    echo "Try: sudo $0 $*" >&2
    exit 1
fi

OS="$(uname -s)"
case "$OS" in
    Linux)  PLATFORM=linux  ;;
    Darwin) PLATFORM=darwin ;;
    *)      echo "install.sh: $OS is not supported. LocNet runs on Linux, macOS and Windows." >&2; exit 1 ;;
esac

HERE="$(cd "$(dirname "$0")" && pwd)"

# ---------------------------------------------------------------- uninstall

if [ "$UNINSTALL" -eq 1 ]; then
    echo "Stopping and removing LocNet…"
    if [ "$PLATFORM" = linux ]; then
        systemctl disable --now locnetd.service   2>/dev/null || true
        systemctl disable --now locnet-hub.service 2>/dev/null || true
        rm -f /etc/systemd/system/locnetd.service /etc/systemd/system/locnet-hub.service
        systemctl daemon-reload
    else
        launchctl bootout system/com.locnet.locnetd 2>/dev/null || true
        rm -f /Library/LaunchDaemons/com.locnet.locnetd.plist
    fi
    rm -f "$BIN_DIR"/locnet "$BIN_DIR"/locnetd "$BIN_DIR"/locnet-hub
    echo "Removed. State was left in place:"
    echo "  node: $([ "$PLATFORM" = linux ] && echo /var/lib/locnet || echo '/Library/Application Support/LocNet')"
    echo "Delete it by hand if you want this machine to forget its identity."
    exit 0
fi

# ------------------------------------------------------------------ locate

find_binary() {
    local name="$1"
    for candidate in \
        "$HERE/$name" \
        "$HERE/../dist/locnet_"*"_${PLATFORM}_$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')/$name"
    do
        if [ -f "$candidate" ]; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

install_binary() {
    local name="$1" src
    if ! src="$(find_binary "$name")"; then
        echo "install.sh: cannot find $name." >&2
        echo "  Run scripts/build.sh first, or run this script from an unpacked release." >&2
        exit 1
    fi
    install -m 0755 "$src" "$BIN_DIR/$name"
    echo "  $BIN_DIR/$name"
}

echo "Installing binaries:"
install_binary locnetd
install_binary locnet
[ "$WITH_HUB" -eq 1 ] && install_binary locnet-hub

# ----------------------------------------------------------------- service

echo
echo "Installing the service:"

# The locnet group owns the control socket, so `locnet status` and the connect
# commands work without sudo. Without it everything still works — it just means
# typing sudo, and sudo is what makes `locnet ssh` try to log in as root.
if [ "$PLATFORM" = linux ]; then
    groupadd -f locnet 2>/dev/null || true
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
        usermod -aG locnet "$SUDO_USER" 2>/dev/null || true
        ADDED_USER="$SUDO_USER"
    fi

    install -d -m 0700 /var/lib/locnet
    install -m 0644 "$HERE/systemd/locnetd.service" /etc/systemd/system/locnetd.service
    echo "  /etc/systemd/system/locnetd.service"

    if [ "$WITH_HUB" -eq 1 ]; then
        # The hub listens above port 1024 and touches no interfaces, so it has
        # no business running as root.
        id -u locnet-hub >/dev/null 2>&1 || \
            useradd --system --no-create-home --shell /usr/sbin/nologin locnet-hub
        install -d -m 0700 -o locnet-hub -g locnet-hub /var/lib/locnet-hub
        install -m 0644 "$HERE/systemd/locnet-hub.service" /etc/systemd/system/locnet-hub.service
        if [ ! -f /etc/locnet/hub.env ]; then
            install -d -m 0755 /etc/locnet
            cat > /etc/locnet/hub.env <<'ENV'
# Address your machines will use to reach this hub, as host:port.
# This MUST be reachable from every machine that will join — if the hub is
# behind NAT, that means a forwarded TCP and UDP port, or a hostname that
# resolves to the right place.
LOCNET_ADVERTISE=CHANGE-ME:8420

# What the hub binds to locally. Leave as-is unless you know why not.
LOCNET_LISTEN=:8420

# Network name and address range, used on first run only.
LOCNET_NETWORK=locnet
LOCNET_PREFIX=10.99.0.0/16

# Extra flags for locnet-hub serve. Once every machine runs 0.10.4 or later
# (locnet-hub nodes lists any that do not), refuse plain HTTP with:
#LOCNET_HUB_FLAGS=-require-tls
ENV
            chmod 0644 /etc/locnet/hub.env
        fi
        echo "  /etc/systemd/system/locnet-hub.service"
        echo "  /etc/locnet/hub.env"
    fi

    systemctl daemon-reload
    systemctl enable locnetd.service
    # restart, not "enable --now": --now starts a stopped service but leaves a
    # running one alone, so an upgrade would put the new binary on disk and
    # keep executing the old process until the next reboot. That produces
    # version errors that make no sense to anyone reading them.
    systemctl restart locnetd.service
    echo "  locnetd enabled and (re)started: $("$BIN_DIR/locnetd" -version 2>/dev/null || echo running)"

    if [ "$WITH_HUB" -eq 1 ] && systemctl is-enabled --quiet locnet-hub.service 2>/dev/null; then
        systemctl restart locnet-hub.service
        echo "  locnet-hub restarted: $("$BIN_DIR/locnet-hub" version 2>/dev/null || echo running)"
    fi
else
    # macOS has no groupadd. Without a locnet group the control socket has no
    # group to belong to, so it stays root-only and every command needs sudo —
    # which is worse than an annoyance, because `sudo locnet ssh` then tries to
    # log in as root@peer.
    if ! dscl . -read /Groups/locnet >/dev/null 2>&1; then
        dseditgroup -o create -r "LocNet control socket" locnet 2>/dev/null || true
    fi
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
        dseditgroup -o edit -a "$SUDO_USER" -t user locnet 2>/dev/null || true
        ADDED_USER="$SUDO_USER"
    fi

    install -d -m 0700 "/Library/Application Support/LocNet"
    # launchd will not start a job whose StandardOutPath directory does not
    # exist — it fails to spawn and retries on the throttle interval, which
    # looks like a daemon that is running but keeps losing its hub connection.
    install -d -m 0755 /var/log/locnet
    PLIST=/Library/LaunchDaemons/com.locnet.locnetd.plist
    LABEL=system/com.locnet.locnetd

    install -m 0644 "$HERE/launchd/com.locnet.locnetd.plist" "$PLIST"
    chown root:wheel "$PLIST"

    # A malformed plist and an already-loaded one both fail with the same
    # unhelpful "Input/output error", so rule the first one out here.
    if ! plutil -lint "$PLIST" >/dev/null 2>&1; then
        echo "  ✗ $PLIST is not a valid plist" >&2
        plutil -lint "$PLIST" >&2 || true
        exit 1
    fi

    # bootout returns before launchd has finished tearing the job down. Firing
    # bootstrap straight after it is a race, and losing it gives
    # "Bootstrap failed: 5: Input/output error" — which reads like a disk
    # fault and is really just "that label is still registered". Wait for it
    # to actually go.
    if launchctl print "$LABEL" >/dev/null 2>&1; then
        launchctl bootout "$LABEL" 2>/dev/null || true
        n=0
        while launchctl print "$LABEL" >/dev/null 2>&1 && [ "$n" -lt 50 ]; do
            sleep 0.2
            n=$((n + 1))
        done
    fi

    # An earlier `launchctl disable` outlives the plist, and a disabled
    # service bootstraps and then refuses to run.
    launchctl enable "$LABEL" 2>/dev/null || true

    if launchctl bootstrap system "$PLIST" 2>/tmp/locnet-bootstrap.err; then
        :
    elif launchctl print "$LABEL" >/dev/null 2>&1; then
        # It is registered after all — the teardown never completed. Restart
        # it in place, which is what bootstrap would have achieved.
        launchctl kickstart -k "$LABEL"
    else
        echo "  ✗ could not start locnetd:" >&2
        sed 's/^/    /' /tmp/locnet-bootstrap.err >&2
        echo "    Try:  sudo launchctl bootout $LABEL && sudo launchctl bootstrap system $PLIST" >&2
        rm -f /tmp/locnet-bootstrap.err
        exit 1
    fi
    rm -f /tmp/locnet-bootstrap.err

    echo "  $PLIST"
    echo "  locnetd loaded and started"
fi

# -------------------------------------------------------------- next steps

cat <<EOF

Done.
EOF

# ------------------------------------------------------------------- join

# Joining here rather than telling the operator to join is the difference
# between one command and three. The service has just been started, so it may
# not have its control socket up yet; a short wait costs nothing and turns a
# race into a reliable install.
if [ -n "$JOIN_CODE" ]; then
    echo
    echo "Joining the network…"
    for _ in $(seq 1 20); do
        "$BIN_DIR/locnet" status >/dev/null 2>&1 && break
        sleep 0.5
    done

    if "$BIN_DIR/locnet" join "$JOIN_CODE"; then
        echo
        "$BIN_DIR/locnet" status || true
        echo
        echo "This machine is on the network. Check the others with:  locnet peers"
        exit 0
    fi

    # A failed join is not a failed install: the software is in place and the
    # code can be retried without doing any of this again.
    cat <<EOF

The software is installed, but joining failed — see the error above.
The usual causes are a code that has been used up or has expired, and a hub
that is not reachable from this network. Get a fresh code and retry with:

    sudo locnet join <code>
EOF
    exit 1
fi

cat <<'EOF'

Next:
EOF

if [ "$WITH_HUB" -eq 1 ] && [ "$PLATFORM" = linux ]; then
    cat <<'EOF'
  1. Edit /etc/locnet/hub.env and set LOCNET_ADVERTISE to an address your
     other machines can reach.
  2. sudo systemctl enable --now locnet-hub
  3. sudo journalctl -u locnet-hub -n 30      # the first-run join code is here
  4. On every machine:  sudo locnet join <code>
EOF
else
    cat <<'EOF'
  1. Get a join code from whoever runs the hub:
       locnet-hub invite
  2. On this machine:
       sudo locnet join <code>
  3. Check it worked:
       locnet status
EOF
fi

if [ -n "${ADDED_USER:-}" ]; then
    cat <<EOF

  $ADDED_USER was added to the 'locnet' group, so locnet works without sudo.
  Log out and back in for that to take effect — until then, use sudo.
EOF
fi

# The desktop helper is deliberately not started here. It has to run inside a
# graphical session, as the person logged in to it, and a root install script
# has neither — starting a --user service from root either fails or starts it
# in the wrong session, which is worse than not trying.
cat <<'EOF'

Optional — install and start the remote-access pieces (SSH, screen sharing):
     locnet setup                  # see exactly what is missing
     sudo locnet setup -install    # install, configure and start it

  On Linux that sets up a VNC virtual desktop on :1, bound to localhost and
  published to your peers through LocNet's access list. It is a desktop of its
  own, not the screen you are sitting in front of — no VNC server can show
  that on a Wayland session. See docs/INSTALL.md.

Optional — let others watch this machine's *physical* screen from their
browser, with no client and no VNC at the far end:
     locnet desktop share -allow <who> [-control]    # once, as an admin
     locnet desktop autostart                        # as the logged-in user

  On a Wayland desktop, capture goes through a VNC server running here, which
  is what `locnet setup -install` provides:
     locnet desktop autostart -vnc 127.0.0.1:5901
  See docs/DESKTOP.md.

Optional — let this machine run queued work for the fleet:
     locnet compute enable -allow <who> -user <account>
  Then anyone allowed can:  locnet queue submit -- <command>
EOF
echo
