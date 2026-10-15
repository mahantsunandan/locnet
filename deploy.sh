#!/usr/bin/env bash
# Install the current LocNet build on this machine and restart the services.
#
# Run with: sudo bash deploy.sh            (on linuxbox)
#           sudo bash deploy.sh --hub      (on hubpc, which also runs the hub)
#
# The version is never written down here. This script was called deploy-0.8.1.sh
# and pointed at a 0.8.1 build that had not existed for two releases, so it
# failed on the one day somebody needed it. It now reads VERSION beside itself
# and finds the matching build, which means it keeps working without being
# edited.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -z "${VERSION:-}" ] && [ -f "$ROOT/VERSION" ]; then
    VERSION="$(tr -d ' \t\r\n' < "$ROOT/VERSION")"
fi
[ -n "${VERSION:-}" ] || { echo "no VERSION file at $ROOT and \$VERSION unset" >&2; exit 1; }

# The build to install is the one for this machine, not an assumed amd64 — the
# fleet has arm in it, and installing the wrong architecture produces an "Exec
# format error" from systemd long after this script reports success.
case "$(uname -m)" in
    x86_64|amd64)   ARCH=amd64 ;;
    aarch64|arm64)  ARCH=arm64 ;;
    armv7l|armv6l)  ARCH=arm ;;
    *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

SRC="${SRC:-$ROOT/dist/locnet_${VERSION}_linux_${ARCH}}"

WITH_HUB=0
if [ "${1:-}" = "--hub" ]; then
    WITH_HUB=1
fi

if [ ! -d "$SRC" ]; then
    echo "no build at $SRC" >&2
    echo "run scripts/build.sh first, or set SRC to a build directory" >&2
    exit 1
fi

# Refuse to install a half-built directory. Every binary is checked before the
# running services are stopped, so a bad build cannot leave this machine with
# locnetd down and nothing to put back.
NEED=(locnet locnetd)
[ "$WITH_HUB" = 1 ] && NEED+=(locnet-hub)
for bin in "${NEED[@]}"; do
    [ -x "$SRC/$bin" ] || { echo "missing or not executable: $SRC/$bin" >&2; exit 1; }
done

echo "== installing LocNet $VERSION (linux/$ARCH) from $SRC =="

echo "== stopping services =="
systemctl stop locnetd || true
if [ "$WITH_HUB" = 1 ]; then
    systemctl stop locnet-hub || true
fi

echo "== installing binaries =="
for bin in "${NEED[@]}"; do
    install -m 0755 "$SRC/$bin" "/usr/local/bin/$bin"
done

# The service units change too, now and then — a sandboxing setting that hid
# home directories from the agent was one — and a deploy that only copied
# binaries left every machine running the old unit forever. Only units that
# differ are replaced, and only the ones for services this machine runs.
UNITS=(locnetd.service)
[ "$WITH_HUB" = 1 ] && UNITS+=(locnet-hub.service)
UNIT_SRC=""
for dir in "$SRC/systemd" "$ROOT/scripts/systemd"; do
    [ -d "$dir" ] && { UNIT_SRC="$dir"; break; }
done
if [ -n "$UNIT_SRC" ]; then
    reload=0
    for unit in "${UNITS[@]}"; do
        [ -f "$UNIT_SRC/$unit" ] || continue
        if ! cmp -s "$UNIT_SRC/$unit" "/etc/systemd/system/$unit"; then
            echo "   updating /etc/systemd/system/$unit"
            install -m 0644 "$UNIT_SRC/$unit" "/etc/systemd/system/$unit"
            reload=1
        fi
    done
    [ "$reload" = 1 ] && systemctl daemon-reload
fi

echo "== starting services =="
if [ "$WITH_HUB" = 1 ]; then
    systemctl start locnet-hub
fi
systemctl start locnetd

sleep 4
echo
/usr/local/bin/locnet version
echo
/usr/local/bin/locnet doctor || true
