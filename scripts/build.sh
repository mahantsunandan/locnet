#!/usr/bin/env bash
# Build LocNet for every supported platform into dist/.
#
# Everything is statically linked with CGO off, so each output is one file with
# no runtime dependencies — except on Windows, where the tunnel driver needs
# wintun.dll beside the binary. See docs/INSTALL.md.
set -euo pipefail

cd "$(dirname "$0")/.."

# Where the version comes from, in order: the environment, the VERSION file,
# then git. The file is first because this tree is not always a git checkout —
# an unpacked source release has no tags to describe, and falling back to a
# hardcoded 0.1.0 there produced binaries that lied about themselves.
if [ -z "${VERSION:-}" ] && [ -f VERSION ]; then
    VERSION="$(tr -d ' \t\r\n' < VERSION)"
fi
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo 0.1.0)}"
OUT="${OUT:-dist}"

TARGETS=(
    "linux/amd64"
    "linux/arm64"
    "linux/arm"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
    "windows/arm64"
)

CMDS=(locnet locnetd locnet-hub)

rm -rf "$OUT"
mkdir -p "$OUT"

echo "LocNet $VERSION"
for target in "${TARGETS[@]}"; do
    GOOS="${target%%/*}"
    GOARCH="${target##*/}"
    dir="$OUT/locnet_${VERSION}_${GOOS}_${GOARCH}"
    mkdir -p "$dir"

    ext=""
    [ "$GOOS" = "windows" ] && ext=".exe"

    for cmd in "${CMDS[@]}"; do
        CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
            go build -trimpath \
            -ldflags "-s -w -X main.Version=$VERSION" \
            -o "$dir/${cmd}${ext}" "./cmd/$cmd"
    done

    # The whole of docs/, not just INSTALL.md. Half the features in this
    # release are ones somebody has to read a page about before they know the
    # command exists, and a release you have to go back to the repository to
    # understand is not a complete one.
    cp README.md LICENSE "$dir/" 2>/dev/null || true
    mkdir -p "$dir/docs"
    cp docs/*.md "$dir/docs/" 2>/dev/null || true
    cp docs/INSTALL.md "$dir/" 2>/dev/null || true
    if [ "$GOOS" = "windows" ]; then
        cp scripts/install.ps1 "$dir/"
    else
        # The service units travel with the installer: it looks for them
        # beside itself, and a release without them installs nothing.
        cp scripts/install.sh "$dir/"
        chmod +x "$dir/install.sh"
        case "$GOOS" in
            linux)  mkdir -p "$dir/systemd" && cp scripts/systemd/*.service "$dir/systemd/" ;;
            darwin) mkdir -p "$dir/launchd" && cp scripts/launchd/*.plist "$dir/launchd/" ;;
        esac
    fi

    ( cd "$OUT" && tar czf "$(basename "$dir").tar.gz" "$(basename "$dir")" )
    printf '  %-28s %s\n' "$GOOS/$GOARCH" "$(du -sh "$dir" | cut -f1)"
done

echo
echo "Archives in $OUT/:"
ls -1 "$OUT"/*.tar.gz | sed 's/^/  /'
