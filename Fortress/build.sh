#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  build-release.sh  —  Cross-compile Fortress for all platforms
#
#  Run this ONCE (by the maintainer) to produce the pre-built binaries that
#  users download via install.sh.  Users never need Go on their machines.
#
#  Requirements (maintainer only):
#    go 1.21+
#
#  Usage:
#    chmod +x build-release.sh && ./build-release.sh
#
#  Output (in ./dist/):
#    fortress-linux-amd64
#    fortress-linux-arm64
#    fortress-darwin-amd64
#    fortress-darwin-arm64
#    fortress-windows-amd64.exe
# ═══════════════════════════════════════════════════════════════════════════

set -e

BOLD="\033[1m"
CYAN="\033[36m"
GREEN="\033[32m"
RED="\033[31m"
RESET="\033[0m"

VERSION="1.1.0"
DIST="./dist"

echo -e "${CYAN}"
echo "  Fortress  —  Cross-Platform Release Builder"
echo -e "${RESET}"
echo -e "  ${BOLD}Version:${RESET} ${VERSION}"
echo ""

# Check Go is available (maintainer needs it, users don't)
if ! command -v go &>/dev/null; then
    echo -e "  ${RED}Go is required to build release binaries.${RESET}"
    echo "  Install from: https://go.dev/dl/"
    exit 1
fi

echo "  Go: $(go version)"
echo ""

mkdir -p "$DIST"

# Build targets: OS / ARCH / output filename
TARGETS=(
    "linux   amd64   fortress-linux-amd64"
    "linux   arm64   fortress-linux-arm64"
    "darwin  amd64   fortress-darwin-amd64"
    "darwin  arm64   fortress-darwin-arm64"
    "windows amd64   fortress-windows-amd64.exe"
)

LDFLAGS="-s -w -X main.VERSION=${VERSION} -X main.BUILD_DATE=$(date +%Y-%m-%d)"

for target in "${TARGETS[@]}"; do
    read -r goos goarch outname <<< "$target"
    out="${DIST}/${outname}"
    echo -ne "  Building ${outname}..."
    GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 \
        go build -trimpath -ldflags "$LDFLAGS" -o "$out" .
    size=$(du -sh "$out" | cut -f1)
    echo -e " ${GREEN}done${RESET}  (${size})"
done

echo ""
echo -e "  ${GREEN}All binaries built:${RESET}"
ls -lh "$DIST"
echo ""
echo "  Upload these to GitHub Releases as:"
echo "    https://github.com/fortress-lang/fortress/releases/tag/v${VERSION}"
echo ""
echo "  Users install with:"
echo "    curl -fsSL https://fortress-lang.dev/install.sh | bash"
echo ""