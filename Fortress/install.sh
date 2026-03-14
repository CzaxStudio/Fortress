#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  Fortress Language Installer  —  v1.1.0
#  No Go installation required.
#  Downloads the correct pre-built binary for your platform.
#
#  Usage:
#    curl -fsSL https://fortress-lang.dev/install.sh | bash
#  Or:
#    chmod +x install.sh && ./install.sh
# ═══════════════════════════════════════════════════════════════════════════

set -e

BOLD="\033[1m"
CYAN="\033[36m"
GREEN="\033[32m"
RED="\033[31m"
RESET="\033[0m"

VERSION="1.1.0"
RELEASE_BASE="https://github.com/fortress-lang/fortress/releases/download/v${VERSION}"

echo -e "${CYAN}"
echo "  ███████╗ ██████╗ ██████╗ ████████╗██████╗ ███████╗███████╗███████╗"
echo "  ██╔════╝██╔═══██╗██╔══██╗╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔════╝"
echo "  █████╗  ██║   ██║██████╔╝   ██║   ██████╔╝█████╗  ███████╗███████╗"
echo "  ██╔══╝  ██║   ██║██╔══██╗   ██║   ██╔══██╗██╔══╝  ╚════██║╚════██║"
echo "  ██║     ╚██████╔╝██║  ██║   ██║   ██║  ██║███████╗███████║███████║"
echo "  ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝"
echo -e "${RESET}"
echo -e "  ${BOLD}Fortress Language Installer  —  v${VERSION}${RESET}"
echo ""

# ── Detect platform ────────────────────────────────────────────────────────
OS="$(uname -s 2>/dev/null || echo Unknown)"
ARCH="$(uname -m 2>/dev/null || echo unknown)"

case "$OS" in
  Linux*)
    case "$ARCH" in
      aarch64|arm64) BINARY="fortress-linux-arm64" ;;
      *)             BINARY="fortress-linux-amd64"  ;;
    esac
    INSTALL_DIR="/usr/local/bin"
    ;;
  Darwin*)
    case "$ARCH" in
      arm64) BINARY="fortress-darwin-arm64" ;;
      *)     BINARY="fortress-darwin-amd64" ;;
    esac
    INSTALL_DIR="/usr/local/bin"
    ;;
  MINGW*|MSYS*|CYGWIN*)
    BINARY="fortress-windows-amd64.exe"
    INSTALL_DIR="$HOME/AppData/Local/Fortress"
    ;;
  *)
    echo -e "  ${RED}Unsupported platform: $OS/$ARCH${RESET}"
    echo "  Build from source: https://github.com/fortress-lang/fortress"
    exit 1
    ;;
esac

DOWNLOAD_URL="${RELEASE_BASE}/${BINARY}"
echo "  Platform   : ${OS}/${ARCH}"
echo "  Binary     : ${BINARY}"
echo "  Install to : ${INSTALL_DIR}/fortress"
echo ""

# ── Download ─────────────────────────────────────────────────────────────
TMP="$(mktemp)"
if command -v curl &>/dev/null; then
    curl -fsSL --progress-bar "$DOWNLOAD_URL" -o "$TMP"
elif command -v wget &>/dev/null; then
    wget -q --show-progress "$DOWNLOAD_URL" -O "$TMP"
else
    echo -e "  ${RED}curl or wget required${RESET}"
    exit 1
fi

SIZE=$(wc -c < "$TMP" | tr -d ' ')
if [ "$SIZE" -lt 100000 ]; then
    rm -f "$TMP"
    echo -e "  ${RED}Download failed — file too small (${SIZE} bytes)${RESET}"
    echo "  Download manually: $DOWNLOAD_URL"
    exit 1
fi

# ── Install ──────────────────────────────────────────────────────────────
chmod +x "$TMP"
if echo "$OS" | grep -qiE 'MINGW|MSYS|CYGWIN'; then
    mkdir -p "$INSTALL_DIR"
    mv "$TMP" "$INSTALL_DIR/fortress.exe"
    echo -e "  ${GREEN}Installed: $INSTALL_DIR/fortress.exe${RESET}"
    echo ""
    echo "  Add to PATH (PowerShell, run as Admin):"
    echo "    [Environment]::SetEnvironmentVariable('PATH',\$env:PATH+';$INSTALL_DIR','Machine')"
else
    if [ -w "$INSTALL_DIR" ]; then
        mv "$TMP" "$INSTALL_DIR/fortress"
    else
        sudo mv "$TMP" "$INSTALL_DIR/fortress"
    fi
    echo -e "  ${GREEN}Installed: $INSTALL_DIR/fortress${RESET}"
fi

rm -f "$TMP"

# ── Smoke test ─────────────────────────────────────────────────────────
echo ""
"$INSTALL_DIR/fortress" --version 2>/dev/null || true

# ── Quick start ────────────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}Quick start:${RESET}"
echo "    fortress run script.frt              Run a script"
echo "    fortress build myapp.exe script.frt  Build a self-contained exe"
echo "    fortress build myapp.exe *           Bundle all .frt files into one exe"
echo "    fortress create script.frt           Create a new script from template"
echo "    fortress get file=websec-1.0.0.frtpkg  Install a library"
echo ""
echo "  Docs & libraries:  https://fortress-lang.dev"
echo ""