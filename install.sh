#!/bin/sh
# ANPU installer for Linux and macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/Marwanmorsy999/anpu/main/install.sh | sh
#
# Env knobs:
#   ANPU_VERSION     release tag, e.g. v0.4.1 (default: latest)
#   ANPU_INSTALL_DIR install directory (default: /usr/local/bin, falls
#                    back to $HOME/.local/bin when not writable)
#   ANPU_BASE_URL    override the release download base URL (testing)
set -eu

UNINSTALL=0
for arg in "$@"; do
  case "$arg" in
    --uninstall) UNINSTALL=1 ;;
  esac
done
if [ "${ANPU_UNINSTALL:-0}" = "1" ]; then
  UNINSTALL=1
fi

REPO="Marwanmorsy999/anpu"

if [ "$UNINSTALL" = "1" ]; then
  INSTALL_DIR="${ANPU_INSTALL_DIR:-/usr/local/bin}"
  if [ ! -w "$INSTALL_DIR" ] && [ -x "$INSTALL_DIR/anpu" ]; then
    if command -v sudo >/dev/null 2>&1; then
      sudo rm -f "$INSTALL_DIR/anpu"
    else
      rm -f "$INSTALL_DIR/anpu" 2>/dev/null || true
    fi
  else
    rm -f "$INSTALL_DIR/anpu" 2>/dev/null || true
  fi
  # also try user bin
  rm -f "$HOME/.local/bin/anpu" 2>/dev/null || true
  say "anpu installer: removed anpu binary"
  if [ "${ANPU_PURGE:-0}" = "1" ]; then
    rm -rf "${XDG_CONFIG_HOME:-$HOME/.config}/anpu" "$HOME/.anpu"
    say "anpu installer: removed data directory"
  else
    if [ -t 0 ]; then
      printf "Remove data directory too? [y/N] " >&2
      read -r ans || ans=""
      case "$ans" in
        y|Y|yes|YES)
          rm -rf "${XDG_CONFIG_HOME:-$HOME/.config}/anpu" "$HOME/.anpu"
          say "anpu installer: removed data directory"
          ;;
        *)
          say "anpu installer: kept data directory"
          ;;
      esac
    else
      say "anpu installer: kept data directory (set ANPU_PURGE=1 to remove)"
    fi
  fi
  exit 0
fi
VERSION="${ANPU_VERSION:-latest}"
INSTALL_DIR="${ANPU_INSTALL_DIR:-}"
BASE_URL="${ANPU_BASE_URL:-https://github.com/$REPO/releases/download}"

say() { printf '%s\n' "$*" >&2; }

# --- fetch tool selection ---------------------------------------------------
if command -v curl >/dev/null 2>&1; then
  FETCH=curl
elif command -v wget >/dev/null 2>&1; then
  FETCH=wget
else
  say "anpu installer: missing required tool: curl or wget"
  exit 1
fi

fetch() {
  url=$1
  dest=$2
  if [ "$FETCH" = "curl" ]; then
    curl -fsSL --fail -o "$dest" "$url"
  else
    wget -q -O "$dest" "$url"
  fi
}

resolve_latest() {
  url="https://github.com/$REPO/releases/latest"
  if [ "$FETCH" = "curl" ]; then
    final=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$url" 2>/dev/null || true)
    tag=${final##*/tag/}
    if [ -n "$tag" ] && [ "$tag" != "$final" ]; then
      printf '%s' "$tag"
      return 0
    fi
  else
    out=$(wget --spider -S "$url" 2>&1 || true)
    tag=$(printf '%s\n' "$out" | sed -n 's/.*\/tag\/\([^/?[:space:]]*\).*/\1/p' | head -n 1)
    if [ -n "$tag" ]; then
      printf '%s' "$tag"
      return 0
    fi
  fi
  return 1
}

# --- platform detection -----------------------------------------------------
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
  linux) OS=linux ;;
  darwin) OS=darwin ;;
  *)
    say "anpu installer: unsupported OS: $OS (use Docker or build from source)"
    exit 1
    ;;
esac

ARCH=$(uname -m)
case "$ARCH" in
  x86_64 | amd64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *)
    say "anpu installer: unsupported architecture: $ARCH"
    exit 1
    ;;
esac

# --- version resolution -----------------------------------------------------
if [ "$VERSION" = "latest" ]; then
  say "anpu installer: resolving latest release..."
  VERSION=$(resolve_latest) || {
    say "anpu installer: could not resolve latest release (set ANPU_VERSION=vX.Y.Z explicitly)"
    exit 1
  }
  if [ -z "$VERSION" ]; then
    say "anpu installer: could not resolve latest release (set ANPU_VERSION=vX.Y.Z explicitly)"
    exit 1
  fi
fi

BASE="$BASE_URL/$VERSION"
TARBALL="anpu_${VERSION#v}_${OS}_${ARCH}.tar.gz"

# --- install dir selection --------------------------------------------------
if [ -z "$INSTALL_DIR" ]; then
  if [ -w /usr/local/bin ]; then
    INSTALL_DIR=/usr/local/bin
  elif command -v sudo >/dev/null 2>&1; then
    INSTALL_DIR=/usr/local/bin
    USE_SUDO=1
  else
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
    USE_SUDO=0
  fi
else
  USE_SUDO=0
  if [ ! -w "$INSTALL_DIR" ]; then
    if command -v sudo >/dev/null 2>&1; then
      USE_SUDO=1
    else
      say "anpu installer: $INSTALL_DIR is not writable"
      exit 1
    fi
  fi
  mkdir -p "$INSTALL_DIR"
fi
USE_SUDO=${USE_SUDO:-0}

# --- download ---------------------------------------------------------------
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT INT TERM HUP

say "anpu installer: downloading $TARBALL ($VERSION)..."
fetch "$BASE/$TARBALL" "$TMPDIR/$TARBALL"
fetch "$BASE/checksums.txt" "$TMPDIR/checksums.txt"

# --- checksum verification (required) --------------------------------------
say "anpu installer: verifying checksum..."
awk -v f="$TARBALL" '$2 == f { print }' "$TMPDIR/checksums.txt" > "$TMPDIR/$TARBALL.sha256"
if [ ! -s "$TMPDIR/$TARBALL.sha256" ]; then
  say "anpu installer: checksum entry for $TARBALL not found"
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$TMPDIR" && sha256sum -c "$TARBALL.sha256")
elif command -v shasum >/dev/null 2>&1; then
  (cd "$TMPDIR" && shasum -a 256 -c "$TARBALL.sha256")
elif command -v openssl >/dev/null 2>&1; then
  expected=$(awk '{print $1}' "$TMPDIR/$TARBALL.sha256")
  actual=$(openssl dgst -sha256 "$TMPDIR/$TARBALL" | sed -E 's/^.*= //')
  if [ "$expected" != "$actual" ]; then
    say "anpu installer: checksum mismatch (want $expected, got $actual)"
    exit 1
  fi
else
  say "anpu installer: no sha256sum, shasum, or openssl found"
  exit 1
fi

# --- cosign (optional) -----------------------------------------------------
if command -v cosign >/dev/null 2>&1; then
  say "anpu installer: verifying cosign signature..."
  fetch "$BASE/checksums.txt.sigstore.json" "$TMPDIR/checksums.txt.sigstore.json"
  cosign verify-blob --bundle "$TMPDIR/checksums.txt.sigstore.json" \
    --certificate-identity-regexp '^https://github.com/Marwanmorsy999/anpu/\.github/workflows/release\.yml@refs/tags/.*$' \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "$TMPDIR/checksums.txt"
else
  say "anpu installer: cosign not found, skipping signature verification"
fi

# --- extract and install ----------------------------------------------------
tar -xzf "$TMPDIR/$TARBALL" -C "$TMPDIR"

BIN_SRC="$TMPDIR/anpu"
if [ ! -f "$BIN_SRC" ]; then
  say "anpu installer: archive did not contain an anpu binary"
  exit 1
fi

if [ "$USE_SUDO" = "1" ]; then
  sudo cp "$BIN_SRC" "$INSTALL_DIR/anpu"
  sudo chmod +x "$INSTALL_DIR/anpu"
else
  cp "$BIN_SRC" "$INSTALL_DIR/anpu"
  chmod +x "$INSTALL_DIR/anpu"
fi

# --- macOS quarantine -------------------------------------------------------
if [ "$OS" = "darwin" ]; then
  if command -v xattr >/dev/null 2>&1; then
    if [ "$USE_SUDO" = "1" ]; then
      sudo xattr -d com.apple.quarantine "$INSTALL_DIR/anpu" 2>/dev/null || true
    else
      xattr -d com.apple.quarantine "$INSTALL_DIR/anpu" 2>/dev/null || true
    fi
  fi
  say "anpu installer: removed macOS quarantine attribute (if present)"
fi

# --- PATH hint --------------------------------------------------------------
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    if [ "$INSTALL_DIR" = "$HOME/.local/bin" ]; then
      say "anpu installer: make sure $INSTALL_DIR is on your PATH"
    fi
    ;;
esac

say "anpu installer: installed to $INSTALL_DIR/anpu"
"$INSTALL_DIR/anpu" version
