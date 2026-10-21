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

say() { printf '%s\n' "$*" >&2; }

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

# --- fetch tool selection ---------------------------------------------------
# The selected tool is always logged. A silent tool switch is exactly what
# made the old `wget -q` path fail without printing a single word.
if command -v curl >/dev/null 2>&1; then
  FETCH=curl
  say "anpu installer: using curl to download releases"
elif command -v wget >/dev/null 2>&1; then
  FETCH=wget
  say "anpu installer: curl not found, using wget to download releases"
else
  say "anpu installer: missing required tool: curl or wget"
  exit 1
fi

# classify_failure <detail> <exit-code>
# Prints the failure reason for a download: HTTP error, TLS error or
# network error. Shared by curl and wget so both report the same way.
#
# Order matters: a definite HTTP status (404/403/500, "server returned
# error") wins over TLS-ish wording, because BusyBox wget prints
# "note: TLS certificate validation not implemented" on *every* HTTPS
# transfer - that note is stripped first so a plain 404 is not reported
# as a TLS error.
classify_failure() {
  detail=$1
  rc=$2
  clean=$(printf '%s\n' "$detail" | grep -v 'note: TLS certificate validation not implemented' || true)
  case "$clean" in
    *server\ returned\ error*|*HTTP\ error*|*returned\ error*|*404*|*403*|*500*|*Not\ Found*|*Forbidden*|*Unauthorized*|*Bad\ Request*|*Internal\ Server\ Error*)
      printf 'HTTP error'
      return 0
      ;;
  esac
  case "$clean" in
    *SSL*|*ssl*|*certificate*|*Certificate*|*handshake*|*not\ trusted*|*known\ issuer*|*issuer*|*unable\ to\ establish*|*tlsv1*|*wrong\ version\ number*)
      printf 'TLS error'
      return 0
      ;;
  esac
  case "$rc" in
    22|8) printf 'HTTP error' ;;
    5|35|51|53|54|58|59|60|64|66|77|80|82|83|90|91) printf 'TLS error' ;;
    *) printf 'network error' ;;
  esac
}

fetch() {
  url=$1
  dest=$2
  if [ "$FETCH" = "curl" ]; then
    if out=$(curl -fsSL --fail -o "$dest" "$url" 2>&1); then
      rc=0
    else
      rc=$?
    fi
    if [ "$rc" -eq 0 ]; then
      return 0
    fi
    reason=$(classify_failure "$out" "$rc")
    rm -f "$dest"
    say "anpu installer: download failed for $url ($reason, curl exit $rc): $out"
    exit 1
  else
    # BusyBox wget has no -nv/--no-verbose, so probe before using it.
    if wget --help 2>&1 | grep -q -- '--no-verbose'; then
      if out=$(wget -nv -O "$dest" "$url" 2>&1); then
        return 0
      else
        rc=$?
      fi
    else
      if out=$(wget -O "$dest" "$url" 2>&1); then
        return 0
      else
        rc=$?
      fi
    fi
    reason=$(classify_failure "$out" "$rc")
    rm -f "$dest"
    say "anpu installer: download failed for $url ($reason, wget exit $rc): $out"
    exit 1
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
  if [ ! -e "$INSTALL_DIR" ]; then
    if ! mkdir -p "$INSTALL_DIR" 2>/dev/null; then
      if command -v sudo >/dev/null 2>&1; then
        USE_SUDO=1
        sudo mkdir -p "$INSTALL_DIR" || {
          say "anpu installer: $INSTALL_DIR does not exist"
          exit 1
        }
      else
        say "anpu installer: $INSTALL_DIR does not exist"
        exit 1
      fi
    fi
  elif [ ! -w "$INSTALL_DIR" ]; then
    if command -v sudo >/dev/null 2>&1; then
      USE_SUDO=1
    else
      say "anpu installer: $INSTALL_DIR is not writable"
      exit 1
    fi
  else
    mkdir -p "$INSTALL_DIR"
  fi
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

# --- cosign (signature over checksums.txt; needs cosign >= 2.5.0) ------------
# Bundles are sigstore bundle v0.3, which cosign only learned to read in
# v2.5.0. Older cosign hard-fails with "bundle does not contain cert for
# verification" — so treat missing/old cosign as skip-with-warning, and
# abort only when a new-enough cosign reports a real verification failure.
# SHA-256 verification above stays mandatory in every case.
COSIGN_MIN="2.5.0"
# Portable major.minor.patch compare: returns 0 when $1 >= $2.
ver_ge() {
  a=${1#v}; b=${2#v}
  a1=${a%%.*}; rest=${a#*.}; a2=${rest%%.*}; a3=${rest#*.}; a3=${a3%%[^0-9]*}
  b1=${b%%.*}; rest=${b#*.}; b2=${rest%%.*}; b3=${rest#*.}; b3=${b3%%[^0-9]*}
  [ "${a1:-0}" -gt "${b1:-0}" ] && return 0
  [ "${a1:-0}" -lt "${b1:-0}" ] && return 1
  [ "${a2:-0}" -gt "${b2:-0}" ] && return 0
  [ "${a2:-0}" -lt "${b2:-0}" ] && return 1
  [ "${a3:-0}" -ge "${b3:-0}" ]
}
if command -v cosign >/dev/null 2>&1; then
  COSIGN_VER=$(cosign version 2>/dev/null | sed -n 's/.*GitVersion:[[:space:]]*\(v[0-9][0-9.]*\).*/\1/p' | head -n 1)
  if [ -z "$COSIGN_VER" ]; then
    COSIGN_VER=$(cosign version 2>/dev/null | grep -oE 'v?[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)
  fi
  if [ -z "$COSIGN_VER" ] || ! ver_ge "$COSIGN_VER" "$COSIGN_MIN"; then
    say "anpu installer: WARNING: cosign ${COSIGN_VER:-unknown} found, but signature verification requires cosign >= v2.5.0 — skipping signature verification (SHA-256 verification already passed)"
  else
    say "anpu installer: verifying cosign signature..."
    fetch "$BASE/checksums.txt.sigstore.json" "$TMPDIR/checksums.txt.sigstore.json"
    cosign verify-blob --bundle "$TMPDIR/checksums.txt.sigstore.json" \
      --certificate-identity-regexp '^https://github.com/Marwanmorsy999/anpu/\.github/workflows/release\.yml@refs/tags/.*$' \
      --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
      "$TMPDIR/checksums.txt"
  fi
else
  say "anpu installer: cosign not found, skipping signature verification (signature verification requires cosign >= v2.5.0)"
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
