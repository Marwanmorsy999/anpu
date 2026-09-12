#!/bin/sh
# ANPU installer for Linux and macOS.
#
#   curl -sSL https://raw.githubusercontent.com/Marwanmorsy999/anpu/main/install.sh | sh
#
# Env knobs:
#   ANPU_VERSION     release tag, e.g. v0.3.1 (default: latest)
#   ANPU_INSTALL_DIR install directory (default: /usr/local/bin, falls
#                    back to $HOME/.local/bin when not writable)
#   ANPU_WITH_TOOLS  when "1", pre-install all advanced-level external
#                    tools via the binary itself (needs Go toolchain for
#                    go-based tools; failures are reported, never fatal)
set -eu

REPO="Marwanmorsy999/anpu"
VERSION="${ANPU_VERSION:-latest}"
INSTALL_DIR="${ANPU_INSTALL_DIR:-/usr/local/bin}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "anpu installer: missing required tool: $1" >&2
    exit 1
  }
}

need curl
need tar

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$OS" in
  linux) OS="linux" ;;
  darwin) OS="darwin" ;;
  *)
    echo "anpu installer: unsupported OS: $OS (build from source: go build -o anpu ./cmd/anpu)" >&2
    exit 1
    ;;
esac

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64 | amd64) ARCH="amd64" ;;
  arm64 | aarch64) ARCH="arm64" ;;
  *)
    echo "anpu installer: unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

if [ "$VERSION" = "latest" ]; then
  echo "anpu installer: resolving latest release..." >&2
  VERSION="$(curl -sSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')"
  if [ -z "$VERSION" ]; then
    echo "anpu installer: could not resolve latest release (set ANPU_VERSION=vX.Y.Z explicitly)" >&2
    exit 1
  fi
fi

BASE="https://github.com/$REPO/releases/download/$VERSION"
TARBALL="anpu_${VERSION#v}_${OS}_${ARCH}.tar.gz"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT INT TERM

echo "anpu installer: downloading $TARBALL ($VERSION)..." >&2
curl -sSL --fail -o "$TMPDIR/$TARBALL" "$BASE/$TARBALL"
curl -sSL --fail -o "$TMPDIR/checksums.txt" "$BASE/checksums.txt"

echo "anpu installer: verifying checksum..." >&2
(cd "$TMPDIR" && grep "  $TARBALL\$" checksums.txt > want.sha256)
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$TMPDIR" && sha256sum -c want.sha256)
elif command -v shasum >/dev/null 2>&1; then
  (cd "$TMPDIR" && shasum -a 256 -c want.sha256)
else
  echo "anpu installer: no sha256sum/shasum found, skipping verification (NOT recommended)" >&2
fi

# Cosign signature over checksums.txt (Sigstore keyless, published per
# release as checksums.txt.sigstore.json). Verified when cosign is
# available; otherwise the SHA-256 check above is the verification.
if command -v cosign >/dev/null 2>&1; then
  echo "anpu installer: verifying cosign signature..." >&2
  curl -sSL --fail -o "$TMPDIR/checksums.txt.sigstore.json" "$BASE/checksums.txt.sigstore.json"
  cosign verify-blob --bundle "$TMPDIR/checksums.txt.sigstore.json" \
    --certificate-identity-regexp "^https://github.com/$REPO/\.github/workflows/release\.yml@refs/tags/.*$" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "$TMPDIR/checksums.txt"
else
  echo "anpu installer: cosign not found, skipping signature verification (checksum verified; install cosign from https://docs.sigstore.dev for full verification)" >&2
fi

tar -xzf "$TMPDIR/$TARBALL" -C "$TMPDIR"

BIN_SRC="$TMPDIR/anpu"
if [ ! -x "$BIN_SRC" ]; then
  echo "anpu installer: archive did not contain an anpu binary" >&2
  exit 1
fi

# Fall back to ~/.local/bin when the target dir is not writable (no sudo).
if [ ! -w "$INSTALL_DIR" ]; then
  if [ "$INSTALL_DIR" = "/usr/local/bin" ]; then
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
    echo "anpu installer: $INSTALL_DIR is not writable, installing to $INSTALL_DIR instead" >&2
    echo "anpu installer: make sure $INSTALL_DIR is on your PATH" >&2
  else
    echo "anpu installer: $INSTALL_DIR is not writable (re-run with sudo?)" >&2
    exit 1
  fi
fi

cp "$BIN_SRC" "$INSTALL_DIR/anpu"
chmod +x "$INSTALL_DIR/anpu"
echo "anpu installer: installed $($INSTALL_DIR/anpu --version 2>/dev/null || echo anpu) to $INSTALL_DIR/anpu" >&2
if [ "${ANPU_WITH_TOOLS:-0}" = "1" ]; then
  echo "anpu installer: pre-installing advanced external tools (ANPU_WITH_TOOLS=1)..." >&2
  "$INSTALL_DIR/anpu" tools install --all --level advanced --yes >&2 || echo "anpu installer: some tools failed (see above); scans warn-and-skip missing ones" >&2
fi
echo "anpu installer: run 'anpu scan https://example.com' for a first safe scan (only against targets you own or are authorized to test)" >&2
echo "anpu installer: tip: 'anpu scan --auto-install' self-provisions missing tools on first use" >&2
