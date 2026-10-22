# Installation

See [releases.md](releases.md) for verification details.

## One-liners

Linux/macOS:
```sh
curl -fsSL https://raw.githubusercontent.com/Marwanmorsy999/anpu/main/install.sh | sh
```

Windows:
```powershell
irm https://raw.githubusercontent.com/Marwanmorsy999/anpu/main/install.ps1 | iex
```

Docker:
```sh
docker run --rm ghcr.io/marwanmorsy999/anpu scan https://example.com
```

## What the installer verifies

Both installers verify the downloaded archive against the release's
published SHA-256 checksum. That catches **corruption and modification
in transit** - a truncated download, a proxy that rewrote bytes, a
mirror that serves something else.

It does **not** prove authenticity. The published `checksums.txt` is
downloaded from the *same* place as the archive, so a hostile source can
serve a fake archive together with a matching checksum file and the
SHA-256 check still passes. For authenticity, verify the release
signature or the attestation:

```sh
# 1. cosign (needs cosign >= 2.5.0) over the published checksums.txt
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/Marwanmorsy999/anpu/\.github/workflows/release\.yml@refs/tags/.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

# 2. or the GitHub attestation for the file itself
gh attestation verify anpu_0.5.6_linux_amd64.tar.gz --repo Marwanmorsy999/anpu
```

The installers run the cosign check themselves when cosign >= 2.5.0 is
installed, and it is **mandatory** there: a verification failure aborts
the install.

### Installing from another source

`ANPU_BASE_URL` points the installers at a different download base (a
mirror, a local test server). Because a custom base cannot be trusted
the way the official release location can:

- a base URL that is not under `https://github.com/Marwanmorsy999/anpu/`
  prints a prominent warning, and
- without a usable cosign (>= 2.5.0) the installers **refuse** to
  install from it, unless `ANPU_ALLOW_CUSTOM_BASE_URL=1` is set, which
  means accepting a download that cannot be signature-verified.

```sh
ANPU_BASE_URL=https://mirror.example/anpu ANPU_ALLOW_CUSTOM_BASE_URL=1 sh install.sh
```

## Uninstall

```sh
curl -fsSL https://raw.githubusercontent.com/Marwanmorsy999/anpu/main/install.sh | sh -s -- --uninstall
ANPU_UNINSTALL=1 ANPU_PURGE=1 sh install.sh
```

```powershell
$env:ANPU_UNINSTALL = "1"; irm ... | iex
```

## Update

```sh
anpu update --check
anpu update
```