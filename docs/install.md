# Installation

ANPU ships as a single static binary (Go, `CGO_ENABLED=0`) for
linux/darwin/windows on amd64 and arm64. Every release artifact is
signed and attested; verify before you trust it.

## Channels

| Channel | What you get | Verification |
|---|---|---|
| Release archive (tar.gz/zip) | Prebuilt binary + README/LICENSE/man page | sha256, cosign, gh attestation |
| One-liner (install.sh / install.ps1) | Downloads the matching release archive and installs | same as archive |
| deb / rpm / apk / pkg.tar.zst | Native package for apt/dnf/apk/pacman | package manager + checksums.txt |
| `go install github.com/Marwanmorsy999/anpu/cmd/anpu@latest` | Build from source | Go module checksums |

## Release archive

```sh
# Linux amd64 example; pick your os/arch from the release page.
curl -LO https://github.com/Marwanmorsy999/anpu/releases/download/vX.Y.Z/anpu_X.Y.Z_linux_amd64.tar.gz
curl -LO https://github.com/Marwanmorsy999/anpu/releases/download/vX.Y.Z/checksums.txt
sha256sum -c checksums.txt --ignore-missing
```

Cosign (keyless, sigstore):

```sh
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp 'https://github.com/Marwanmorsy999/anpu/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

GitHub attestation:

```sh
gh attestation verify anpu_X.Y.Z_linux_amd64.tar.gz \
  --repo Marwanmorsy999/anpu
```

## One-liner scripts

```sh
# Linux / macOS
curl -fsSL https://raw.githubusercontent.com/Marwanmorsy999/anpu/main/install.sh | sh
# Windows (PowerShell)
irm https://raw.githubusercontent.com/Marwanmorsy999/anpu/main/install.ps1 | iex
```

Both scripts download the matching release archive and run the same
sha256 verification; they do not bypass the checks above.

## Native packages

```sh
# Debian/Ubuntu
sudo dpkg -i anpu_X.Y.Z_linux_amd64.deb
# RHEL/Fedora
sudo rpm -i anpu_X.Y.Z_linux_amd64.rpm
# Alpine
sudo apk add --allow-untrusted anpu_X.Y.Z_linux_amd64.apk
```

## From source

```sh
go install github.com/Marwanmorsy999/anpu/cmd/anpu@latest
```

Requires Go 1.27.4+. Builds with `CGO_ENABLED=0`.

## Verifying claims

ANPU makes no claims beyond what the release artifacts demonstrate.
`docs/trust.md` lists the exact verification commands and their expected
output; if a claim there cannot be reproduced, treat it as a bug.