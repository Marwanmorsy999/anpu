# Releases and installation

This guide covers the supported ways to obtain ANPU, verify a release, build from source, and prepare a GitHub release.

## 1. Choose an installation method

### Quick install (recommended)

Linux / macOS:

```sh
curl -sSL https://raw.githubusercontent.com/Marwanmorsy999/anpu/main/install.sh | sh
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/Marwanmorsy999/anpu/main/install.ps1 | iex
```

Both scripts resolve the latest release, verify the SHA-256 checksum
against `checksums.txt`, verify the cosign signature over
`checksums.txt` when `cosign` is installed, and install the binary.
Useful overrides:

```sh
ANPU_VERSION=v0.3.1 install.sh            # pin a version
ANPU_INSTALL_DIR=$HOME/.local/bin install.sh  # unprivileged install
```

```powershell
$env:ANPU_VERSION = "v0.3.1"
$env:ANPU_INSTALL_DIR = "C:\tools\anpu"
```

### Native Linux packages

Each release also publishes `.deb`, `.rpm`, `.apk`, and Arch Linux
(`.pkg.tar.zst`) packages for amd64 and arm64 (see
`.goreleaser.yaml` → `nfpms` for the authoritative list):

```sh
sudo apt install ./anpu_<version>_linux_amd64.deb
sudo dnf install ./anpu_<version>_linux_amd64.rpm
sudo apk add ./anpu_<version>_linux_amd64.apk
sudo pacman -U ./anpu_<version>_linux_amd64.pkg.tar.zst
```

### Pre-built GitHub Release

The preferred path for most users is the repository's **Releases** page. Release archives are produced by GoReleaser and are published when a `v*` tag is pushed. The release workflow also smoke-tests the published Linux amd64 artifact before the workflow completes. See `.github/workflows/release.yml` for the authoritative automation.

Each release contains a platform archive, `checksums.txt`, and the
cosign signature bundle `checksums.txt.sigstore.json`. Every published
archive and package is additionally covered by SLSA build provenance
(GitHub artifact attestations, Sigstore-signed).

Current release targets are:

| OS | Architectures |
|---|---|
| Linux | amd64, arm64 |
| Windows | amd64, arm64 |
| macOS (darwin) | amd64, arm64 |

The archive name follows:

```text
anpu_<version>_<os>_<arch>.tar.gz
```

Windows archives also contain the `anpu.exe` binary.

### Build from source

Use this when you want the current `main` branch or need to inspect the exact source being built.

```sh
git clone https://github.com/Marwanmorsy999/anpu.git
cd anpu
go build -o anpu ./cmd/anpu
./anpu --version
./anpu --help
```

ANPU currently targets Go 1.26. Dependencies are declared in `go.mod` and locked by `go.sum`.

### Docker

Build the image locally:

```sh
docker build -t anpu .
```

Run a scan while keeping generated reports on the host:

```sh
docker run --rm \
  -v "$(pwd)/reports:/reports" \
  anpu scan https://example.com \
  --output /reports
```

Only scan systems you own or are explicitly authorized to test.

## 2. Verify a downloaded release

Three independent layers, strongest last. All three are produced by
`.github/workflows/release.yml` on every `v*` tag, and the workflow
re-verifies all three against the published files before finishing.

### 2a. SHA-256 checksum (required)

GoReleaser publishes `checksums.txt` alongside the release archives. Use it to verify the downloaded file before execution.

On Linux/macOS:

```sh
sha256sum anpu_<version>_linux_amd64.tar.gz
```

Compare the resulting SHA-256 digest with the corresponding entry in `checksums.txt`.

On PowerShell:

```powershell
Get-FileHash .\anpu_<version>_windows_amd64.tar.gz -Algorithm SHA256
```

The reported digest must match the release checksum.

### 2b. Cosign signature (recommended, needs `cosign`)

`checksums.txt` is signed keyless via Sigstore (Fulcio + Rekor) under
the release workflow's identity, and the bundle is published as
`checksums.txt.sigstore.json`. This proves the checksums — and
transitively every artifact — were produced by ANPU's release workflow,
not just by someone holding a file with matching hashes.

```sh
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/Marwanmorsy999/anpu/\.github/workflows/release\.yml@refs/tags/.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

Install cosign from https://docs.sigstore.dev/. The `install.sh` /
`install.ps1` scripts run this check automatically when `cosign` is on
`PATH` and fail closed if the signature is invalid.

### 2c. SLSA build provenance (strongest, needs `gh`)

Every file in `checksums.txt` carries a Sigstore-signed SLSA provenance
attestation (GitHub artifact attestations) recording exactly which
repository, workflow, and commit built it:

```sh
gh attestation verify anpu_<version>_linux_amd64.tar.gz --repo Marwanmorsy999/anpu
```

A passing verification means: this exact byte sequence was built from
commit `<sha>` of `Marwanmorsy999/anpu` by `.github/workflows/release.yml`.

## 3. Run the first scan

After extracting the archive:

```sh
./anpu --version
./anpu scan https://example.com
```

The default profile is `safe`. For a broader authorized assessment:

```sh
./anpu scan https://example.com --profile advanced --json --sarif
```

For CI gating:

```sh
./anpu scan https://staging.example.com \
  --profile advanced \
  --sarif \
  --fail-on high \
  --output ./reports
```

See [cli.md](cli.md) for the complete command reference and [configuration.md](configuration.md) for YAML configuration.

## 4. Understand the release contents

The release archive includes the executable plus these project files:

- `README.md`
- `LICENSE`
- `anpu.example.yaml`

The GoReleaser configuration also publishes `checksums.txt`. Release version and commit metadata are injected into the binary at build time.

## 5. Release process for maintainers

ANPU's release automation is tag-driven. A maintainer should:

1. Make sure `main` is green in CI.
2. Review `CHANGELOG.md` and update it for the release.
3. Decide the semantic version and create a tag such as `v0.2.0`.
4. Push the tag to GitHub:

```sh
git tag v0.2.0
git push origin v0.2.0
```

5. GitHub Actions starts `.github/workflows/release.yml`.
6. GoReleaser builds the configured OS/architecture matrix, creates archives, generates `checksums.txt`, and publishes the GitHub Release.
7. The workflow then attests every file in `checksums.txt` (SLSA provenance), signs `checksums.txt` with keyless cosign, and uploads `checksums.txt.sigstore.json` to the release.
8. The release workflow downloads the published Linux amd64 archive and runs `anpu --version` and `anpu --help` as a post-publish smoke test, then re-verifies the checksum, the cosign bundle, and the SLSA attestation against the published files.

Do not publish a release from a failing or unreviewed `main` branch.

## 6. Release checklist

Before creating the tag:

- [ ] `go build ./...` passes.
- [ ] `go vet ./...` passes.
- [ ] `go test -race ./...` passes.
- [ ] Docker build passes.
- [ ] The ANPU security integration scan passes.
- [ ] `README.md` matches the current CLI behavior.
- [ ] `docs/cli.md`, `docs/configuration.md`, and `docs/scanners.md` match the current implementation.
- [ ] `CHANGELOG.md` contains the release notes.
- [ ] Version/tag choice is intentional.

After publishing:

- [ ] Release is visible on GitHub.
- [ ] Expected archives are present.
- [ ] `checksums.txt` is present.
- [ ] `checksums.txt.sigstore.json` (cosign bundle) is present.
- [ ] Downloaded artifact checksum matches.
- [ ] `cosign verify-blob` passes (section 2b).
- [ ] `gh attestation verify` passes (section 2c).
- [ ] The published binary reports the expected version.
- [ ] The release notes clearly identify new features, fixes, limitations, and any breaking changes.

## 7. Version metadata

The version information is injected by GoReleaser into `pkg/version`. A release build therefore reports its release version and commit metadata through the CLI version command.

For source builds, the version can differ from published release artifacts depending on how the binary is built.

## 8. Support and security

For vulnerabilities or security-sensitive reports, follow [SECURITY.md](../SECURITY.md) rather than opening a public issue with exploit details.

For contribution and development guidance, see [CONTRIBUTING.md](../CONTRIBUTING.md) and [development.md](development.md).
