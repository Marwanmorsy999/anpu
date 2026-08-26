# Releases and installation

This guide covers the supported ways to obtain ANPU, verify a release, build from source, and prepare a GitHub release.

## 1. Choose an installation method

### Pre-built GitHub Release

The preferred path for most users is the repository's **Releases** page. Release archives are produced by GoReleaser and are published when a `v*` tag is pushed. The release workflow also smoke-tests the published Linux amd64 artifact before the workflow completes. See `.github/workflows/release.yml` for the authoritative automation.

Each release contains a platform archive and `checksums.txt`.

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

ANPU currently targets Go 1.25. Dependencies are declared in `go.mod` and locked by `go.sum`.

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

## 3. Run the first scan

After extracting the archive:

```sh
./anpu --version
./anpu scan https://example.com
```

The default profile is `safe`. For a broader authorized assessment:

```sh
./anpu scan https://example.com --profile standard --json --sarif
```

For CI gating:

```sh
./anpu scan https://staging.example.com \
  --profile standard \
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
7. The release workflow downloads the published Linux amd64 archive and runs `anpu --version` and `anpu --help` as a post-publish smoke test.

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
- [ ] Downloaded artifact checksum matches.
- [ ] The published binary reports the expected version.
- [ ] The release notes clearly identify new features, fixes, limitations, and any breaking changes.

## 7. Version metadata

The version information is injected by GoReleaser into `pkg/version`. A release build therefore reports its release version and commit metadata through the CLI version command.

For source builds, the version can differ from published release artifacts depending on how the binary is built.

## 8. Support and security

For vulnerabilities or security-sensitive reports, follow [SECURITY.md](../SECURITY.md) rather than opening a public issue with exploit details.

For contribution and development guidance, see [CONTRIBUTING.md](../CONTRIBUTING.md) and [development.md](development.md).
