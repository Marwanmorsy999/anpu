# CI/CD Integration

ANPU is designed to be a frictionless addition to your CI/CD pipelines. Because it runs locally and doesn't rely on a cloud backend, you can integrate it easily into any CI runner; GitHub Actions is shown below (GitLab CI can consume the same SARIF output via its SAST report artifact).

## Configuring for CI Environments

When running ANPU in a CI environment, consider the following flags:

- `--profile safe|standard|deep`: controls how active the scan is (`safe` is fully passive).
- `--fail-on <severity>`: exits with a non-zero status code if vulnerabilities of the specified severity (or higher) are found, breaking the build.
- `--sarif`: generates a SARIF report, the standard format for importing results into platforms like GitHub Code Scanning.

> **Report naming:** ANPU writes one report file per run with a timestamped
> name (for example `127.0.0.1-2026-01-02-150405.sarif`). Point your upload
> step at a glob such as `./reports/*.sarif` rather than a fixed filename.
>
> **Scan authorization:** never scan targets you do not own or are not
> authorized to test. Scanning real third-party websites from CI is both a
> policy violation and a source of flaky builds — target your own staging
> environment or a local fixture.

## Project Self-Test Workflow

The repository ships its own security self-test in `.github/workflows/scan.yml`.
It scans **OWASP Juice Shop** running as a service container on the runner's own
loopback (`http://127.0.0.1:3000`). The scan itself is loopback-only: the only
external traffic is GitHub/Docker Hub/module-proxy infrastructure, never a
third-party scan target.

Because the fixture is intentionally vulnerable, the workflow does **not** gate
with `--fail-on`; its purpose is pipeline validation (the SARIF upload must
succeed), not vulnerability gating. Between the scan and upload steps, the
workflow also asserts that exactly one SARIF file exists, its driver name is
`ANPU`, and at least one result is present — so an upload can never silently
publish an empty or malformed report.

Key elements of that workflow:

```yaml
permissions:
  contents: read
  # Required by github/codeql-action/upload-sarif@v3.
  security-events: write

services:
  juice-shop:
    # Pinned to an immutable digest (Juice Shop v20.2.0; matches
    # .github/workflows/scan.yml).
    image: bkimminich/juice-shop@sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e
    ports: [ "3000:3000" ]
    options: >-
      --health-cmd "wget -qO- http://127.0.0.1:3000/ >/dev/null || exit 1"
      --health-interval 10s --health-timeout 5s --health-retries 12
```

```yaml
      - name: Run ANPU Scan (self-test against local fixture)
        env:
          # Loopback guard override — see the note below this workflow
          # before reusing outside 127.0.0.1.
          ANPU_ALLOW_LOCAL_NETWORK: "1"
        run: |
          # --json is kept for debugging failed runs; assertions only use SARIF.
          ./anpu scan http://127.0.0.1:3000 \
            --profile safe \
            --sarif --json --html=false \
            --output ./reports/

      - name: Upload SARIF Report
        if: always() && (github.event_name != 'pull_request' || !github.event.pull_request.head.repo.fork)
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ./reports/*.sarif   # glob: filenames are timestamped
          category: anpu-scan
```

Note on `ANPU_ALLOW_LOCAL_NETWORK=1`: by default ANPU refuses to scan
loopback, private, and link-local addresses. The environment variable disables
that guard for the current process only — enable it exclusively for scans
against infrastructure you control, such as this loopback fixture.

> Scheduled workflows are automatically disabled after 60 days of repository
> inactivity; re-enable them from the Actions tab if that happens.

## Downstream User Template

Copy-paste starting point for integrating ANPU into *your* project's CI. It
scans your staging URL, fails the build on high-severity findings, and uploads
SARIF results to the GitHub Security tab. Save the following as
`.github/workflows/anpu-scan.yml` in your repository:

```yaml
name: "ANPU Security Scan"

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]
  schedule:
    - cron: '0 3 * * 1' # Weekly, Mondays at 03:00 UTC

permissions:
  contents: read
  security-events: write

jobs:
  security-scan:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          # Installs the latest stable Go, which is what building ANPU from
          # source requires (>= 1.25, see its go.mod). Do NOT use
          # `go-version-file: go.mod` here: your project may have no go.mod,
          # or an older toolchain than ANPU needs.
          go-version: stable

      - name: Install ANPU
        # Built from source because the Go module path (go.mod) does not
        # match this repo URL, so `go install <repo>/cmd/anpu@latest`
        # cannot resolve. Clones the current default branch — pin with
        # `--branch <tag>` if you want frozen scanner versions.
        # Revisit this install method if the module path is ever renamed.
        run: |
          git clone --depth 1 https://github.com/Marwanmorsy999/anpu.git "$RUNNER_TEMP/anpu-src"
          go build -C "$RUNNER_TEMP/anpu-src" -o "$RUNNER_TEMP/bin/anpu" ./cmd/anpu
          echo "$RUNNER_TEMP/bin" >> "$GITHUB_PATH"

      - name: Run ANPU Scan
        # Replace <your-staging-url> with a target you own, e.g. https://staging.example.com
        run: |
          anpu scan "<your-staging-url>" \
            --profile standard \
            --fail-on high \
            --sarif \
            --output ./reports/

      - name: Upload SARIF Report
        # Fork PRs receive a read-only token, so skip the (failing) upload
        # there; code scanning only accepts uploads from the base repo.
        if: always() && (github.event_name != 'pull_request' || !github.event.pull_request.head.repo.fork)
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ./reports/*.sarif
          category: anpu-scan
```

Notes for downstream users:

- The SARIF filename is timestamped, so `./reports/*.sarif` is used instead of
  a fixed path.
- `security-events: write` is required by the upload step; without it the job
  fails with a 403.
- On fork pull requests the upload step is skipped entirely (fork runs receive
  a read-only token); only builds on the base repository publish results to
  code scanning.
- If your repository is private without GitHub Advanced Security,
  `upload-sarif` is rejected — swap it for `actions/upload-artifact` instead.
