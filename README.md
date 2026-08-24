# ANPU

**Guard what you build.**

ANPU is an open-source, authorized web security analysis and
attack-surface intelligence CLI. It orchestrates existing security
tools (Nuclei today, OWASP ZAP planned) alongside its own passive
analyzers, and combines the results into a single, unified,
understandable security report — as a single local Go binary, no cloud
services required.

> ⚠️ **ANPU performs active network requests against the target you give
> it.** Only scan targets you own or are explicitly authorized to test.
> See [SECURITY.md](./SECURITY.md).

---

## 1. What ANPU is

ANPU is **not** another from-scratch vulnerability scanner. Its job is
to:

1. Run its own passive analyzers (HTTP headers, cookies, TLS,
   technology fingerprinting, recon, endpoint discovery).
2. Optionally invoke real, independently-maintained scanners (Nuclei;
   ZAP in the future) as subprocesses/APIs.
3. Normalize every result — from any source — into one unified,
   evidence-backed finding model.
4. Deduplicate findings that multiple tools reported for the same
   underlying issue.
5. Score every finding transparently (documented, deterministic
   scoring — never an opaque or AI-generated number).
6. Produce a polished HTML report (plus JSON/SARIF for tooling), and
   store scan history locally in SQLite.

## 2. What it does

- **Recon**: DNS resolution, robots.txt/sitemap.xml parsing, redirect
  chain observation, source-map exposure detection.
- **HTTP / security headers**: CSP, HSTS, X-Content-Type-Options,
  Referrer-Policy, Permissions-Policy, Server/X-Powered-By disclosure.
- **Cookies**: Secure, HttpOnly, SameSite, with context-aware severity.
- **TLS**: certificate validity, expiration, hostname match, protocol
  version, HTTP→HTTPS redirect behavior.
- **Technology fingerprinting**: web servers, frameworks, CMSs, CDNs,
  JS libraries — from headers, cookies, and page content, with
  confidence scores and no invented version numbers.
- **Endpoint discovery**: links, forms, and JS references, normalized
  and categorized (page / api / asset / authentication / admin-like /
  unknown).
- **Nuclei integration** (optional): runs real `nuclei` templates
  scoped to the selected profile, converts results into ANPU findings.
- **Deduplication**: merges the same underlying issue across sources
  while preserving every original piece of evidence.
- **Transparent risk scoring**: severity × confidence + exposure +
  corroboration, with a documented formula attached to every score.

## 3. Installation

Requires Go 1.22+.

```bash
git clone https://github.com/Marwanmorsy999/anpu
cd anpu
go build -o anpu ./cmd/anpu
./anpu --help
```

ANPU's (small) dependency set — Cobra, pflag, go-sqlite3, and
yaml.v3 — is vendored under `third_party/` via `go.mod` replace
directives, so this builds fully offline once you have the repository;
no `go mod download` step, no external module proxy required.

`go-sqlite3` uses cgo, so a C compiler (`gcc`/`clang`) must be
available at build time. A prebuilt Docker image is also provided (see
below) if you'd rather not install a toolchain locally.

### Docker

```bash
docker build -t anpu .
docker run --rm -v "$(pwd)/reports:/reports" anpu scan https://example.com --output /reports
```

## 4. Quick start

```bash
# Safe (default) profile — passive analysis only, HTML report
./anpu scan https://example.com

# Standard profile — adds Nuclei's exposure/misconfig/CVE templates,
# if nuclei is installed
./anpu scan https://example.com --profile standard --json --sarif

# View past scans
./anpu history

# Re-view a specific scan
./anpu show scan-1234567890-1

# Compare two historical scans
./anpu diff scan-old scan-new
```

## 5. Architecture

```
cmd/anpu/              CLI entry point (Cobra commands: scan, history, show)

internal/
  scanner/              Scanner interface, target validation, pipeline orchestrator
  diff/                 Historical scan comparison and attack-surface change detection
  recon/                Passive recon (DNS, robots.txt, sitemap.xml, redirects)
  http/                 Shared HTTP client (timeouts, redirect/SSRF guards)
  technology/            Technology fingerprinting
  tls/                  Passive TLS analysis
  headers/              Security headers + cookie analysis
  endpoints/             Endpoint discovery/normalization
  findings/              Deduplication engine
  scoring/               Transparent risk scoring
  storage/                SQLite persistence (scan history)
  integrations/          Nuclei (implemented) + ZAP (prepared interface)
  reporting/              JSON / SARIF / HTML report generation, terminal UI
  config/                 YAML config loading + CLI-flag resolution

pkg/models/             Shared, scanner-agnostic data model (Finding, Technology,
                        Endpoint, ScanSummary, ...)

third_party/            Vendored dependencies (cobra, pflag, go-sqlite3, yaml.v3)
rules/                  Reserved for future custom detection rules
tests/                  Shared test fixtures/helpers
docs/                   Additional documentation
```

**Design principle**: `internal/scanner` defines a single `Scanner`
interface (`Name`, `Available`, `Run`). Every analyzer and every
external tool integration implements it, and the orchestrator only
ever depends on that interface — never on a concrete scanner. Adding a
new scanner means implementing the interface and registering it in
`cmd/anpu/scan.go`'s `buildPipeline`; nothing else in the pipeline
changes.

## 6. Scan profiles

| Profile    | Passive analysis | Nuclei | Notes |
|------------|:---:|:---:|---|
| `safe` (default) | ✅ | ❌ | Headers, cookies, TLS, technology, recon, endpoints only |
| `standard` | ✅ | ✅ (exposure, misconfig, tech, ssl, cve tags) | |
| `deep`     | ✅ | ✅ (broader template set, all severities) | |

`--no-nuclei` / `--no-zap` (or `nuclei: false` / `zap: false` in
config) disable those integrations regardless of profile. ZAP is a
prepared-but-unimplemented interface in this MVP — see
`internal/integrations/zap.go`.

## 7. Scan comparison and CI gates

ANPU keeps complete scan history locally, which enables deterministic
attack-surface and risk comparisons without sending scan data to a
cloud service.

```bash
# Human-readable comparison
./anpu diff scan-old scan-new

# Machine-readable comparison
./anpu diff scan-old scan-new --json --output ./reports/diff.json

# Fail CI when a scan contains high or critical findings
./anpu scan https://example.com --profile standard --sarif --fail-on high
```

`--fail-on` exits non-zero after reports and scan history are written.
Supported thresholds are `low`, `medium`, `high`, and `critical`; the
default is `none`. `anpu diff` requires both scans to target the same
URL and reports changes to findings, endpoints, technology versions, and
the aggregate risk score.

## 8. Output examples

Terminal:

```
        ▄▀█ █▄░█ █▀█ █░█
        █▀█ █░▀█ █▀▀ █▄█
   Web Security Intelligence

Target: https://example.com

Recon              ✓
Technology         ✓
TLS                ✓
Headers            ✓
Cookies            ✓
Endpoints          ✓
Nuclei             -
ZAP                -

Results

CRITICAL     0
HIGH         2
MEDIUM       5
LOW          8
INFO         11

Risk Score: 6.4/10

Report:
./reports/example-2026-08-24.html
```

`--json` and `--sarif` write machine-readable equivalents; `--sarif`
output can be consumed by GitHub code scanning workflows or other SARIF-compatible tooling.

## 9. Integrations

- **Nuclei** (`internal/integrations/nuclei.go`): if `nuclei` is on
  `PATH`, ANPU invokes it with a template scope matched to the
  selected profile, parses its `-jsonl` output, and converts each
  match into an ANPU finding, preserving the original template ID and
  match evidence. If Nuclei isn't installed, ANPU logs a warning and
  continues — it never fails the whole scan.
- **OWASP ZAP** (`internal/integrations/zap.go`): interface is
  defined and wired into the pipeline (`Available()` returns `false`),
  but the actual ZAP driver is not implemented yet. This is a real
  extension point, not a fake scanner.

## 10. Development

```bash
go build ./...
go vet ./...
go test ./...
gofmt -l $(find . -name '*.go' | grep -v third_party)   # should print nothing
```

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the full guide, including
how to add a new analyzer or external tool integration.

## 11. Contributing

Contributions are welcome — see [CONTRIBUTING.md](./CONTRIBUTING.md).
Please read [SECURITY.md](./SECURITY.md) first: ANPU has hard safety
boundaries (no local-network scanning by default, no destructive
actions, no fabricated evidence) that all contributions must respect.

## 12. Responsible use

ANPU performs active network requests. **Only scan targets you own or
are explicitly authorized to test.** Unauthorized scanning may be
illegal in your jurisdiction. ANPU's `safe` default profile and
local-network guard reduce the risk of *accidental* harm, but do not
constitute authorization — that responsibility is yours. See
[SECURITY.md](./SECURITY.md) for the full list of built-in safety
boundaries.

---

License: [Apache-2.0](./LICENSE)
