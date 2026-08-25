# ANPU

**Guard what you build.**
*Authorized web security analysis and attack-surface intelligence CLI.*

[Install](#3-installation) &middot; [Documentation](#5-architecture) &middot; [Releases](https://github.com/Marwanmorsy999/anpu/releases)

![Build Status](https://img.shields.io/github/actions/workflow/status/Marwanmorsy999/anpu/ci.yml?branch=main&style=flat-square)
![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go)
![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)
![SARIF](https://img.shields.io/badge/SARIF-Supported-success?style=flat-square)
![Docker](https://img.shields.io/badge/Docker-Supported-2496ED?style=flat-square&logo=docker)

### 🔗 Quick Links
- 🎯 **[Risk Scoring Deep Dive](./docs/scoring.md)** - Understand our transparent scoring math.
- ⚙️ **[CI/CD Integration](./docs/ci-cd.md)** - Drop-in workflows for GitHub Actions.
- 🛡️ **[Security Policy](./SECURITY.md)** - Responsible disclosure & safety.

```bash
$ anpu scan https://example.com

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

Results
CRITICAL     0
HIGH         0
MEDIUM       2
LOW          5
INFO         11

Risk Score: 3.4/10
Report: ./reports/example.html
```

## Why ANPU?

ANPU orchestrates existing security tools (like Nuclei) alongside its own passive analyzers, and combines the results into a single, unified, understandable security report. Unlike cloud scanners, ANPU runs entirely as a single local Go binary, ensuring your scan data stays completely private.

> ⚠️ **ANPU performs active network requests against the target you give it.** Only scan targets you own or are explicitly authorized to test. See [SECURITY.md](./SECURITY.md).

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

Requires Go 1.25+.

```bash
git clone https://github.com/Marwanmorsy999/anpu
cd anpu
go build -o anpu ./cmd/anpu
./anpu --help
```

Dependencies (Cobra, pflag, yaml.v3, and the pure-Go SQLite driver) are
resolved normally through the Go module proxy on first build; `go.sum`
pins every version. ANPU uses a pure-Go SQLite driver
(`modernc.org/sqlite`), so **no C compiler (cgo) is needed** — `go build`
works out of the box on Windows, macOS, and Linux. A prebuilt Docker
image is also provided (see below).

### Docker

```bash
docker build -t anpu .
docker run --rm -v "$(pwd)/reports:/reports" anpu scan https://example.com --output /reports
```

## 4. Quick start

```bash
# See every engine and what each profile enables
./anpu tools

# Safe (default) profile — passive analysis only, HTML report
./anpu scan https://example.com

# Standard profile — + sensitive-path probing, JS secrets hunt,
# CORS/method audits, subdomain CT-log enumeration, and Nuclei
# templates if nuclei is installed
./anpu scan https://example.com --profile standard --json --sarif

# Deep profile — everything above + DNS brute-force of common
# subdomains and a TCP connect scan of common ports
./anpu scan https://example.com --profile deep --html

# View past scans
./anpu history

# Re-view a specific scan
./anpu show scan-1234567890-1

# Compare two historical scans
./anpu diff scan-old scan-new
```

### Built-in engines

| Engine        | What it does | Profile |
|---------------|--------------|---------|
| Recon         | DNS, robots.txt, sitemap.xml, redirect chain, source maps | all |
| Technology    | passive stack fingerprinting (headers/cookies/HTML/JS) | all |
| TLS           | certificate validity/expiry, protocol versions, HTTPS redirect | all |
| Headers       | security-header presence & quality | all |
| Cookies       | Secure / HttpOnly / SameSite audit | all |
| Endpoints     | link/form/script/API discovery from HTML+JS | all |
| Subdomains    | Certificate-Transparency enumeration (+ DNS brute on deep) | standard+ |
| PortScan      | TCP connect scan of ~36 common service ports | deep |
| Dirs          | sensitive-path probing (`.env`, `.git`, backups…) with soft-404 baseline | standard+ |
| Secrets       | AWS/GCP/GitHub/Slack keys, JWTs, private-key blocks in served assets | standard+ |
| CORS          | origin-reflection + credentials misconfiguration | standard+ |
| Methods       | OPTIONS audit with live TRACE/XST verification | standard+ |
| Nuclei        | template-based vuln scanning (optional external binary) | standard+ |

All engines run behind the same SSRF/local-network guard as the core
scanner. When a CDN (Cloudflare, CloudFront, …) is fingerprinted,
port-scan results are annotated to note they may reflect the CDN edge
rather than your origin.

### Accuracy engineering

Content-discovery results are filtered through several false-positive
defenses, each validated against real sites:

- **Soft-404 baselines** — two random probe paths calibrate what this
  server's "not found" looks like; catch-all routers (SPAs, parked
  hosting) are detected via body similarity.
- **App-shell detection** — sites that answer unknown paths with HTTP 200
  and a copy of their own homepage (e.g. github.com's shell) are filtered
  by Jaccard word-similarity against the root page.
- **WAF rejection handling** — only 2xx counts as exposure and 401/403 as
  "present but protected"; other rejections (406 WAF blocks, 410 gone)
  are ignored rather than inflated into findings.
- **Port-scan sanity probe** — if ports 1/9 accept connections (a
  transparent proxy answering for everything), scan results are
  suppressed with a warning instead of reported.

### Testing

```bash
go test ./...                       # full offline suite

# Live-site integration test (hits https://example.com over the network):
ANPU_LIVE_TESTS=1 go test -run TestLiveScanExample -v ./cmd/anpu
```

## 5. Architecture

```
cmd/anpu/              CLI entry point (Cobra commands: scan, history, show, diff, tools)

internal/
  scanner/              Scanner interface, target validation, pipeline orchestrator
  diff/                 Historical scan comparison and attack-surface change detection
  recon/                Passive recon (DNS, robots.txt, sitemap.xml, redirects)
  http/                 Shared HTTP client (timeouts, redirect/SSRF guards)
  technology/            Technology fingerprinting
  tls/                  Passive TLS analysis
  headers/              Security headers + cookie analysis
  endpoints/             Endpoint discovery/normalization
  subdomains/            Subdomain enumeration (CT logs + DNS brute-force)
  portscan/              TCP connect scan of common ports
  dirs/                  Sensitive-path content discovery with soft-404 baseline
  secrets/               API-key/token/private-key scanning of discovered assets
  cors/                  CORS misconfiguration detection
  methods/               HTTP method / XST auditing
  findings/              Deduplication engine
  scoring/               Transparent risk scoring
  storage/                SQLite persistence (scan history)
  integrations/          Nuclei (implemented) + ZAP (prepared interface)
  reporting/              JSON / SARIF / HTML report generation, terminal UI
  config/                 YAML config loading + CLI-flag resolution

pkg/models/             Shared, scanner-agnostic data model (Finding, Technology,
                        Endpoint, ScanSummary, ...)

third_party/            (removed — dependencies come from the Go module proxy)
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
- **OWASP ZAP** (`internal/integrations/zap.go`) - **[Status: Planned / Interface Defined]**: The interface is defined and wired into the pipeline (`Available()` returns `false`), but the actual ZAP driver is not implemented yet. This is a real extension point on our roadmap, designed to eventually support full DAST orchestration.

## 10. Development

```bash
go build ./...
go vet ./...
go test ./...
gofmt -l $(find . -name '*.go')   # should print nothing
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
