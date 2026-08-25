# Changelog

## 0.3.1 (Unreleased)

- **CI self-test**: security scanning now runs only against a pinned local OWASP Juice Shop fixture and uploads generated reports as workflow artifacts instead of GitHub Code Scanning.
- **SARIF validation**: CI verifies SARIF 2.1.0 structure, ANPU tool identity, and non-empty results before archiving reports.
- **CI reliability**: workflow uses the Go version declared in `go.mod`, adds concurrency/timeout controls, and removes the floating Nuclei installation from the security workflow.
- **Build/supply-chain**: pure-Go SQLite via `modernc.org/sqlite`, reproducible Docker build settings, and automated vulnerability checking remain enabled.
- **Scanner engines**: added subdomain enumeration, port scanning, directory discovery, secret detection, CORS checks, and HTTP-method auditing with profile gating and accuracy safeguards.

## 0.3.0

- **Repo cleanup**: removed the entire vendored `third_party/` tree (~106 files of upstream cobra/pflag/yaml.v3/mousetrap sources and their replace directives). Dependencies now resolve normally from the Go module proxy, pinned by `go.sum`.
- **New engines (all built-in, zero external dependencies)**: subdomain enumeration via Certificate Transparency logs with optional DNS brute-forcing, a TCP connect port scanner for common service ports, sensitive-path content discovery with soft-404 baseline detection, JS/asset secrets hunting (AWS/GCP/GitHub/Slack keys, JWTs, private-key blocks), CORS origin-reflection auditing, and HTTP-method/XST verification.
- **Profile ladder**: `safe` is fully passive; `standard` adds the active-but-polite engines; `deep` enables DNS brute-force and the port scan. Every engine can be toggled individually via the `modules:` config section.
- **False-positive hardening for content discovery** (validated against live sites): dual soft-404 baselines with Jaccard similarity catch catch-all routers (SPAs, parked hosting); app-shell detection filters HTTP 200 copies of the site's own root page; WAF rejections (406) and intentional removals (410) are no longer reported as exposures.
- **Port-scan sanity probe**: when sanity-check ports 1/9 accept connections (transparent proxy answering for all ports), results are suppressed with a warning instead of reported.
- Added `anpu tools` doctor command listing built-in engines, optional integrations, and profile contents.
- Port-scan results now carry a CDN caveat when Cloudflare/CloudFront/Vercel/Fastly are fingerprinted, since scanned addresses may be the CDN edge rather than the origin.
- Sensitive-path findings distinguish readable exposure from 401/403 "present but protected" responses.
- New shared `DoWithHeaders` client method keeps custom probes (CORS/methods) behind the same SSRF guards as core requests.
- Added live-site integration test (`ANPU_LIVE_TESTS=1 go test -run TestLiveScanExample ./cmd/anpu`) that runs the full pipeline against example.com and validates the JSON report end-to-end.
- **Breaking Change**: Added a connectivity pre-check. Scans now immediately abort with a non-zero exit code if the target is completely unreachable (e.g., DNS failure, connection refused). Use `--skip-pre-check` to bypass this behavior.
- Switched the SQLite driver from `mattn/go-sqlite3` (cgo) to `modernc.org/sqlite` (pure Go). ANPU no longer requires a C compiler at build time and produces valid executables on all platforms out of the box; the old vendored `third_party/go-sqlite3` copy was removed.
- SARIF reports now serialize empty `rules`/`results` as `[]` instead of `null`, complying with the SARIF 2.1.0 schema.
- Fixed a bug where error messages were printed twice in the terminal.
- Added path to output filenames (`target-path-date.html`) to prevent collisions on same-host scans.
- Support config fallback for target URL when not passed via command line.
- Fixed `show --export` silencing output on successful writes.
- Upgraded `--verbose` output to show the true number of deduplicated findings each stage contributed.
- Clarified scoring documentation to explicitly mention Category Weight over Exposure.

## 0.2.1

- Clarified the status of OWASP ZAP integration (currently planned / interface defined) in documentation.
- Added comprehensive CI/CD documentation and example GitHub Actions workflow (`docs/ci-cd.md`).
- Added documentation for the transparent risk scoring algorithm (`docs/scoring.md`).
- Improved error messaging for local-network scanning attempts.
- Updated security policy with a vulnerability response timeline and PGP key placeholder.

## 0.2.0

- Added `anpu diff <older> <newer>` for historical scan comparison.
- Added attack-surface diffing for endpoints and technologies, including technology version changes.
- Added finding added/removed/changed detection with risk-score deltas.
- Added `--fail-on none|low|medium|high|critical` for CI security gates.
- Reports and scan history are still written before a failed security gate returns non-zero.
- Added a compact risk grade to HTML reports.
- Centralized the release version as `pkg/version`.
- Updated README documentation and examples.
