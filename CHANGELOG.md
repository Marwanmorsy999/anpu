# Changelog

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
