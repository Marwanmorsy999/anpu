# Changelog

## 0.3.0

- **Breaking Change**: Added a connectivity pre-check. Scans now immediately abort with a non-zero exit code if the target is completely unreachable (e.g., DNS failure, connection refused). Use `--skip-pre-check` to bypass this behavior.
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
