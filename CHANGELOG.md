# Changelog

## 0.2.0

- Added `anpu diff <older> <newer>` for historical scan comparison.
- Added attack-surface diffing for endpoints and technologies, including technology version changes.
- Added finding added/removed/changed detection with risk-score deltas.
- Added `--fail-on none|low|medium|high|critical` for CI security gates.
- Reports and scan history are still written before a failed security gate returns non-zero.
- Added a compact risk grade to HTML reports.
- Centralized the release version as `pkg/version`.
- Updated README documentation and examples.
