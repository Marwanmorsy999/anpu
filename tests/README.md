# tests/

ANPU's automated tests live alongside the code they test
(`internal/*/**_test.go`, `pkg/models/*_test.go`), using Go's standard
`testing` package and `net/http/httptest` for mock HTTP targets — per
project policy, **no automated test targets a real third-party website.**

This directory holds cross-package integration fixtures that don't
belong to a single `internal/` package (see `tests/fixtures/`):
multi-stage pipeline fixtures, sample YAML configs, sample Burp/ZAP/HAR
imports, sample Nuclei JSONL output, and soft-404 / WAF / CDN page
pairs for false-positive regression tests.

Phase 0 safety net (per corroboration contract): pure-function units
cover `findings.Deduplicate`, `scoring.ScoreFinding/ScoreAll/AggregateScore`,
`models.DedupKey`, `diff.Compare`, `drift.Compare/ParserVersions`,
`importx.ParseBurp/ParseZAP/ParseHAR`, `reporting.RiskGrade/WriteCSV/WriteMarkdown`,
similarity helpers (`dirs`, `active/soft404`), and integration helpers
(`registrableBase`, `hostOf`, `mapSeverity`, `parseFuzzer`, `parseNikto`,
`parsePorts`). Run with `go test ./...`.
