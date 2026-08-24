# tests/

ANPU's automated tests live alongside the code they test
(`internal/*/**_test.go`), using Go's standard `testing` package and
`net/http/httptest` for mock HTTP targets — per project policy, **no
automated test targets a real third-party website.**

This directory is reserved for cross-package integration fixtures that
don't belong to a single `internal/` package (e.g. multi-stage pipeline
fixtures, sample YAML configs, sample Nuclei JSONL output for
integration-layer tests). It currently has no contents beyond this
README; see `internal/scanner/pipeline_test.go` for the current
pipeline-level integration test, which uses an in-package stub
`Scanner` plus an `httptest` server.
