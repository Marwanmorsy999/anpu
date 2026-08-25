# Contributing to ANPU

Thanks for your interest in contributing. ANPU orchestrates existing
security tools into a unified, understandable report — contributions
that keep that focus (rather than reimplementing scanners from scratch)
are especially welcome.

## Ground rules

- **Read `SECURITY.md` first.** All contributions must respect ANPU's
  safety boundaries (no destructive scanning by default, no local-network
  scanning, no shell execution of target-controlled data, no fabricated
  evidence).
- **Never treat target-controlled data as executable.** This applies to
  HTML/JS content, headers, robots.txt, and any other response data —
  it is parsed, never executed or interpolated into shell commands.
- **Never fabricate findings or evidence.** If a check can't gather
  concrete evidence, the finding's `Evidence.Unavailable` must be `true`
  and `Evidence.Observed` must be empty. Don't invent plausible-looking
  detail.
- **Confidence discipline.** Only use `confirmed` confidence when a
  finding was actually verified (e.g. authenticated exploitation
  confirmation), not just because a signature matched.
- **Test against mock targets only.** Automated tests must use
  `net/http/httptest` fixtures, never real third-party websites. See
  `internal/*/**_test.go` for examples, and `tests/` for shared mock
  target helpers.

## Development setup

```bash
git clone https://github.com/Marwanmorsy999/anpu.git
cd anpu
go build ./...
go test ./...
```

Dependencies are declared in `go.mod` and pinned by `go.sum`; they
resolve normally from the Go module proxy on the first `go build` /
`go test` run (no vendored tree is kept in the repository). To add or
update a dependency, run `go get <module>@<version>` followed by
`go mod tidy`, then commit the resulting `go.mod`/`go.sum` changes.
Once the module cache is populated, builds also work offline.

## Project structure

See `README.md` → "Architecture" for the full module layout. In short:

- `internal/scanner` — the `Scanner` interface, target validation, and
  pipeline orchestrator. This is the only package that should know how
  to sequence stages; it should never import a specific analyzer package.
- `internal/<analyzer>` (headers, tls, technology, recon, endpoints) —
  built-in passive analyzers. Each implements `scanner.Scanner`.
- `internal/integrations` — wrappers around external tools (Nuclei, and
  the prepared ZAP interface). These invoke real external binaries/APIs;
  they must never simulate results.
- `internal/findings` — deduplication/merging.
- `internal/scoring` — the transparent risk-scoring engine.
- `internal/reporting` — JSON/SARIF/HTML report generation and terminal
  UI helpers.
- `internal/storage` — SQLite persistence for `anpu history` / `anpu show`.
- `pkg/models` — the shared, scanner-agnostic data model (`Finding`,
  `Technology`, `Endpoint`, `ScanSummary`, ...). Changes here ripple
  everywhere, so keep them backward compatible where possible.

## Adding a new scanner/analyzer

1. Create a new package under `internal/` implementing `scanner.Scanner`
   (`Name() string`, `Available(ctx) bool`, `Run(ctx, *ScanContext)
   (StageResult, error)`).
2. Normalize its output into `models.Finding` (and `models.Technology` /
   `models.Endpoint` where relevant) — see any existing analyzer for the
   expected level of detail (Title, Description, Severity, Confidence,
   Category, Evidence, Impact, Remediation).
3. Register it as a `Stage` in `cmd/anpu/scan.go`'s `buildPipeline`.
4. Add a module toggle to `models.ModuleConfig` / `config.ModulesFileConfig`
   if it should be independently enable/disable-able.
5. Write tests using `httptest` fixtures.

## Adding a new external tool integration

Follow the pattern in `internal/integrations/nuclei.go`:
- `Available()` must only *check* for the tool (e.g. `exec.LookPath` +
  a version check) — never install or download it.
- `Run()` must degrade gracefully (a warning, not a hard error) when the
  tool isn't installed.
- Convert the tool's native output format into `models.Finding`,
  preserving the original identifier/evidence via `Source` and
  `DetectionMethod`.

## Code style

- Run `gofmt -w` and `go vet ./...` before submitting.
- Keep packages loosely coupled — the dependency graph should stay
  roughly: `pkg/models` ← analyzers/integrations ← `internal/scanner`
  (interface only) ← `cmd/anpu` (wiring). Avoid new import cycles.
- Prefer small, focused functions with doc comments explaining *why*,
  not just *what* — especially for anything touching the safety
  boundaries above.

## Pull requests

- Include tests for new behavior.
- Run `go build ./... && go vet ./... && go test ./...` locally before
  opening a PR.
- Describe what profile(s) (safe/standard/deep) your change affects, if
  applicable.
