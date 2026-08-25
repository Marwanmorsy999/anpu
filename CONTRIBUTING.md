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
concrete evidence, the finding's `Evidence.Unavailable` must be `true` and `Evidence.Observed` must be empty. Don't invent plausible-looking detail.
- **Confidence discipline.** Only use `confirmed` confidence when a
finding was actually verified (for example, authenticated exploitation confirmation), not just because a signature matched.
- **Test against mock targets only.** Automated tests must use
`net/http/httptest` fixtures, never real third-party websites. See
`internal/*/**_test.go` for examples, and `tests/` for shared mock
target helpers.

## Development setup

```sh
git clone https://github.com/Marwanmorsy999/anpu
cd anpu
go build ./...
go test ./...
go vet ./...
```

Dependencies are defined in `go.mod` and pinned by `go.sum`. The repository does **not** vendor the Go module cache, so a normal first build requires access to the configured Go module proxy (or a populated local module cache). After dependencies are cached, subsequent builds can run without downloading them again.

## Project structure

See `README.md` → "Architecture" for the full module layout. In short:

- `internal/scanner` — the `Scanner` interface, target validation, and pipeline orchestrator. This is the only package that should know how to sequence stages; it should never import a specific analyzer package.
- `internal/<analyzer>` (headers, tls, technology, recon, endpoints, and additional engines) — built-in analyzers. Each implements the scanner interface.
- `internal/integrations` — wrappers around external tools (Nuclei, and the prepared ZAP interface). These invoke real external binaries/APIs; they must never simulate results.
- `internal/findings` — deduplication/merging.
- `internal/scoring` — the transparent risk-scoring engine.
- `internal/reporting` — JSON/SARIF/HTML report generation and terminal UI helpers.
- `internal/storage` — SQLite persistence for `anpu history` / `anpu show`.
- `pkg/models` — the shared, scanner-agnostic data model (`Finding`, `Technology`, `Endpoint`, `ScanSummary`, ...). Changes here ripple everywhere, so keep them backward compatible where possible.

## Adding a new scanner/analyzer

1. Create a new package under `internal/` implementing the scanner interface (`Name() string`, `Available(ctx) bool`, `Run(ctx, *ScanContext) (StageResult, error)`).
2. Normalize its output into `models.Finding` (and `models.Technology` / `models.Endpoint` where relevant) — see existing analyzers for the expected level of detail (Title, Description, Severity, Confidence, Category, Evidence, Impact, Remediation).
3. Register it as a `Stage` in `cmd/anpu/scan.go`'s `buildPipeline`.
4. Add a module toggle to `models.ModuleConfig` / `config.ModulesFileConfig` if it should be independently enable/disable-able.
5. Write tests using `httptest` fixtures.

## Adding a new external tool integration

Follow the pattern in `internal/integrations/nuclei.go`:

- `Available()` must only check for the tool (for example, `exec.LookPath` plus a version check) — never install or download it.
- `Run()` must degrade gracefully (a warning, not a hard error) when the tool isn't installed.
- Convert the tool's native output format into `models.Finding`, preserving the original identifier/evidence via `Source` and `DetectionMethod`.

## Code style

- Run `gofmt -w`, `go vet ./...`, and `go test ./...` before submitting.
- Keep packages loosely coupled — avoid new import cycles and preserve the scanner-interface boundary.
- Prefer small, focused functions with doc comments explaining *why*, not just *what* — especially for anything touching the safety boundaries above.

## Pull requests

- Include tests for new behavior.
- Run `go build ./... && go vet ./... && go test ./...` locally before opening a PR.
- Describe what profile(s) (`safe`/`standard`/`deep`) your change affects, if applicable.
