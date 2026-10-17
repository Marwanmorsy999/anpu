# ANPU Repository Audit

Audit date: 2026-10-17 · Scope: README, docs/, cmd/, internal/, Dockerfile, .goreleaser.yaml, .github/workflows/, install scripts.
Baseline: `go build ./...`, `go vet ./...`, `go test ./...` all pass on the audited commit (windows/amd64, go1.27.1).

## 1. README links and anchors

| Link / anchor in README.md | Resolves? |
|---|---|
| `anpu-og.png` (img) | YES |
| `#3-installation` (Install nav) | YES — matches `## 3. Installation` |
| `#5-architecture` (Documentation nav) | YES — matches `## 5. Architecture`, but see note |
| `https://github.com/Marwanmorsy999/anpu/releases` | YES (external) |
| shields.io / codecov.io / go.dev / docker.com / docs.oasis-open.org badges | YES (external) |
| `docs/benchmark.md`, `docs/releases.md`, `docs/cli.md`, `docs/configuration.md`, `docs/scanners.md`, `docs/development.md`, `docs/scoring.md`, `docs/trust.md`, `docs/ci-cd.md` | YES — all exist |
| `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `LICENSE` | YES — all exist |
| `docs/scanners.md#engine-capability-matrix-what-each-check-can-and-cannot-prove` | YES — matches `## Engine capability matrix (what each check can and cannot prove)` |
| `docs/screenshots/report-hero.png`, `docs/screenshots/report-full.png` | YES |
| `docs/demo/scan.cast`, `docs/demo/record.sh` | YES |
| `action/README.md` | YES |
| `install.sh`, `install.ps1` (raw.githubusercontent.com) | YES — files exist at repo root |

Note: the top-nav **Documentation** link points at the in-page `#5-architecture` anchor rather than a `docs/` page. It resolves, but the task asks to point it at the real docs pages.

## 2. CLI commands/flags in README vs registered in cmd/anpu

Commands registered in `cmd/anpu/root.go` (+ subcommands): `scan`, `safe`, `advanced`, `ultra`, `history`, `show`, `diff`, `verify`, `watch`, `tools` (+`install`), `query`, `import`, `feeds` (+`update`,`check`), `wordlists` (+`update`), `drift`, `bench`, `serve`, `plugin` (+`init`,`run`,`list`), `search`, plus cobra `completion`/`help`.

| README command/flag | Registered? |
|---|---|
| `anpu scan <target>` / `--profile` / `--json` / `--sarif` / `--html` / `--output` / `--only` / `--fail-on` | YES |
| `anpu history` | YES |
| `anpu show <scan-id>` / `--export` / `--format` / `--severity` / `--limit` / `--long` | YES |
| `anpu diff <a> <b>` / `--json` / `--output` | YES |
| `anpu verify --finding <id>` / `--scan` / `--json` | YES |
| `anpu tools` / `anpu tools install --help` / `--list` / `--dry-run` / `--all` / `--level` / `--yes` | YES |
| `anpu watch` / `--interval` / `--cron` / `--fail-on` / `--webhook` | YES |
| `anpu serve --addr` / `--limit` | YES |
| `anpu plugin init/run/list` | YES |
| `anpu query` / `anpu import` / `anpu feeds update/check` / `anpu wordlists update` | YES |
| `anpu drift` / `anpu bench` / `anpu search` | YES |
| `anpu --version` / `-v` | YES (cobra `Version` field) |
| **`anpu version`** | **NO — not registered.** Only the `--version` flag exists. `main.go` rewrite passes the token `version` through, but no subcommand matches, so `anpu version` falls through to root help instead of printing the version. |
| **`anpu doctor`** | **NO — not registered.** Required by task 4. |

## 3. Hardcoded path separators

No hardcoded `/` or `\` path separators were found in path construction. All path building uses `filepath.Join`:

- `cmd/anpu/root.go` — `defaultDataDir`, `defaultDBPath` use `filepath.Join`.
- `cmd/anpu/reports.go` — report paths use `filepath.Join(outputDir, ...)`.
- `internal/storage/storage.go` — DSN uses `filepath.ToSlash(path)` (correct for the SQLite URI form).
- `internal/feeds/feeds.go` — `CacheDir` uses `filepath.Join`.
- `cmd/anpu/{bench,feeds,plugin,query,serve_test,...}.go` — `filepath.Join` throughout.

The only literal `"/"` in reporting is the ASCII spinner frame in `internal/reporting/live.go:34` (not a path). Verdict: clean.

## 4. DB path logic

- `cmd/anpu/root.go:548` — `defaultDataDir()` returns `filepath.Join(home, ".anpu")` using **`os.UserHomeDir()`**, falling back to `.anpu`.
- `cmd/anpu/root.go:556` — `defaultDBPath()` returns `<dataDir>/anpu.db`, creating the dir with `MkdirAll(0o750)`.
- `internal/feeds/feeds.go:49` — `CacheDir()` returns `~/.anpu/feeds` via **`os.UserHomeDir()`**.

Issues vs task 3:
1. Uses `os.UserHomeDir()` instead of `os.UserConfigDir()`. On Linux this honors `XDG_CONFIG_HOME`; on Windows it maps to `%AppData%`; on macOS to `~/Library/Application Support`. `~/.anpu` works everywhere but is not the platform config convention and ignores `XDG_CONFIG_HOME`.
2. **No `--data-dir` flag** and **no `ANPU_HOME` env override.** Every consumer (`scan`, `history`, `show`, `diff`, `verify`, `watch`, `drift`, `serve`, `bench`) calls `defaultDBPath()`, so an override must live there and be threaded through.

## 5. Terminal / ANSI / unicode handling

- `internal/reporting/terminal.go` — `SupportsColor()` honors `NO_COLOR` and `TERM=dumb`, and gates on `IsTerminal()` (`os.Stdout` `ModeCharDevice`).
- `--plain` forces ASCII stage markers (`[ok]`/`[!!]`/`[--]`) and a `#` banner via `toPlainBlocks()`.
- Unicode box-drawing/block glyphs are used in the banner, live panel, phase headers, and spinner.
- **No Windows virtual-terminal processing.** On Windows, ANSI SGR sequences require `ENABLE_VIRTUAL_TERMINING_PROCESSING` on the console handle; without it, color escapes can render literally in older conhost/Windows Terminal. There is no `golang.org/x/sys/windows` call to enable VT, and no Windows-specific ASCII fallback beyond `--plain`/`NO_COLOR`.
- `internal/reporting/live.go` — `isTerminalWriter` just delegates to `IsTerminal()`.

## 6. Dockerfile correctness

Current `Dockerfile`:

| Check | Status |
|---|---|
| Multi-stage (build + runtime) | YES |
| `CGO_ENABLED=0` in build | YES |
| Non-root user (`anpu`, uid 10001) | YES |
| `ENTRYPOINT ["anpu"]` | YES |
| `CMD ["--help"]` | YES |
| ca-certificates installed | YES |
| Nuclei in image | **NO** — Nuclei is absent; standard/deep (advanced/ultra) runs degrade to the embedded fallback inside the container |

Issues vs task 6:
1. **No `anpu:nuclei` variant.** Task 6 requires an optional Nuclei-enabled variant so standard/deep profiles get real Nuclei coverage in-container.
2. The README docker run command (`docker run --rm -v "$(pwd)/reports:/reports" anpu scan https://example.com --output /reports`) is correct and works with the current image.

## 7. Releases

- `.goreleaser.yaml` — exists. `builds` matrix is linux/darwin/windows × amd64/arm64 = 5 targets, `CGO_ENABLED=0`, `checksums.txt`, nfpms (deb/rpm/apk/archlinux), CycloneDX SBOMs. Correct.
- `.github/workflows/release.yml` — exists, tag-triggered (`v*`), runs GoReleaser, attests (SLSA), signs (cosign), smoke-tests the published linux/amd64 artifact. Correct.
- `.github/workflows/ci.yml` — **runs on `ubuntu-latest` only.** No macOS/Windows matrix. Task 7 requires a matrix (ubuntu, macos, windows) running build, vet, test, gofmt.

## 8. Docs / links / placeholders

| Item | Status |
|---|---|
| `rules/README.md` → `internal/analyzers` | **BROKEN** — `internal/analyzers` does not exist. The file is an explicit placeholder ("Reserved for future…", "No custom rule engine is implemented in this MVP"). |
| `CONTRIBUTING.md:44` "the prepared ZAP interface" | **INCONSISTENT** — `internal/integrations/zap.go` is a 778-line implementation (Docker `zap-baseline.py`/`zap-full-scan.py`, local `zap.sh`/`zap.bat`/`zaproxy`, alert→finding normalization, risk/confidence mapping) and is wired into the pipeline at `cmd/anpu/pipeline_stages.go:278` (ultra profile). ZAP is **implemented**, not a stub. Documenting it as "planned" would contradict the code and the "no fabricated evidence" principle. Flagged for decision. |
| `docs/trust.md` scorecard table | Placeholder ("Pending first run", all dashes) — but the linked `.github/workflows/scorecard.yml` **does exist**. |
| `docs/community.md`, `docs/benchmark.md`, `docs/ci-cd.md` plain-text workflow references | The referenced workflow files (`release-train.yml`, `bench.yml`, `ci.yml`) **all exist**. |
| Install sections per OS | README §3 already has Linux/macOS (`curl`), Windows PowerShell (`irm`), pre-built binaries, build-from-source, Docker. |
| "Documentation" nav link | Points to `#5-architecture`; task asks to point at real `docs/` pages. |
| Link-check in CI | **Missing** — no workflow step validates markdown links. |
| ZAP mentions | README §9, docs/configuration.md, docs/scanners.md, docs/development.md all describe ZAP as implemented (Docker/zap.sh + embedded fallback) — accurate to the code. Only CONTRIBUTING.md understates it. |

## 9. Summary of work items (input to tasks 2–8)

1. **CGO removal (task 2)** — already done: `go.mod` pins `modernc.org/sqlite v1.58.0`, `internal/storage/storage.go` imports it, schema/API unchanged. Remaining: verify `CGO_ENABLED=0` cross-compiles for all 5 targets. There is **no `vendor/` directory** despite the task context mentioning vendored deps; deps resolve from the module proxy/cache.
2. **Portability (task 3)** — add `os.UserConfigDir()`-based data dir with `--data-dir` + `ANPU_HOME` override; enable Windows VT processing with ASCII/`NO_COLOR`/non-TTY fallback; ensure report output dirs use `MkdirAll` (scan already `MkdirAll`s `outputDir`; `WriteHTML`/export funcs assume the dir exists — fine since the caller creates it).
3. **Commands (task 4)** — add `anpu version` and `anpu doctor`; ensure scan/history/show/diff match README examples (they do).
4. **Nuclei (task 5)** — already robust: `findExecutable` (PATH + Go bins + `versionCheck`), warning-not-fail via embedded fallback, `exec.CommandContext` timeout, `.exe`-safe on Windows. A clearer "nuclei not found" warning for standard/deep profiles is the remaining polish.
5. **Docker (task 6)** — add `anpu:nuclei` variant.
6. **Releases (task 7)** — add the CI matrix.
7. **Docs (task 8)** — fix `rules/README.md` placeholder link, correct CONTRIBUTING.md ZAP wording (implemented, not "prepared"), point Documentation at `docs/`, add link-check step.
