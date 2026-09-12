# CLI Reference

ANPU exposes 12 commands: `scan`, `safe`, `advanced`, `ultra`, `history`, `show`, `diff`, `watch`, `tools`, `search`, `completion`, and `help`.

Shorthand: `anpu <target> [flags]` rewrites to `anpu scan <target> [flags]`,
so the most common invocation needs no subcommand. Canonical profiles are
`safe`, `advanced`, `ultra` (aliases: `standard`→`advanced`, `deep`→`ultra`).

Global flags are available on every command.

## Global options

| Flag | Default | Purpose |
|---|---|---|
| `--config <path>` | `anpu.yaml` if present | Use a specific YAML configuration file. |
| `--verbose` | `false` | Show per-stage finding and warning counts. |
| `--version` | — | Print the ANPU version. |
| `--help` | — | Show command help. |

ANPU stores scan history locally in `~/.anpu/anpu.db` by default. The database is created automatically when a command needs it.

## `anpu scan`

Run the scan pipeline against a target URL.

```sh
anpu scan https://example.com
```

The target may also come from `target.url` in `anpu.yaml`:

```sh
anpu scan
```

### Scan options

| Flag | Default | Purpose |
|---|---|---|
| `--profile <profile>` | `safe` | Select `safe`, `advanced`, or `ultra` (aliases: `standard`, `deep`). |
| `--html` | `true` | Write an HTML report. |
| `--json` | `false` | Write a JSON report. |
| `--sarif` | `false` | Write a SARIF 2.1.0 report. |
| `--output <dir>` | `./reports` | Directory for generated reports. |
| `--no-nuclei` | `false` | Disable Nuclei for this scan. |
| `--no-katana` | `false` | Disable the katana crawl integration for this scan. |
| `--no-httpx` | `false` | Disable the httpx probe integration for this scan. |
| `--no-subfinder` | `false` | Disable the subfinder integration for this scan. |
| `--no-dalfox` | `false` | Disable the dalfox XSS confirmation integration for this scan. |
| `--no-zap` | `false` | Disable ZAP (implemented via Docker/zap.sh with embedded fallback). |
| `--no-api` | `false` | Disable API schema discovery and testing. |
| `--no-authz` | `false` | Disable authorization testing. |
| `--oob-interactsh` | `false` | Use public interactsh fleet to CONFIRM blind SSRF/XXE/Log4Shell. |
| `--oob-host` | empty | Custom OOB callback host for blind injection detection. |
| `--adversarial` | `false` | Enable hazardous adversarial probes (stateful multi-step, header/body/WS, JWT/mass-assign/race/smuggling/proto-pollute, sqli boolean differential with bundle) — requires `--confirm-authorized` on authorized ultra/adversarial targets only; Benign/LowImpact only, no `SafetyDestructive` (no data destruction). |
| `--confirm-authorized` | `false` | Confirm you are authorized to run adversarial probes (required with `--adversarial`). |
| `--ghost` | `false` | Undetectable mode: Chrome 131 JA3, h2, GREASE, stable Chrome-ordered header set, Pareto 800-3500ms jitter, no `anpu` canary substring, proxy rotation, adaptive rate, payload polymorphism (combine with `--proxy-pool` and `--adversarial` for max power). |
| `--ghost-canary-prefix` | `""` when `--ghost`, `anpu` otherwise | Custom ghost canary prefix (default `""` when `--ghost`, no `anpu` substring; set to `anpu` to keep allowlist mode). |
| `--ghost-workers` | `4` | Parallel ghost workers for sharded active scanning (0 = sequential). |
| `--proxy-pool` | empty | Path to file with proxy URLs (one per line, `http/https/socks5`) for RoundRobin per-request rotation with healthcheck. |
| `--rate-limit` | `0` | Max requests per second across all stages (0 = unlimited); ghost defaults to adaptive 2 rps when unset. |
| `--delay` | `0` | Fixed inter-request delay (stacks with `--rate-limit`); ghost uses Pareto 800-3500ms lognormal when unset. |
| `--proxy` | empty | Route all HTTP traffic through an `http/https/socks5` proxy (fixed via `x/net/proxy` SOCKS5 dialer). |
| `--fail-on <severity>` | `none` | Return non-zero when findings meet or exceed `low`, `medium`, `high`, or `critical`. |
| `--skip-pre-check` | `false` | Skip the initial connectivity check. |
| `--quiet` | `false` | Suppress info-severity findings from terminal output (reports unchanged). |
| `--silent` | `false` | Suppress banner, stage lines, and summary for clean piped output (reports still written). |
| `--plain` | `false` | ASCII markers (`[ok]/[!!]/[--]`) and `#` banner instead of unicode blocks. |
| `--no-banner` | `false` | Suppress the banner (target line still shown unless `--silent`). |
| `--proxy <url>` | empty | Route all HTTP traffic through an `http/https/socks5` proxy (e.g. Burp at `http://127.0.0.1:8080`); `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` env honored when unset. |
| `--stdin` | `false` | Read targets (one URL per line) from stdin: `cat targets.txt \| anpu scan --stdin`. |
| `--list, -l <file>` | empty | Read targets (one URL per line) from a file. |
| `--jsonl` | `false` | Stream findings as JSON lines to stdout for piping (implies `--silent`). |
| `--scope-file <path>` | empty | Allowlist file (one host per line, `#` comments, `*.example.com` wildcards); off-scope targets abort before any request (hard stop). |
| `--auto-install` | `false` | Self-provision missing external tools mid-scan (go/pipx/docker; apt/choco best-effort) instead of skipping them. Also `scan.auto_install` in YAML and `ANPU_WITH_TOOLS=1` in the OS installers for pre-installing. Mass-DNS resolvers default to public DNS when `ANPU_RESOLVERS` is unset. |
| `--unsafe` | `false` | Operator master override: implies `--adversarial --confirm-authorized`, lifts safe-purity embedded filters, runs wrappers at fuller strength (sqlmap level/risk 2, nikto full-minus-DoS). Defaults, the authorization warning, and the hard exclusions (no brute-force, no exploit frameworks, no DoS, no destruction) are unchanged. Also `scan.unsafe` in YAML. |
| `--only <a,b>` | empty | Run only these modules (e.g. `--only headers,tls`); disables all others. |
| `--enable <a,b>` | empty | Enable modules (e.g. `--enable archiveurls,certsan`). |
| `--disable <a,b>` | empty | Disable modules (e.g. `--disable brokenlink,originip`). |
| `--parallel N` | `8` | Run snapshot-safe stages concurrently with N workers (max 32); merging stays in stage order so output is deterministic. |
| `--budget <dur>` | `0` | Cap total scan wall time, e.g. `15m` (queued stages stop between stages with per-phase coverage in warnings; `0` = uncapped). Makes capped scans viable in CI. |
| `--checkpoint <path>` | empty | Write per-stage checkpoint snapshots here as the scan runs. |
| `--resume <path>` | empty | Resume an interrupted scan from a checkpoint file (completed stages merge without re-running). |
| `--risk-accept <path>` | empty | Suppress finding IDs listed in a YAML accept file (`accept: [{id, reason, expires}]`); expired entries re-arm with a warning. |
| `--nuclei-tags <tags>` | empty | Override nuclei template tags (comma-separated); widens the scan considerably. |
| `--zap-ajax` | `false` | Enable the ZAP Ajax spider for JS-heavy routes (Docker runs only; longer scan). |
| `ANPU_CODE_DIR` | empty | Local code checkout for the Codesecrets stage (tfstate/env/docker/k8s secrets + misconfigs, offline). |

Example:

```sh
anpu scan https://staging.example.com \
  --profile advanced \
  --json \
  --sarif \
  --output ./reports \
  --fail-on high
```

`--fail-on` is evaluated after the scan, reports, and scan history have been written. Informational findings are not thresholds for this gate.

### Report filenames

Generated report names use the target host/path plus a timestamp, for example:

```text
reports/example.com-2026-01-01-120000.html
reports/example.com-2026-01-01-120000.json
reports/example.com-2026-01-01-120000.sarif
```

The exact filename is generated at runtime, so CI workflows should discover `*.sarif` or `*.json` rather than hard-code a timestamp.

## `anpu history`

List previous local scans (SQLite history database — the same source
`show` and `diff` read).

```sh
anpu history
anpu history --limit 50
anpu history --target example.com
anpu history --json
```

| Flag | Default | Purpose |
|---|---|---|
| `--limit <n>` | `20` | Maximum number of scans to list. |
| `--target <substr>` | empty | Only list scans whose target contains this substring (case-insensitive). |
| `--json` | `false` | Print rows as JSON with full IDs and targets (no truncation). |

The table includes scan ID, target, profile, status, risk score, and finding count.

## `anpu show`

Display a previous scan from local history (same record `diff` compares),
including pipeline phase timings.

```sh
anpu show scan-1234567890-1
anpu show scan-1234567890-1 --severity high --limit 20 --long
```

| Flag | Default | Purpose |
|---|---|---|
| `--export <path>` | empty | Re-render the stored scan to a file instead of printing the summary. |
| `--format <format>` | `html` | Export format: `html`, `json`, `sarif`, `csv`, or `md`. |
| `--severity <floor>` | empty | Only print findings at/above `low`, `medium`, `high`, or `critical`. |
| `--limit <n>` | `50` | Max findings to print (`0` = all). |
| `--long` | `false` | Print full finding IDs (for `--risk-accept` files), URLs, and evidence excerpts. |

Examples:

```sh
anpu show scan-1234567890-1 --export ./reports/scan.html
anpu show scan-1234567890-1 --export ./reports/scan.json --format json
anpu show scan-1234567890-1 --export ./reports/scan.sarif --format sarif
```

## `anpu diff`

Compare two scans of the same target (from history).

```sh
anpu diff <older-scan-id> <newer-scan-id>
```

Identity model: findings match by DedupKey (category + normalized URL +
title + parameter + CWE); severity/confidence/score/evidence/remediation
changes report as "changed". Endpoints match by normalized URL,
technologies by name + category (version bumps report as "changed").
Targets must be equivalent after normalization (scheme/host case,
default ports, trailing slashes ignored) — otherwise the comparison is
rejected. For pin-guarded baseline checks see `drift` (stable-ID
identity); for live monitoring see `watch` (diff identity, added-only
alerts).

| Flag | Default | Purpose |
|---|---|---|
| `--json` | `false` | Print the comparison as JSON. |
| `--output <path>` | empty | Write the JSON comparison to a file. |

Examples:

```sh
anpu diff scan-old scan-new
anpu diff scan-old scan-new --json
anpu diff scan-old scan-new --output ./reports/diff.json
```

## `anpu tools`

Show which built-in engines are available and whether optional external integrations are installed.

```sh
anpu tools
```

Built-in engines require no installation. Free external binaries (amass, ffuf, nmap, …) run as pipeline stages when installed and warn-and-skip otherwise; state-touching ones additionally need `--adversarial --confirm-authorized`. Fuzzers need `ANPU_WORDLIST`, code tools need `ANPU_CODE_DIR`, mass-DNS tools need `ANPU_RESOLVERS`. `anpu tools` shows every registry tool with its real status (external/embedded/missing + install hint), the operator environment, and worst-case staged time per profile.

`ANPU_TOOL_BUDGET_SEC=N` caps cumulative external-tool seconds per scan (0/unset = uncapped); exhausted tools skip with an explicit reason instead of burning time silently.

### `anpu tools install`

Managed installation for the free-only Wave 2 registry: ANPU runs the install itself (go → pipx → apt/choco → docker pull) and verifies the binary resolves. `--dry-run` only prints the recipe. `--all` bulk-installs every installable recipe for a level (requires `--yes`, continues past failures with a summary). Absent tools always warn-and-skip in scans; state-touching tools are marked `[adversarial-gated]` (the gate applies at run time, not at install).

```sh
anpu tools install --list
anpu tools install amass            # asks once before downloading (use --yes in scripts)
anpu tools install sqlmap --dry-run
anpu tools install --all --level advanced --yes
```

Single installs print the recipe and ask for confirmation first (default No; `--yes` skips the prompt; piped stdin without `--yes` refuses so nothing installs silently). `--all` always requires `--yes` and lists the plan. `scan --auto-install` likewise announces every tool it may fetch and confirms once, unless `--yes` is given (with `--stdin` targets it proceeds with a notice, since the prompt would eat a target line).

Fuzzers additionally need `ANPU_WORDLIST`, code tools `ANPU_CODE_DIR`, mass-DNS tools `ANPU_RESOLVERS` before their stages will run.

`--csv` / `--md` write finding exports alongside the scan (same filename stem as the other reports); `show <id> --export --format csv|md` re-renders them later from history.

## `anpu query`

Filter findings across saved JSON reports (`--json` scans).

```sh
anpu query --severity high
anpu query --dir ./my-reports --text xss
```

```sh
anpu query --severity high
anpu query --input ./reports/scan.json --text xss --json
anpu query --category vulnerability --confidence confirmed --limit 20
```

## `anpu import`

Normalize Burp XML, ZAP JSON, or HAR captures into ANPU findings (import-only, no traffic sent).

```sh
anpu import burp.xml --json
anpu import zap.json --output imported.json
anpu import session.har --target https://example.com/
```

## `anpu feeds` / `anpu wordlists`

Keyless threat-intel and wordlist maintenance (explicit commands only — scans never auto-download except the fail-silent KEV/reputation lookups).

```sh
anpu feeds update          # refresh local CISA KEV cache
anpu feeds check https://example.com/   # URLhaus + ThreatFox reputation
anpu wordlists update      # refresh vendored subsets from SecLists (opt-in)
```

Live EPSS scoring is opt-in via `ANPU_EPSS=1`. The KEV cache auto-refreshes when older than a week (fail-silent, 20s cap); `anpu feeds update` forces it. PhishTank is excluded (its API needs a key).

`watch` accepts the same `--scope-file`, `--auto-install`, and `--yes` flags, passed through to every iteration scan. `scan` also takes `--nuclei-tags` (comma-separated template tags overriding the profile set — widens the scan considerably).

Mobile scope: set `ANPU_APK` to your APK/IPA plus `ANPU_MOBSF_URL`/`ANPU_MOBSF_KEY` for your operator-run MobSF server to enable the ultra-profile MobSF static stage (dynamic analysis is never run).

## `anpu drift`

Compare a current report against an authorized baseline with parser-pin verification (exit 1 on new findings or pin drift).

```sh
anpu drift --write-pins --pins pins.json
anpu drift base.json now.json --pins pins.json --json
```

## `anpu show` export formats

`--format` accepts `html`, `json`, `sarif`, `csv`, and `md`.

## Authorization and safety

ANPU is intended only for systems you own or are explicitly authorized to test. `safe` is the default profile and is designed for passive/low-impact analysis (API/AuthZ anonymous probing as designed behavior); `advanced` and `ultra` enable additional active checks.
