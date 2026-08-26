# CLI Reference

ANPU exposes five subcommands: `scan`, `history`, `show`, `diff`, and `tools`.

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
| `--profile <profile>` | `safe` | Select `safe`, `standard`, or `deep`. |
| `--html` | `true` | Write an HTML report. |
| `--json` | `false` | Write a JSON report. |
| `--sarif` | `false` | Write a SARIF 2.1.0 report. |
| `--output <dir>` | `./reports` | Directory for generated reports. |
| `--no-nuclei` | `false` | Disable Nuclei for this scan. |
| `--no-zap` | `false` | Disable the ZAP extension point; ZAP is not implemented in this MVP. |
| `--fail-on <severity>` | `none` | Return non-zero when findings meet or exceed `low`, `medium`, `high`, or `critical`. |
| `--skip-pre-check` | `false` | Skip the initial connectivity check. |

Example:

```sh
anpu scan https://staging.example.com \
  --profile standard \
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

List previous local scans.

```sh
anpu history
anpu history --limit 50
```

| Flag | Default | Purpose |
|---|---|---|
| `--limit <n>` | `20` | Maximum number of scans to list. |

The table includes scan ID, target, profile, status, risk score, and finding count.

## `anpu show`

Display a previous scan from local history.

```sh
anpu show scan-1234567890-1
```

| Flag | Default | Purpose |
|---|---|---|
| `--export <path>` | empty | Re-render the stored scan to a file instead of printing the summary. |
| `--format <format>` | `html` | Export format: `html`, `json`, or `sarif`. |

Examples:

```sh
anpu show scan-1234567890-1 --export ./reports/scan.html
anpu show scan-1234567890-1 --export ./reports/scan.json --format json
anpu show scan-1234567890-1 --export ./reports/scan.sarif --format sarif
```

## `anpu diff`

Compare two scans of the same target.

```sh
anpu diff <older-scan-id> <newer-scan-id>
```

The command reports changes in risk score, findings, endpoints, and technologies. Comparing different targets is rejected.

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

Built-in engines require no installation. Nuclei is optional. OWASP ZAP is listed as a future integration point.

## Authorization and safety

ANPU is intended only for systems you own or are explicitly authorized to test. `safe` is the default profile and is designed for passive/low-impact analysis; `standard` and `deep` enable additional active checks.
