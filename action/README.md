# ANPU scan action

GitHub Action wrapper around [`anpu scan`](../docs/cli.md): installs a
checksum-verified release, gates on `--fail-on`, and reports grade + top
findings to the step summary (always) and optionally to the PR.

```yaml
permissions:
  contents: read # + pull-requests: write only when comment: true

jobs:
  anpu:
    runs-on: ubuntu-latest
    steps:
      - uses: Marwanmorsy999/anpu/action@v1
        with:
          target: https://staging.example.com
          profile: advanced
          fail-on: high
          sarif: "true"
```

Only scan systems you own or are explicitly authorized to test.

## Inputs

| Input | Default | Notes |
| ----- | ------- | ----- |
| `target` | (required) | Target URL. |
| `profile` | `safe` | `safe`, `advanced`, or `ultra`. Active profiles only against authorized targets. |
| `fail-on` | `high` | Step fails on findings at or above this severity (`none` disables the gate). Reports are still written. |
| `version` | `latest` | Release tag (`vX.Y.Z`) or `latest`. Pin for reproducible gates. Install is checksum-verified via `install.sh`/`install.ps1`. |
| `sarif` | `"true"` | Write SARIF 2.1.0 (upload to code scanning with `github/codeql-action/upload-sarif`, needs `security-events: write`). |
| `json` | `"true"` | Keep the JSON report (always generated internally for outputs/summary). |
| `html` | `"false"` | Write the HTML report. |
| `args` | `""` | Extra args appended to `anpu scan` (e.g. `"--only headers,tls"`). |
| `comment` | `"false"` | Post grade + top 5 to the PR (`pull-requests: write`, PR events only). |
| `output-dir` | `anpu-reports` | Report directory (created if missing). |

## Outputs

`grade` (A–F, mirrors ANPU `RiskGrade`), `risk-score` (0–10),
`json-report`, `sarif-report`, `html-report` (empty when disabled).

## Local targets

The action never auto-allows local-network scanning. To scan service
containers in the same workflow, export the same override the CLI uses:

```yaml
env:
  ANPU_ALLOW_LOCAL_NETWORK: "1"
```

## Marketplace

The in-repo metadata (`branding`, inputs/outputs) is published under the
`security` category by the maintainer (publish step cannot be expressed
in files). Version tags (`v1`, `v1.x`) are moved on each action release.
