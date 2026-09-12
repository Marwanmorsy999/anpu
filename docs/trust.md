# Trust & supply-chain posture

ANPU's brand is honesty, and that applies to its own supply chain: this
page records what the [OpenSSF Scorecard](https://scorecard.dev/) says
about the repo, what is already hardened, and what is still pending.
Nothing here is aspirational — a check is listed as passing only when it
is verifiable in this repo or in the workflow runs.

## Scorecard runs

- Workflow: [`.github/workflows/scorecard.yml`](../.github/workflows/scorecard.yml)
  — weekly (Mondays 09:20 UTC), on pushes to `main`, and on branch
  protection changes.
- Results: repo **Security → Code scanning**, downloadable SARIF per run
  (`scorecard-results-*` artifacts, 30-day retention), and the public
  REST record at `https://api.scorecard.dev/projects/github.com/Marwanmorsy999/anpu`
  (enabled by `publish_results: true`).
- After the first green run on `main`, add the badge to README next to
  the build badge:
  `[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Marwanmorsy999/anpu/badge)](https://scorecard.dev/viewer/?uri=github.com/Marwanmorsy999/anpu)`

## Current score (as of 2026-09-12)

> **Pending first run.** This table is filled in from the first
> `Scorecard analysis` run on `main` after this page merges — update it
> in the same PR that records any remediation, never in advance.

| Check | Score | Notes |
| ----- | ----- | ----- |
| Overall | — | fill after first run |
| Maintained | — | — |
| Code-Review | — | CODEOWNERS + PR-only `main` (see checklist) |
| Branch-Protection | — | needs the settings below |
| Token-Permissions | — | least-privilege blocks in every workflow |
| Pinned-Dependencies | — | actions pinned, Dependabot weekly |
| Security-Policy | — | `SECURITY.md` with private reporting |
| License | — | Apache-2.0 (`LICENSE` + `NOTICE`) |
| SAST | — | pending P1-5 (CodeQL) |
| Signed-Releases | — | pending P1-3 (cosign + SLSA) |
| SBOM | — | informational; pending P1-4 (CycloneDX) |
| Binary-Artifacts | — | no binaries tracked (verified) |
| Dangerous-Workflow | — | no untrusted-code execution patterns |
| Dependency-Update-Tool | — | Dependabot: gomod + github-actions |

## Already hardened (verifiable in-repo)

| Hardening | Evidence |
| --------- | -------- |
| Least-privilege tokens | `permissions:` blocks in `ci.yml`, `scan.yml`, `release.yml`, `scorecard.yml` |
| Pinned actions | exact pins (`golangci-lint-action@v7` + tool `v2.13.2`, `scorecard-action@v2.4.4`) or weekly-bumped majors via Dependabot |
| Weekly dependency PRs | `.github/dependabot.yml` (gomod + github-actions, Mondays) |
| Private vuln reporting | `SECURITY.md` → Security → Advisories flow, 2-day ack target |
| Review routing | `.github/CODEOWNERS` (`@Marwanmorsy999`), PR template with security checklist |
| False-positive intake | `.github/ISSUE_TEMPLATE/false_positive.yml` |
| No tracked binaries | `.gitignore` covers `*.exe`, `/dist/`, reports/; verified via `git ls-files` |
| Coverage ratchet | `codecov.yml` (project `auto`, patch 80%) + CI floor gate |

## Human checklist (GitHub UI, cannot be set from files)

Branch protection for `main` (**Settings → Branches → Add rule**),
required for a maximal Branch-Protection score:

- [ ] Require a pull request before merging (required approvals ≥ 1)
- [ ] Dismiss stale pull request approvals when new commits are pushed
- [ ] Require review from Code Owners
- [ ] Require status checks to pass (select `build-test`, and after P1-5 the CodeQL check)
- [ ] Require branches to be up to date before merging
- [ ] Do not allow bypassing the above settings (include administrators)
- [ ] Restrict who can push (no direct pushes); block force pushes and deletions

Also confirm: **Settings → Code security →** Dependabot alerts + security
updates enabled (Dependabot PRs already configured in-repo).

## Roadmap (lifts the remaining checks)

- **P1-3 Signed releases** — cosign signing, SLSA provenance, real
  SHA-256 checksums in `release.yml` → lifts Signed-Releases.
- **P1-4 SBOM** — CycloneDX SBOM attached to every release.
- **P1-5 CodeQL + dependency scanning** on PR → SAST score + earlier
  vulnerability signal than govulncheck/gosec alone.
