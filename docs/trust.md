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
  (done — see README).

## Current score: 4.2/10 (as of 2026-09-14, Scorecard v5.5.0)

First published run above; refresh this table when the score moves.
Scores we disagree with say so — a scoreboard you cannot argue with is
marketing, not measurement.

| Check | Score | Notes |
| ----- | ----- | ----- |
| Overall | 4.2 | up from unmeasured; biggest levers left are branch protection (human) and a first signed release |
| Maintained | 0 | repo under 90 days old — auto-resolves with age, not action |
| Code-Review | 0 | 0/13 changesets human-approved — structural for a solo dev; needs a second reviewer, not a config |
| Branch-Protection | 0 | **not enabled on `main`** — the single biggest lever; see human checklist below |
| Token-Permissions | 0 → fixed | flagged top-level `contents: write` in `release.yml`; moved to job-level least privilege |
| Pinned-Dependencies | 0 → fixed | was: 0/33 deps pinned; now every action pinned by hash (`# tag` comments, Dependabot-kept), go-installs version-pinned, Docker bases digest-pinned |
| Security-Policy | 4 | policy detected but "no linked content" — added real links to the advisory flow |
| License | 9 | standard Apache-2.0 text; the "not FSF/OSI" warn looks like detector quirk — watching, file untouched |
| SAST | 10 | CodeQL on all 30 commits (live since P1-5) |
| Signed-Releases | 0 | v0.1.0/v0.3.1 predate signing; lifts automatically with the first cosign+SLSA release (v1.0 train) |
| SBOM | informational | CycloneDX per archive live since P1-4 (Scorecard does not score it) |
| Binary-Artifacts | 10 | no binaries tracked |
| Dangerous-Workflow | 10 | no untrusted-code patterns |
| Dependency-Update-Tool | 10 | Dependabot gomod + actions |
| Packaging | 10 | release workflow detected |
| CI-Tests | 10 | 13/13 merged PRs checked |
| Vulnerabilities | 3 | 7 upstream OSV items, none reachable per `govulncheck` (one ID-scoped waiver); Dependabot owns the fixes |
| Fuzzing | 0 | no fuzzer integration — future work, not a claim |
| Contributors | 0 | solo project — structural, not a defect |

Accepted exceptions (flagged by Scorecard, consciously kept): the
`install.sh` pipe in `release.yml` (`downloadThenRun` — it is our own
script at a pinned path; a release-asset install would remove the
warning at the cost of bootstrapping complexity) and the `syft`
installer (version-pinned `v1.40.0`, hash-pinning a pipe is not
meaningful).

## Already hardened (verifiable in-repo)

| Hardening | Evidence |
| --------- | -------- |
| Least-privilege tokens | `permissions:` blocks in every workflow; writes scoped to the job that needs them (`release`) |
| Hash-pinned actions | every `uses:` pinned by commit SHA with `# tag` comments (Dependabot-kept); go-installs version-pinned; Docker bases digest-pinned |
| Weekly dependency PRs | `.github/dependabot.yml` (gomod + github-actions, Mondays) |
| Private vuln reporting | `SECURITY.md` → Security → Advisories flow with real links, 2-day ack target |
| Review routing | `.github/CODEOWNERS` (`@Marwanmorsy999`), PR template with security checklist |
| False-positive intake | `.github/ISSUE_TEMPLATE/false_positive.yml` |
| No tracked binaries | `.gitignore` covers `*.exe`, `/dist/`, reports/; verified via `git ls-files` |
| Coverage ratchet | `codecov.yml` (project `auto`, patch 80%) + CI floor gate |
| Signed releases + SBOM | cosign bundle + SLSA attestations + CycloneDX per archive on every `v*` tag (score lifts on first signed release) |
| SAST + dependency review | CodeQL `security-extended` on push/PR/weekly; dependency-review on PRs |

## Human checklist (GitHub UI, cannot be set from files)

Branch protection for `main` (**Settings → Branches → Add rule**),
required for a maximal Branch-Protection score:

- [ ] Require a pull request before merging (required approvals ≥ 1)
- [ ] Dismiss stale pull request approvals when new commits are pushed
- [ ] Require review from Code Owners
- [ ] Require status checks to pass (select `build-test` and the CodeQL check)
- [ ] Require branches to be up to date before merging
- [ ] Do not allow bypassing the above settings (include administrators)
- [ ] Restrict who can push (no direct pushes); block force pushes and deletions

Also confirm: **Settings → Code security →** Dependabot alerts + security
updates enabled (Dependabot PRs already configured in-repo).

## Roadmap (lifts what is left)

- **Branch protection (human, biggest lever)** — checklist below;
  flips Branch-Protection 0 → ~10 and helps Code-Review.
- **First signed release (v1.0 train)** — flips Signed-Releases once
  `v*` artifacts carry cosign + SLSA provenance.
- **Second reviewer (human, structural)** — the only fix for
  Code-Review on a solo project.
- **Dependabot cadence** — owns the Vulnerabilities tail; the
  `govulncheck` gate guarantees nothing reachable ships meanwhile.
- **CII badge / fuzzing (optional, future)** — CII Best Practices
  effort and fuzzer integration; tracked, not claimed.
