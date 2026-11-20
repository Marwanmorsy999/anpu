# Trust & supply-chain posture

ANPU's brand is honesty, and that applies to its own supply chain: this
page records what the [OpenSSF Scorecard](https://scorecard.dev/) says
about the repo, what is already hardened, and what is still pending.
Nothing here is aspirational -- a check is listed as passing only when it
is verifiable in this repo or in the workflow runs.

## Scorecard runs

- Workflow: [`.github/workflows/scorecard.yml`](../.github/workflows/scorecard.yml)
  -- weekly (Mondays 09:20 UTC), on pushes to `main`, and on branch
  protection changes.
- Results: repo **Security -- Code scanning**, downloadable SARIF per run
  (`scorecard-results-*` artifacts, 30-day retention), and the public
  REST record at `https://api.scorecard.dev/projects/github.com/Marwanmorsy999/anpu`
  (enabled by `publish_results: true`).
- After the first green run on `main`, add the badge to README next to
  the build badge:
  `[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Marwanmorsy999/anpu/badge)](https://scorecard.dev/viewer/?uri=github.com/Marwanmorsy999/anpu)`
  (done -- see README).

## Current score: 6.2/10 (as of 2026-11-20, Scorecard v5.5.0)

Refresh this table when the score moves. Scores we disagree with say so --
a scoreboard you cannot argue with is marketing, not measurement.

| Check | Score | Notes |
| ----- | ----- | ----- |
| Overall | 6.2 | up from 4.2; remaining levers: branch protection (human), signed-release provenance detection, pinning coverage |
| Maintained | 0 | repo under 90 days old -- self-healing with age |
| Code-Review | 0 | structural for a solo dev; needs a second reviewer |
| Branch-Protection | 0 | **not enabled on `main`** -- human checklist below (biggest lever) |
| Token-Permissions | 10 | job-level least privilege everywhere |
| Pinned-Dependencies | 5 | every action SHA-pinned as of v0.5.10 (Task 2 of the v0.5.10 cycle) |
| Security-Policy | 10 | real links to the advisory flow |
| License | 9 | Apache-2.0 text present; SPDX identifier mismatch in winget/Homebrew fixed in Task 2 of this cycle |
| SAST | 10 | CodeQL security-extended on push/PR/weekly |
| Signed-Releases | 8 | 5 of last 5 releases signed; Scorecard reports "provenance not detected" even though `gh attestation verify` passes on the published artifacts (SLSA provenance is present but not auto-detected by Scorecard) |
| SBOM | informational | CycloneDX per archive |
| Binary-Artifacts | 10 | no binaries tracked |
| Dangerous-Workflow | 10 | no untrusted-code patterns |
| Dependency-Update-Tool | 10 | Dependabot gomod + actions |
| Packaging | 10 | release workflow detected |
| CI-Tests | 10 | merged PRs checked |
| Vulnerabilities | 6 | 4 upstream advisories (GO-2026-5320, GO-2026-5932, GO-2026-6860, GO-2026-6866); only GO-2026-5932 is reachable (openpgp, init-only via opt-in OOB, Fixed in: N/A, waived in CI). The other three are unreachable at the current versions (x/net html quadratic/coalescing complexity, goldmark XSS) and fixed upstream (x/net v0.62.0, goldmark v1.7.17). CI gate fails on any other affecting advisory. |
| Fuzzing | 0 | no fuzzer integration -- roadmap |
| Contributors | 0 | solo project -- structural |

## Advisory reconciliation (govulncheck, 2026-11-20)

| Advisory | Module | Found in | Fixed in | Reachable in anpu? | Why CI gate passes |
| -------- | ------ | -------- | -------- | ------------------ | ------------------ |
| GO-2026-5932 | golang.org/x/crypto/openpgp | v0.1.0-deprecated | N/A | Yes (init-only, via internal/oob/interactsh.go, opt-in OOB) | ID-scoped waiver in ci.yml; Fixed in N/A |
| GO-2026-6866 | golang.org/x/net | v0.60.0 | v0.62.0 | No (unreachable) | govulncheck reports "not called" |
| GO-2026-6860 | golang.org/x/net | v0.60.0 | v0.62.0 | No (unreachable) | govulncheck reports "not called" |
| GO-2026-5320 | github.com/yuin/goldmark | v1.7.13 | v1.7.17 | No (unreachable) | govulncheck reports "not called" |

Source: `govulncheck -show verbose ./...` on Go 1.27.4; module versions from `go.mod`.

## Accepted exceptions (flagged by Scorecard, consciously kept): the
`install.sh` pipe in `release.yml` (`downloadThenRun` -- it is our own
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
| Private vuln reporting | `SECURITY.md` -- Security -- Advisories flow with real links, 2-day ack target |
| Review routing | `.github/CODEOWNERS` (`@Marwanmorsy999`), PR template with security checklist |
| False-positive intake | `.github/ISSUE_TEMPLATE/false_positive.yml` |
| No tracked binaries | `.gitignore` covers `*.exe`, `/dist/`, reports/; verified via `git ls-files` |
| Coverage ratchet | `codecov.yml` (project `auto`, patch 80%) + CI floor gate |
| Signed releases + SBOM | cosign bundle + SLSA attestations + CycloneDX per archive on every `v*` tag (score lifts on first signed release) |
| SAST + dependency review | CodeQL `security-extended` on push/PR/weekly; dependency-review on PRs |

## Release artifacts (v0.5.8+)

Every `v*` release publishes, and the release workflow verifies before
publishing:

- `checksums.txt` (SHA-256 for every archive/package) plus
  `checksums.txt.sigstore.json` (cosign keyless bundle over checksums.txt).
- Per-archive CycloneDX SBOMs (`*.sbom.cyclonedx.json`).
- SLSA build-provenance attestations (`gh attestation verify`).
- Stable, version-less archive aliases (`anpu_<os>_<arch>.tar.gz` /
  `.zip`) that are byte-identical to their versioned counterparts.
- Native packages: `.deb`, `.rpm`, `.apk`, `.pkg.tar.zst` (amd64/arm64).

Verification commands: [docs/install.md](install.md).

## Packaging drift guard

The `packaging-validate` CI job parses `manifests/winget/...yaml`,
`Formula/anpu.rb` and `flake.nix`, extracts each manifest's version, and
asserts all three equal `git describe --tags --abbrev=0`. CI fails on
drift, so a release cannot ship with stale store manifests.

## Human checklist (GitHub UI, cannot be set from files)

Branch protection for `main` (**Settings -- Branches -- Add rule**),
required for a maximal Branch-Protection score:

- [ ] Require a pull request before merging (required approvals -- 1)
- [ ] Dismiss stale pull request approvals when new commits are pushed
- [ ] Require review from Code Owners
- [ ] Require status checks to pass (select `build-test` and the CodeQL check)
- [ ] Require branches to be up to date before merging
- [ ] Do not allow bypassing the above settings (include administrators)
- [ ] Restrict who can push (no direct pushes); block force pushes and deletions

Also confirm: **Settings -- Code security --** Dependabot alerts + security
updates enabled (Dependabot PRs already configured in-repo).

## Roadmap (lifts what is left)

- **Branch protection (human, biggest lever)** -- checklist below;
  flips Branch-Protection 0 -- ~10 and helps Code-Review.
- **First signed release (v1.0 train)** -- flips Signed-Releases once
  `v*` artifacts carry cosign + SLSA provenance.
- **Second reviewer (human, structural)** -- the only fix for
  Code-Review on a solo project.
- **Dependabot cadence** -- owns the Vulnerabilities tail; the
  `govulncheck` gate guarantees nothing reachable ships meanwhile.
- **CII badge / fuzzing (optional, future)** -- CII Best Practices
  effort and fuzzer integration; tracked, not claimed.