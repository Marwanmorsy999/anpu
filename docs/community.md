# Community seeding checklist

Outreach order for ANPU, human-executed. Rules everywhere: read venue
norms first, disclose authorship, lead with the honest artifact
(benchmark misses, capability matrix) rather than claims, and never
scan anyone's infrastructure as a "demo" without written permission.

## Ready now (post-merge)

- [ ] **Nuclei community Discord** — `#showcase` / tooling channels.
  Angle: ANPU runs Nuclei templates and *correlates* them with native
  engines (`nuclei_correlation` overlap report); looking for template
  authors to stress-test the dedup. Bring: `docs/benchmark.md`,
  `action/` usage.
- [ ] **Bug Bounty World (Discord/community)** — practitioner angle:
  deterministic scoring explanations for triage (`score_explanation`
  on every finding) and the evidence contract. Ask what would make
  ANPU output directly usable in a report.
- [ ] **r/netsec weekly / "what are you working on" threads** — only
  inside the recurring threads, never as standalone promo posts.
  Angle: "the scanner that's honest about what it can't prove" +
  published miss rate. Bring thick skin and the benchmark link.

## At v1.0 (needs: tagged release, green benchmark gate, action live)

- [ ] **Show HN** — title pattern: "Show HN: ANPU, a scanner that
  publishes its miss rate". Body: what it does in 3 bullets (README
  "Why ANPU"), the benchmark table, what it deliberately does not do.
  Be present for comments all day; answer the hard questions first.
- [ ] **Blog posts** (`blog/01-03`, re-verify numbers before posting):
  publish in order honesty → scoring → benchmark, one week apart, and
  link each from the repo (release notes / README where fitting).

## Conference circuit (lightning talks, 5–15 min)

- [ ] **BSides CFP calendar** (local BSides first): talk "We
  benchmarked our scanner and published the misses". CFPs open
  months ahead — submit early with the benchmark table as the
  abstract's evidence.
- [ ] Record the talk; link it from `docs/demo/` next to the terminal
  recording.

## Ongoing hygiene (keeps the above credible)

- [ ] Answer every issue within days; label `good first issue` regularly.
- [ ] Keep `docs/benchmark.md` fresh — a stale honesty table is worse
  than none (CI enforces this).
- [ ] Monthly release train keeps the project visibly alive
  (`.github/workflows/release-train.yml`).
