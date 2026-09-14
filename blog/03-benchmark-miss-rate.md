<!-- DRAFT for human publishing. Numbers below are from
docs/benchmark.md at time of writing — RE-VERIFY against that file
before posting, as the table is freshness-gated and moves. -->

# We benchmarked ourselves and published our miss rate

Every scanner vendor publishes detection rates. Nobody publishes miss
rates — the vulnerabilities their tool walked past. So we did.

ANPU now ships an **honesty benchmark**: five deliberately planted
weaknesses in a local fixture (weak headers, an exposed `.env`, a
backup archive, reflected XSS, an open redirect), scanned with both
profiles, with every hit *and every miss* in a committed Markdown
table enforced by CI. If a code change moves a verdict, the gate fails
until a human reviews the diff and commits it deliberately.

## The current table

At time of writing: **5/5 signals detected** under `advanced`, and the
`safe` profile correctly silent on the four signals outside passive
scope (absence by design, recorded as such — not as failure).

But the headline number is the least interesting part. The interesting
parts are the footnotes, and we published those too:

- **The backup archive hits 3 runs out of 4.** One cold run missed it,
  mechanism unproven. It is marked non-gating in the ground truth and
  stays visible until root-caused — a flaky detection you can see is
  worth more than a perfect score you cannot audit.
- **The open redirect was caught by the wrong engine.** Our redirect
  pack found it; the dedicated active `open-redirect` rule never fired
  (the HTTP client follows the 302 past the unresolvable canary domain
  before the rule can observe it). That is now a documented detection
  gap with a suspected mechanism, not a silent hole.
- **The XSS was caught by the embedded dalfox candidate**, never by the
  active `xss-reflected` rule. Mechanism unproven — recorded, not
  diagnosed, and not hand-waved.
- **Safe-profile finding counts wobble** 8–12 across identical runs
  (timing-sensitive discovery) while verdicts hold. So the gate
  compares verdicts, not counts — and says so in the methodology.

## What we deliberately do not claim

The benchmark measures recall against planted signals, not precision:
we refuse to auto-label unmatched findings as false positives, because
the harness cannot prove a negative. Stored XSS needing JS execution,
authenticated flows, and adversarial-gated checks are out of scope and
listed as such — never probed, never claimed.

## The standing offer

The table's value is not "5/5". It is the policy behind it: **any
future MISS cell stays published until it is fixed or explained.** A
scanner that shows you its misses is asking to be judged on them.
Please do — `anpu bench` runs the whole thing locally in about five
minutes, and the fixture, ground truth, and harness are all in the
repo.
