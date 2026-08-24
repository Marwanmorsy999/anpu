# Risk Scoring Methodology

ANPU's risk scoring (`internal/scoring`) is fully deterministic and
documented — never an opaque or AI-generated number. Every scored
finding carries a `ScoreExplanation` string showing exactly how its
score was derived.

## Per-finding score

```
score = min(10, severity_base × confidence_multiplier + exposure_weight + corroboration_bonus)
```

- **`severity_base`** — fixed points per severity level:
  critical=9.0, high=7.0, medium=4.5, low=2.0, info=0.5.
- **`confidence_multiplier`** — discounts less-certain findings so a
  "low-confidence critical" doesn't outrank a "confirmed high":
  confirmed=1.00, high=0.90, medium=0.75, low=0.55.
- **`exposure_weight`** — a small additive term based on the finding's
  category, reflecting how directly it represents reachable exposure
  vs. defense-in-depth (e.g. a real vulnerability match from Nuclei/ZAP
  = +1.0; a missing security header = +0.1).
- **`corroboration_bonus`** — up to +0.5, added when independent
  scanners (e.g. a built-in analyzer *and* Nuclei) reported the same
  underlying issue after deduplication, since independent agreement
  increases real-world certainty beyond a single tool's confidence
  label.

## Aggregate scan score

```
aggregate = min(10, max(finding_scores) + volume_bonus)
```

The aggregate is dominated by the single worst finding (a scan with
one critical shouldn't score the same as a scan with none, no matter
how many low-severity findings surround it), with a small bonus
(+0.15 per medium-or-above finding, capped at +1.5) so that "one high"
and "one high plus twenty mediums" don't score identically.

## Why not AI-generated scores?

A scanner's output is used to make real decisions about what to fix
first. A score needs to be explainable and reproducible: given the
same findings, ANPU always produces the same score, and that score can
be traced back to specific, documented weights — not a black box.
