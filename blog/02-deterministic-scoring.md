<!-- DRAFT for human publishing. Verify the formula and table values
against docs/scoring.md and internal/scoring/scoring.go before posting;
the serialized explanation keeps a legacy field name noted below. -->

# How ANPU's deterministic scoring works

Security scores are usually black boxes: a number with no derivation,
different on every run, tuned by persons unknown. ANPU's score is the
opposite — four public inputs, fixed weights, one rounding rule, and
the full derivation stored on every finding. Given the same findings,
you get the same score. Every time. Here is the whole thing.

## Per-finding score

```
Finding Score = (Severity Base × Confidence Multiplier)
              + Category Weight
              + Corroboration Bonus
```

Rounded to one decimal, clamped at 10.0. The tables:

| Severity | Base | Confidence | Multiplier |
|---|---|---|---|
| Critical | 9.0 | Confirmed | 1.00 |
| High | 7.0 | High | 0.90 |
| Medium | 4.5 | Medium | 0.75 |
| Low | 2.0 | Low | 0.55 |
| Info | 0.0 | | |

Informational observations always score 0 — they describe attack
surface, not risk.

Category weights run from +1.0 (confirmed vulnerability) down to +0.0
(other), with headers and technology at +0.1. And when deduplication
merges independent detections of the same issue, a corroboration bonus
of up to +0.5 acknowledges that agreement across engines is itself
evidence.

Worked example, straight from the test suite: a High-severity,
High-confidence headers finding scores `(7.0 × 0.90) + 0.1 + 0 = 6.4`.
A Critical at Low confidence scores `(9.0 × 0.55) + 0.1 ≈ 5.1` — *lower*
than the confirmed High. That inversion is deliberate: an unproven
critical should never outrank a proven high.

## The grade numerator only counts proof

The scan-level score is not an average:

```
Aggregate = min(Max Confirmed Score + Volume Bonus + Posture Penalty, 10.0)
```

Only **confirmed** findings feed the numerator — high/confirmed
confidence without a needs-review flag, or multi-source agreement. A
scan whose scariest finding is an unconfirmed differential grades on
*posture* (a small capped penalty), landing in A/B territory instead of
pretending unproven risk. Twenty unconfirmed mediums move the score by
1.0, total. That is the point: volume of hints must never masquerade
as certainty of holes.

## Why determinism matters

Three practical questions this design answers:

1. **Why did this finding score 6.4?** The report carries the exact
   inputs (`score_explanation`), including the legacy-named
   `exposure_weight` field we kept for compatibility.
2. **Why did the grade change since last week?** The aggregate is max +
   documented bonuses — diff the findings, and the delta explains
   itself. (`anpu diff` and `anpu watch` automate exactly this.)
3. **Can I reproduce it?** Yes, byte for byte, from the same findings.

No model calls. No hidden weights. No Tuesday-is-different results.
Boring arithmetic, on purpose — because a score you cannot audit is a
marketing number, and marketing numbers do not belong in security
reports.
