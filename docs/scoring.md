# ANPU Risk Scoring: A Transparent Approach

ANPU uses deterministic, explainable scoring rather than an opaque or AI-generated number. Every finding receives a score explanation showing the inputs used, and the aggregate scan score is derived from those finding scores.

## Finding score

For each non-informational finding:

```text
Finding Score = (Severity Base × Confidence Multiplier)
              + Category Weight
              + Corroboration Bonus
```

The result is rounded to one decimal place and capped at `10.0`.

### Severity base

| Severity | Base |
|---|---:|
| Info | 0.0 |
| Low | 2.0 |
| Medium | 4.5 |
| High | 7.0 |
| Critical | 9.0 |

Informational observations are score-neutral and always receive `0.0` because they describe attack-surface facts rather than security risk by themselves.

### Confidence multiplier

| Confidence | Multiplier |
|---|---:|
| Low | 0.55 |
| Medium | 0.75 |
| High | 0.90 |
| Confirmed | 1.00 |

Confidence must reflect the evidence actually collected. A fingerprint match is not automatically a confirmed vulnerability.

### Category weight

| Category | Weight |
|---|---:|
| Vulnerability | +1.0 |
| Authentication | +0.7 |
| TLS | +0.5 |
| Endpoint | +0.3 |
| Configuration | +0.3 |
| Cookies | +0.2 |
| Exposure | +0.2 |
| Headers | +0.1 |
| Technology | +0.1 |
| Other | +0.0 |

The serialized explanation keeps the historical field name `exposure_weight` for compatibility, even though the value is now derived from the finding category.

### Corroboration bonus

When deduplication merges evidence from multiple independent sources, ANPU adds a small corroboration bonus:

```text
min(0.5, 0.15 × (number of merged sources - 1))
```

So the bonus is `0.0` for one source, `0.15` for two sources, `0.30` for three, and never exceeds `0.5`.

## Aggregate scan score

The overall scan score is not simply the average of findings. ANPU uses the highest individual finding score and then adds a volume bonus for medium-or-higher findings:

```text
Aggregate = min(Max Finding Score + Volume Bonus, 10.0)
```

The volume bonus is:

```text
min(0.15 × count_of_medium_or_higher_findings, 1.5)
```

Informational findings do not contribute to the aggregate score.

This makes the score sensitive to both the most serious issue and the breadth of the security problem without allowing a large number of low-severity observations to dominate the result.

## Example: Missing HSTS

Suppose ANPU observes a missing HSTS header and classifies it as a medium-severity header finding with confirmed confidence:

```text
Severity base        = 4.5
Confidence multiplier = 1.00
Category weight      = 0.1
Corroboration bonus  = 0.0

Finding score = (4.5 × 1.00) + 0.1 + 0.0
              = 4.6 / 10
```

The final scan score may be higher if other medium-or-higher findings are present because of the aggregate volume bonus.

## Why transparency matters

A deterministic score lets developers and security teams answer three practical questions:

1. **Why did this finding receive this score?** The report contains the exact inputs.
2. **Why did the overall scan score change?** The aggregate is driven by the highest finding plus the documented severity-volume bonus.
3. **Can the result be reproduced?** Yes. Given the same findings and evidence, the scoring function is deterministic.
