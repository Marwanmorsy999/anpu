# ANPU Risk Scoring: A Transparent Approach

In many commercial and open-source scanners, risk scores are a black box. You see an arbitrary "Critical 9.8", but it's unclear *how* that number was derived or if it accurately reflects the actual context of your application.

ANPU takes a different approach: **Transparent, deterministic risk scoring.** 

Our scoring algorithm evaluates every finding based on a public formula, combining the inherent severity of the issue with the confidence of our detection, the exposure of the asset, and corroboration across multiple tools.

## The Formula

The risk score for a single finding is calculated as follows:

```
Risk Score = (Severity × Confidence) + Exposure + Corroboration
```

### 1. Severity (1.0 to 10.0)
The base impact of the vulnerability if successfully exploited.
- **Info:** 0.0
- **Low:** 2.0 - 3.9
- **Medium:** 4.0 - 6.9
- **High:** 7.0 - 8.9
- **Critical:** 9.0 - 10.0

### 2. Confidence (Multiplier: 0.1 to 1.0)
How certain are we that this vulnerability exists, based on the evidence?
- **Tentative (0.5):** Fingerprint matched, but no direct exploitation evidence.
- **Firm (0.8):** Strong indicator of vulnerability, like an exposed config file.
- **Certain (1.0):** Definitive proof, such as successful active exploitation or exact version matching a CVE.

### 3. Exposure (Addition: 0.0 to +1.0)
Where was the issue found?
- **Internal/Admin endpoints:** +0.0 (baseline)
- **Public-facing/Unauthenticated endpoints:** +1.0 (increases risk)

### 4. Corroboration (Addition: 0.0 to +1.0)
Did multiple tools flag this same issue?
- **Single Source:** +0.0
- **Multiple Sources (e.g., Nuclei + ANPU Passive):** +1.0 (increases certainty and risk)

*(Note: The final score is always capped at a maximum of 10.0)*

---

## Example Scenario: Missing HSTS Header

Let's look at how a common finding gets scored.

**Scenario:** A scanner detects that `https://example.com` does not return the `Strict-Transport-Security` header.
- **Finding:** Missing HSTS Header
- **Base Severity:** 4.0 (Medium) - It allows potential downgrade attacks.

**Calculation:**
1. **Confidence:** We observed the HTTP response directly and the header is unequivocally absent. (Certain: `1.0`)
2. **Exposure:** This is on the main public index page. (Public: `+0.5`)
3. **Corroboration:** Only the internal ANPU header analyzer flagged this. (Single source: `0.0`)

```
Score = (4.0 × 1.0) + 0.5 + 0.0 = 4.5 (Medium)
```

## Why Transparency Matters for Security Teams

1. **Prioritization without the Noise:** When every tool cries "Critical," nothing is critical. By adjusting scores based on exposure and confidence, teams can focus on what actually matters.
2. **Explainability to Stakeholders:** When a developer asks, "Why is this a high priority?", you can point to the exact math: "It has a high base severity, and we have 100% confidence it exists on a public-facing endpoint."
3. **Reproducibility:** A deterministic formula means that the same scan, run in the same environment, will produce the same score every time. No opaque AI hallucinations.
