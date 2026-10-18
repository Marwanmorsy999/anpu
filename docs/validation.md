# Validation

ANPU is validated against local fixtures with ground truth derived from the
fixture configuration, not from ANPU output. `ANPU_ALLOW_LOCAL_NETWORK` is
enabled only inside the harness; a test asserts it stays off by default.

## Latest run (safe profile, purpose-built fixture)

Per-analyzer precision/recall (TP/FP/FN):

| Analyzer | TP | FP | FN | Precision | Recall | Actual | Expected |
|---|---|---|---|---|---|---|---|
| headers | 4 | 0 | 0 | 1.00 | 1.00 | 4 | 4 |
| cookies | 2 | 0 | 0 | 1.00 | 1.00 | 2 | 2 |
| tls | 2 | 0 | 0 | 1.00 | 1.00 | 2 | 2 |
| recon | 3 | 0 | 0 | 1.00 | 1.00 | 3 | 3 |
| endpoints | 0 | 0 | 0 | N/A | N/A | 0 | 0 |
| tech | 0 | 0 | 0 | N/A | N/A | 0 | 0 |
| nuclei | 0 | 0 | 0 | N/A | N/A | 0 | 0 |
| zap | 0 | 0 | 0 | N/A | N/A | 0 | 0 |
| **TOTAL** | **11** | **0** | **0** | **1.00** | **1.00** | | |

Determinism: risk score identical across repeated runs (5.1 on the fixture).

## TLS-broken fixture

Expired certificate with wrong hostname: ANPU reported `TLS certificate has
expired` and `TLS certificate failed validation` (TP). TLS 1.1-only server:
ANPU reported no TLS 1.0/1.1 finding (FN — known gap, not fixed).

## Hardened baseline

Valid TLS (trusted local CA), all recommended security headers, secure cookie:
8 findings, 0 medium/high/critical. No false positives observed.

## Limitations

- Single small HTTP fixture plus one TLS-broken server and one hardened
  server. Juice Shop/DVWA targets are defined in `tests/docker-compose.yml`
  but not yet wired into the fast CI job.
- Nuclei and ZAP analyzers show N/A because they are not installed in the
  fast CI fixture run. ZAP runs in the scheduled validation workflow.
- TLS 1.0/1.1 detection is a known false negative.
- No per-analyzer precision/recall beyond the fixture set; do not generalize
  these numbers to all targets.