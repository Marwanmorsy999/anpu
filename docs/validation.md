# Validation

ANPU is validated against local, intentionally vulnerable fixtures and
hardened baselines. The local-network guard stays off by default; validation
harnesses set `ANPU_ALLOW_LOCAL_NETWORK=1` explicitly and a test asserts the
default remains off.

Methodology:
- Fixtures: OWASP Juice Shop, DVWA, and a purpose-built static fixture with
  missing headers, insecure cookies, expired/self-signed TLS, exposed source
  maps, and robots/sitemap leaks.
- For each profile (safe, advanced, ultra) we record expected findings and
  assert true positives are found, evidence is not fabricated, dedup works
  across sources, and scores are deterministic across repeated runs.
- Hardened baselines measure false positives.

Latest validation run (safe profile, purpose-built fixture):
- 11 findings (8 info, 3 low, 3 medium in the fixture run; counts vary by
  profile).
- True positives observed: missing security headers, missing HttpOnly on the
  session cookie, weak SameSite, robots.txt discovery, HTTPS-not-available.
- False positives: none observed on the hardened baseline in the current
  fixture set, but the fixture is small and does not yet cover all analyzers.
- Determinism: risk score identical across repeated runs (5.1 on the fixture).
- Limitations: only one small HTTP fixture today; TLS/ Juice Shop / DVWA
  coverage is not yet automated; numbers are not per-analyzer precision/recall.