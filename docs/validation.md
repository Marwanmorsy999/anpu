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

Precision/recall numbers are collected from the validation harness and
published here once the harness is wired into CI. Until then, treat the
benchmark in docs/benchmark.md as the only measured detection table.