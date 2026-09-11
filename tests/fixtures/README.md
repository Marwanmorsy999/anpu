# tests/fixtures

Cross-package fixtures for Phase 0 regression tests. All targets are
fictional (`example.com`); no fixture may reference a real third-party
website.

- `burp-sample.xml` — minimal Burp export (2 issues) for `importx.ParseBurp`.
- `zap-sample.json` — minimal ZAP JSON (`site[0].alerts`) for `importx.ParseZAP`.
- `har-sample.json` — 3 entries (one 500) for `importx.ParseHAR`.
- `nuclei-sample.jsonl` — 2 JSONL lines for Nuclei conversion regression.
- `soft404-baseline-a.html` / `soft404-baseline-b.html` — same SPA shell,
  different nonce/hash (must match after normalization).
- `soft404-different.html` — genuinely different page (must not match).
- `waf-block.html` — WAF block page markers (must never become an exposure).
