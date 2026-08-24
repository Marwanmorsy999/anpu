# rules/

Reserved for future custom detection rules (e.g. a declarative format
for pattern-based checks similar in spirit to Nuclei templates, but
maintained by ANPU itself via `internal/analyzers`).

No custom rule engine is implemented in this MVP — see
`internal/headers`, `internal/tls`, `internal/technology`, and
`internal/recon` for the current built-in analyzers, which are
implemented directly in Go rather than a rules DSL.

Future custom rules would live here once `internal/analyzers` grows a
rule-loading engine, keeping detection logic data-driven and easier to
extend without recompiling ANPU.
