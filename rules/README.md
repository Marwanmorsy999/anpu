# rules/

Reserved for future custom detection rules (e.g. a declarative format
for pattern-based checks similar in spirit to Nuclei templates, but
maintained by ANPU itself).

No custom rule engine is implemented in this MVP — see the built-in
analyzers under `internal/` (for example `internal/headers`,
`internal/tls`, `internal/technology`, and `internal/recon`), which are
implemented directly in Go rather than a rules DSL.

Future custom rules would live here once a rule-loading engine grows,
keeping detection logic data-driven and easier to extend without
recompiling ANPU.
