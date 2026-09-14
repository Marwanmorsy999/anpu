# Plugin SDK

Extend ANPU with custom detections without touching the scan pipeline:
declarative YAML checks for marker-style issues, or Go plugins for
custom logic. Both run through ANPU's guarded fetching.

## Safety contract

Plugins never touch the network directly. Every request goes through a
host-provided fetch callback carrying the same SSRF, local-network,
timeout, and redirect guards as built-in engines — a plugin cannot
probe anything the CLI itself would refuse. Loopback targets are
allowed automatically; anything else needs `ANPU_ALLOW_LOCAL_NETWORK=1`,
exactly like scans.

## YAML checks (no code)

```sh
anpu plugin init --dir mycheck   # scaffold mycheck.yaml + mycheck.go
anpu plugin run --plugin mycheck/mycheck.yaml https://target.example
anpu plugin run --plugin mycheck/mycheck.yaml https://target.example --format json
```

A plugin file is a list of checks:

```yaml
checks:
  - name: generator-meta
    path: /
    match: '<meta\s+name="generator"'
    title: Generator meta tag discloses platform
    description: Why it matters.
    severity: low            # info, low, medium, high, critical
    confidence: high         # low, medium, high, confirmed
    category: technology-disclosure
    remediation: Remove the tag.   # optional
```

Semantics: fetch `target + path`; on 2xx, match the body against the
RE2 regex; on match, emit one finding (`source: plugin`, stable ID
derived from name + path). Non-2xx never matches — absence of evidence
is not evidence. Files are validated up front (vocabularies, leading
`/`, regex compiles); a broken file fails fast.

## Go plugins

Implement `plugins.Plugin` (`pkg/plugins` — imports only `pkg/models`
plus stdlib, so external modules stay cycle-free):

```go
type Plugin interface {
    Name() string
    Description() string
    Run(ctx context.Context, target string, fetch plugins.FetchFunc) ([]models.Finding, error)
}
```

Register it (`plugins.Register`, usually in `init`), then:

```sh
anpu plugin list                              # registered Go plugins
anpu plugin run --name my-check https://target.example
```

Findings must carry `Source: models.SourcePlugin` and deterministic IDs
for the same observation. See `pkg/plugins/example/` for a complete
runnable reference (passive generator-meta check, registered in the CLI
as `example-generator-meta`).

## What plugins are (and are not)

- Plugins run standalone via `anpu plugin run`. They are **not** wired
  into `anpu scan` profiles — scans are unaffected by installed plugins.
- Plugin findings skip scoring/dedup/history; `--format json` is the
  machine interface for scripting.
- Keep checks passive and read-only (GET only). Anything state-touching
  belongs in a contracted engagement, not a plugin.
