# Configuration Reference

ANPU can load settings from a YAML file named `anpu.yaml` in the current directory, or from a path supplied with the global `--config` flag.

```sh
anpu scan --config ./configs/staging.yaml
```

CLI flags take precedence over values from the configuration file. A missing default `anpu.yaml` is allowed; ANPU can run entirely from CLI arguments.

## Complete shape

The repository includes [`anpu.example.yaml`](../anpu.example.yaml) as a starting point:

```yaml
target:
  url: https://example.com

scan:
  profile: safe

modules:
  recon: true
  technology: true
  tls: true
  headers: true
  cookies: true
  endpoints: true
  subdomains: false
  portscan: false
  dirs: false
  secrets: false
  cors: false
  methods: false
  nuclei: false
  zap: false

report:
  html: true
  json: true
  sarif: false
```

## `target`

### `target.url`

The default scan target. It should be an HTTP or HTTPS URL.

```yaml
target:
  url: https://staging.example.com
```

When a target is supplied directly to `anpu scan <target>`, that argument takes precedence over `target.url`.

For a configured target without a scheme, ANPU defaults it to HTTPS before validation.

## `scan`

### `scan.profile`

Select the default scan profile:

| Profile | Purpose |
|---|---|
| `safe` | Passive and low-impact baseline. |
| `standard` | Adds broader active checks and Nuclei when available. |
| `deep` | Adds deeper discovery such as DNS brute-force and TCP port scanning. |

The CLI `--profile` flag overrides the configuration value.

## `modules`

Each module can be enabled or disabled explicitly. Profile defaults provide the baseline, and explicit configuration can further control individual engines.

| Module | Description |
|---|---|
| `recon` | DNS, robots.txt, sitemap.xml, redirects, and source-map discovery. |
| `technology` | Passive web-stack fingerprinting. |
| `tls` | Certificate and HTTPS/TLS analysis. |
| `headers` | HTTP security-header analysis. |
| `cookies` | Cookie attribute analysis. |
| `endpoints` | Link, form, script, and API-path discovery. |
| `subdomains` | Certificate Transparency and profile-gated DNS enumeration. |
| `portscan` | TCP connect scanning of common service ports. |
| `dirs` | Sensitive-path discovery with a soft-404 baseline. |
| `secrets` | Credential/token/private-key pattern detection in discovered assets. |
| `cors` | CORS origin and credential behavior checks. |
| `methods` | HTTP method and TRACE checks. |
| `nuclei` | Optional external Nuclei integration. |
| `zap` | Reserved integration point; the driver is not implemented yet. |

A disabled module is skipped by the pipeline rather than treated as an error.

## `report`

The configuration file can define the default report outputs. The CLI also exposes output flags on `anpu scan`.

```yaml
report:
  html: true
  json: true
  sarif: false
```

Use `--json`, `--html`, and `--sarif` when you need to select outputs for a particular invocation.

## Precedence

The practical order is:

```text
CLI flags
    ↓
resolved configuration
    ↓
profile defaults
    ↓
built-in defaults
```

This means, for example, that:

```sh
anpu scan https://example.com --profile deep --no-nuclei
```

uses the supplied target and deep profile while explicitly disabling Nuclei for that invocation.

## Example configurations

### Safe baseline

```yaml
scan:
  profile: safe

modules:
  recon: true
  technology: true
  tls: true
  headers: true
  cookies: true
  endpoints: true
```

### Standard assessment

```yaml
scan:
  profile: standard

modules:
  subdomains: true
  dirs: true
  secrets: true
  cors: true
  methods: true
  nuclei: true
```

### Deep discovery

```yaml
scan:
  profile: deep

modules:
  subdomains: true
  portscan: true
  dirs: true
  secrets: true
  cors: true
  methods: true
  nuclei: true
```

## Validation and safe use

ANPU validates targets before network activity and applies SSRF/local-network protections through its shared HTTP client. Configuration does not bypass authorization requirements: only scan systems you own or are explicitly authorized to test.
