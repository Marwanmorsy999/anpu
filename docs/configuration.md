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
  profile: safe   # safe | advanced | ultra (aliases: standard->advanced, deep->ultra)

modules:
  recon: true
  technology: true
  tls: true
  headers: true
  cookies: true
  endpoints: true
  params: true
  subdomains: false
  takeover: false
  portscan: false
  dirs: false
  secrets: false
  cors: false
  methods: false
  csrf: false
  deps: false
  sri: true
  backup: false
  active: false
  nuclei: false
  katana: false
  httpx: false
  subfinder: false
  dalfox: false
  dnsintel: true
  ipintel: true
  naabu: false
  dnsx: false
  rdap: true
  leak: true
  favicon: true
  doh: true
  bucket: true
  bgp: true
  api: true
  authz: true
  zap: false
  # external wrappers (Wave 2): keys match --only names; profile defaults
  # apply when unset. Fuzzers need ANPU_WORDLIST, code tools ANPU_CODE_DIR.
  # external:
  #   ffuf: false
  #   nmap: false
  archiveurls: true   # live-page URL + param corpus (safe+)
  certsan: true       # TLS SAN subdomains (safe+)
  emailharv: true     # email harvest (safe+)
  dnsaudit: true      # DNSSEC/CAA/DANE (safe+)
  emailauth: true     # SPF/DMARC/DKIM/BIMI/TLS-RPT + MTA-STS (safe+)
  csprecon: true      # CSP subdomains (safe+)
  socialhijack: true  # dangling social links (safe+)
  commentminer: true  # HTML comments (safe+)
  brokenlink: true    # broken links (safe+)
  originip: true      # origin-IP signals (safe+)
  exposedgit: true    # exposed .git detection-only (advanced/ultra)
  exposedconfig: true # exposed VCS/env files (advanced/ultra)
  actuator: true      # Spring Actuator, heapdump HEAD-only (advanced/ultra)
  debugpages: true    # framework debug pages (advanced/ultra)
  oauthanalyzer: true # OAuth/OIDC discovery (advanced/ultra)
  samlmetadata: true  # SAML metadata (advanced/ultra)
  cswsh: true         # WebSocket Origin handshake (advanced/ultra)
  postmessage: true   # postMessage/DOM-sink analysis (advanced/ultra)
  jssecrets: true     # JS secret 40+ pack (advanced/ultra)
  hiddenparams: true  # hidden-param miner (advanced/ultra)
  verbtamper: true      # method-tampering bypass (advanced/ultra)
  cachedeception: true  # cache-deception matrix (advanced/ultra)
  forbiddenbypass: true # 403-bypass matrix (advanced/ultra)
  takeoverplus: true    # 30 takeover sigs (advanced/ultra)
  clickjack: true       # XFO + frame-ancestors (safe+)
  policyheaders: true   # HSTS-preload/COOP/COEP/CORP (safe+)
  cookieprefix: true    # cookie prefix rules (safe+)
  apiversion: true      # API version fuzz (advanced/ultra)
  apiconsole: true      # API console walk (advanced/ultra)
  vhost: true           # vhost discovery (advanced/ultra)
  graphqlfp: true     # GraphQL fingerprint (advanced/ultra)
  graphqlschema: true # introspection test (advanced/ultra)
  jwtplus: true       # observed-JWT analysis (safe+)
  sstiexpand: true    # SSTI 10 engines (advanced/ultra)
  nosqlexpand: true   # NoSQL differential (advanced/ultra)
  h2smuggle: true     # H2 desync safe-subset (advanced/ultra + adversarial)
  h2fp: true          # H2/H3 fingerprint (safe+)
  redirectpack: true  # open-redirect pack (advanced/ultra)
  lfipack: true       # LFI pack (advanced/ultra)
  cvepack: true       # CVE behavior probes (advanced/ultra)
  corsplus: true      # CORS matrix (advanced/ultra)
  certhistory: true   # CT history (safe+)
  axfrplus: true      # AXFR sweep (advanced/ultra)
  subpermute: true    # subdomain permutation (safe+)
  backupplus: true    # backup expansion (advanced/ultra)
  faviconplus: true   # icon sweep (advanced/ultra)
  debugmethods: true  # dangerous methods (advanced/ultra)
  encodepoly: true    # encoding canaries (advanced/ultra)
  difforacle: true    # boolean oracle (advanced/ultra)
  gfclassify: true    # GF classifier (safe+)
  soap: true          # SOAP/WSDL discovery (advanced/ultra)
  nsecwalk: true      # NSEC chain walk (advanced/ultra)
  wafdetect: true     # WAF fingerprint (advanced/ultra)
  oauthpack: true    # OAuth redirect_uri pack (advanced/ultra)
  ppollute: true     # proto-pollution static (advanced/ultra)
  swscope: true      # service workers (advanced/ultra)
  timeoracle: true   # timing oracle (advanced/ultra)
  jwtconfirm: true   # alg:none differential (advanced/ultra + adversarial)
  codesecrets: true  # local code review (safe+, needs ANPU_CODE_DIR)

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
| `safe` | Passive and low-impact baseline (API/AuthZ anonymous probing as designed). |
| `advanced` (`standard` alias) | Adds broader active checks and Nuclei when available. |
| `ultra` (`deep` alias) | Adds deeper discovery such as DNS brute-force and TCP port scanning. |

The CLI `--profile` flag overrides the configuration value.

### `scan.adversarial`

Enable hazardous adversarial probes (stateful multi-step, JWT/mass-assign/race/smuggling/proto-pollute, sqli boolean differential with bundle, GraphQL alias flood). Requires `--confirm-authorized` on CLI for authorized ultra targets only (Benign/LowImpact, no data destruction). Equivalent to CLI `--adversarial`.

```yaml
scan:
  profile: ultra
  adversarial: true
```

### `scan.ghost`

Undetectable mode: Chrome 131 JA3, h2, GREASE, stable Chrome-ordered header set (stdlib serializes sorted; true wire-order needs fhttp, tracked), Pareto 800-3500ms jitter, no `anpu` canary substring, proxy rotation, adaptive rate, payload polymorphism. Equivalent to CLI `--ghost`. Combines with `--adversarial --confirm-authorized --proxy-pool` for max power.

```yaml
scan:
  profile: ultra
  ghost: true
  ghost_canary_prefix: ""   # default "" when ghost, no anpu substring; set "anpu" to keep allowlist
  ghost_workers: 4          # parallel ghost workers (0 = sequential)
  proxy_pool: "proxies.txt" # path to proxy list for RoundRobin rotation
```

CLI flags `--ghost`, `--ghost-canary-prefix`, `--ghost-workers`, `--proxy-pool`, `--rate-limit`, `--delay` override these.

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
| `params` | Query-param classification (passive). |
| `subdomains` | Certificate Transparency and profile-gated DNS enumeration. |
| `takeover` | Subdomain takeover detection. |
| `portscan` | TCP connect scanning of common service ports. |
| `dirs` | Sensitive-path discovery with a soft-404 baseline. |
| `secrets` | Credential/token/private-key pattern detection in discovered assets. |
| `cors` | CORS origin and credential behavior checks. |
| `methods` | HTTP method and TRACE checks. |
| `csrf` | CSRF token detection. |
| `deps` | JS library CVE via fingerprints + manifests (requirements.txt/package.json/pom.xml/go.mod) + OSV (npm/PyPI/Maven/Go). |
| `sri` | Subresource Integrity passive check. |
| `backup` | Backup file discovery. |
| `active` | Safe active testing engine. |
| `nuclei` | Optional external Nuclei integration. |
| `katana` | Optional external crawl integration. |
| `httpx` | Optional external probe integration. |
| `subfinder` | Optional passive subdomains integration. |
| `dalfox` | Optional XSS confirmation integration. |
| `dnsintel` | Passive DNS intel. |
| `ipintel` | Passive IP/ASN intel. |
| `naabu` | Optional fast port-scan integration. |
| `dnsx` | Optional DNS toolkit integration. |
| `rdap` | Passive RDAP WHOIS. |
| `leak` | Private-IP leak detection. |
| `favicon` | Favicon hash correlation. |
| `doh` | DoH exposure check. |
| `bucket` | Cloud bucket probe. |
| `bgp` | BGP prefix intel. |
| `api` | API schema discovery + testing. |
| `authz` | Authorization testing (incl. anonymous probing). |
| `idor` | BOLA/IDOR id+1 replay (read-only GETs; off on safe, on for advanced/ultra). |
| `zap` | ZAP via Docker/zap.sh with embedded fallback (implemented). |
| `adversarial` | Hazardous probes gated by `--adversarial --confirm-authorized` (stateful, JWT/mass-assign/race/smuggling/proto-pollute, sqli boolean differential, alias flood). Safe/advanced = off; ultra + confirm = on. |

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
anpu scan https://example.com --profile ultra --no-nuclei
```

uses the supplied target and ultra profile while explicitly disabling Nuclei for that invocation.

## Example configurations

### Safe baseline

```yaml
scan:
  profile: safe
  # adversarial: false   # set true + CLI --confirm-authorized to enable hazardous probes on authorized ultra only (Benign/LowImpact, no data destruction)

modules:
  recon: true
  technology: true
  tls: true
  headers: true
  cookies: true
  endpoints: true
```

### Advanced assessment

```yaml
scan:
  profile: advanced

modules:
  subdomains: true
  dirs: true
  secrets: true
  cors: true
  methods: true
  nuclei: true
```

### Ultra discovery

```yaml
scan:
  profile: ultra

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
