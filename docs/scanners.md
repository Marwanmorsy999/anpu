# Scanner and Engine Reference

ANPU combines built-in analyzers with an optional Nuclei integration. The scanner pipeline normalizes results into the shared finding model, deduplicates overlapping findings, scores them deterministically, and writes reports.

## Engine matrix

| Engine | What it checks | Profile scope | Activity | External dependency |
|---|---|---|---|---|
| Recon | DNS, robots.txt, sitemap.xml, security.txt, redirects, source maps | All | Passive | No |
| Technology | Server/framework/CMS/CDN/library signals (~130 fingerprints), WordPress version/users/xmlrpc | All | Passive + ≤3 WP GETs | No |
| TLS | Certificate validity, expiry, hostname, protocols, HTTPS behavior | All | Passive | No |
| Headers | CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, disclosure headers | All | Passive | No |
| Cookies | Secure, HttpOnly, SameSite attributes | All | Passive | No |
| Endpoints / Crawler | Same-host pages, links, forms, scripts, API/path references | All | Bounded GETs | No |
| SRI | Subresource Integrity for cross-origin scripts/styles | All | Passive | No |
| DNSIntel | Passive DNS enumeration (MX/NS/TXT/SPF/DMARC) | All | Passive | No |
| IPIntel | Reverse PTR, cloud provider, ASN + IP RDAP | All | Passive | No |
| RDAP | Domain registration (registrar, creation/expiry) via RDAP | All | Passive | No |
| Leak | Private IP / internal host leak in headers/body | All | Passive | No |
| Favicon | Favicon mmh3 hash pivot | All | Passive | No |
| DoH | DNS-over-HTTPS endpoint exposure | All | Passive | No |
| Bucket | Cloud bucket existence probe (S3/Azure/GCS) | All | Passive | No |
| BGP | BGP prefix + RPKI hint via BGPView | All | Passive | No |
| Subdomains | CT logs + Common Crawl, urlscan, CertSpotter, hackertarget, Anubis-DB; permutations (advanced+); DNS brute-force (ultra) | Advanced/Ultra | Passive + bounded DNS | No |
| Takeover | 21 provider fingerprints + dangling-CNAME (NXDOMAIN) catch-all | Advanced/Ultra | Bounded GETs | No |
| API | Auto-discovers openapi.json/swagger and GraphQL introspection at well-known paths; explicit --openapi/--graphql supported | All | Bounded GETs | No |
| AuthZ | Two-identity comparison when creds given; anonymous forced-browsing of sensitive endpoints otherwise (safe-profile anonymous probing as designed) | All | Bounded GETs | No |
| PortScan | TCP connect scan of common service ports | Ultra | Active | No |
| Naabu | Fast port scan (embedded, external optional) | Ultra when available | Active | Naabu binary (optional) |
| DNSx | DNS toolkit (embedded, external optional) | Advanced/Ultra when available | Passive | dnsx binary (optional) |
| Dirs | Sensitive-path probing with soft-404 baseline | Advanced/Ultra | Active | No |
| Secrets | API-key/token/private-key patterns + chunk + fetched-sourcemap scan, JS route mining, email harvest | Advanced/Ultra | Active | No |
| CSRF | Missing CSRF tokens in forms | Advanced/Ultra | Active | No |
| Backup | Backup/archive file probing per endpoint | Advanced/Ultra | Active | No |
| Deps | Built-in advisory table + live OSV.dev lookup for npm/PyPI/Maven/Go package@version (Master: 150 cap, sorted before cap) | Advanced/Ultra | 1 batched POST | No (keyless) |
| Active | Safe active tests: XSS/SQLi/SSRF/path-traversal/bypass-403/blind + cache oracle + Master 11 injection families (LDAP, XPath, SSI, HPP, RFI, Code, Buffer, Formula) + rate-limit API4 | Advanced/Ultra | Active | No |
| CORS | Wildcard, reflection, and credential behavior | Advanced/Ultra | Active | No |
| Methods | `OPTIONS`/`Allow` behavior and live TRACE verification | Advanced/Ultra | Active | No |
| Nuclei | Profile-scoped external vulnerability templates | Advanced/Ultra when available | Active | Nuclei binary |
| Katana | External crawl (JS-heavy routes the built-in crawler misses) | Advanced/Ultra when available | Active | Katana binary |
| Httpx | External probe corroborating technology fingerprinting | Advanced/Ultra when available | Bounded GETs | httpx binary |
| Subfinder | Passive subdomain enumeration feeding Takeover | Advanced/Ultra when available | Passive | subfinder binary |
| Dalfox | XSS confirmation on discovered parameterized URLs; embedded param mining when none exist | Advanced/Ultra when available | Active | dalfox binary |
| Params | Query-parameter classification (sqli/xss/ssrf/idor/redirect/lfi/rce/ssti) | All | Passive | No |
| ZAP | Full scan via Docker/zap.sh when present; embedded passive checks (clickjacking, robots, mixed content, error pages) otherwise | Ultra when available | Active | Docker or ZAP (optional) |
| ArchiveURLs | Live-page URL + param corpus (homepage/robots/JS) | All | ≤3 GETs | No |
| CertSAN | TLS certificate SAN subdomain signal | All | 0 HTTP (TLS handshake) | No |
| EmailHarv | Homepage email harvest, placeholders filtered | All | 1 GET | No |
| DNSAudit | DNSSEC/CAA/DANE posture | All | DNS-only | No |
| EmailAuth | SPF/DMARC/DKIM (3 selectors)/BIMI/TLS-RPT + MTA-STS | All | DNS + ≤1 GET | No |
| CSPRecon | CSP host-source subdomain extraction | All | 1 GET | No |
| SocialHijack | Dangling social profile links (HEAD verify, max 5) | All | 1 GET + ≤5 HEAD | No |
| CommentMiner | Interesting HTML comments, control-subtracted | All | ≤2 GETs | No |
| BrokenLink | Same-host broken links, soft-404 baseline | All | ≤22 reqs (10 links) | No |
| OriginIP | Origin-IP signals (CNAME/DNS/direct-IP title) | All | ≤3 GETs | No |
| ExposedGit | Exposed .git, dual-marker detection-only (never fetches objects) | Advanced/Ultra | ≤4 GETs | No |
| ExposedConfig | Exposed SVN/HG/BZR/ENV/DS_Store markers | Advanced/Ultra | ≤7 GETs | No |
| Actuator | Spring Actuator pack (heapdump HEAD-only, never downloaded) | Advanced/Ultra | ≤12 reqs | No |
| DebugPages | Laravel/Telescope/phpinfo/server-status/trace/elmah/pprof-index | Advanced/Ultra | ≤9 GETs | No |
| OAuthAnalyzer | OIDC discovery + implicit-flow check, endpoints harvested | Advanced/Ultra | ≤6 GETs | No |
| SAMLMetadata | SAML EntityDescriptor + SSO endpoint harvest | Advanced/Ultra | ≤5 GETs | No |
| CSWSH | WebSocket handshake with foreign Origin (0 frames sent) | Advanced/Ultra | ≤4 raw dials | No |
| PostMessage | postMessage listener/sink static analysis | Advanced/Ultra | ≤6 GETs | No |
| JSSecrets | JS secret 40+ regex pack, values masked, never validated | Advanced/Ultra | ≤9 GETs | No |
| Jsluice | Native jsluice port: greedy quoted-string URL harvest + browser-style joinery, 14-pattern secret pack (upstream archived, technique ported not wrapped) | Advanced/Ultra | ≤9 GETs | No |
| HiddenParams | Hidden-param miner, 30-name wordlist, dual baseline | Advanced/Ultra | ≤64 GETs | No |
| VerbTamper | Method-tampering bypass on denied endpoints, denial baseline | Advanced/Ultra | ≤21 reqs | No |
| CacheDeception | Deceptive-suffix matrix + cache HIT check | Advanced/Ultra | ≤8 GETs | No |
| ForbiddenBypass | Header/path 403-bypass matrix, dual baseline | Advanced/Ultra | ≤24 GETs | No |
| TakeoverPlus | 30 dnsReaper-family sigs, CNAME + body required | Advanced/Ultra | ≤20 hosts | No |
| Clickjack | X-Frame-Options + CSP frame-ancestors analysis | All | ≤3 GETs | No |
| PolicyHeaders | HSTS preload readiness + COOP/COEP/CORP gaps | All | 1 GET | No |
| CookiePrefix | __Host-/__Secure- attribute rule audit | All | ≤3 GETs | No |
| APIVersion | Sibling API version fuzz + endpoint harvest | Advanced/Ultra | ≤11 reqs | No |
| APIConsole | GraphiQL/Altair/RapiDoc/Redoc walk + schema harvest | Advanced/Ultra | ≤11 GETs | No |
| VHost | Bounded vhost discovery via Host override, 12 names | Advanced/Ultra | ≤13 GETs | No |
| GraphQLFP | Typename probe + engine identify, endpoints harvested | Advanced/Ultra | ≤8 reqs | No |
| GraphQLSchema | Introspection disclosure test, read-only | Advanced/Ultra | ≤3 reqs | No |
| JWTPlus | Observed-JWT decode (none/kid/jku/exp), never replayed | All | 1 GET | No |
| SSTIExpand | 10-engine benign-math differential | Advanced/Ultra | ≤24 GETs | No |
| NoSQLExpand | Operator differential, no extraction | Advanced/Ultra | ≤18 GETs | No |
| H2Smuggle | H2 desync safe-subset timing, adversarial-gated | Advanced/Ultra + adversarial | ≤5 reqs | No |
| H2FP | H2 ALPN + H3 Alt-Svc fingerprint | All | ≤1 req | No |
| RedirectPack | 10-payload pack, no-follow Location inspection | Advanced/Ultra | ≤22 GETs | No |
| LFIPack | Traversal/wrapper pack, marker + differential | Advanced/Ultra | ≤20 GETs | No |
| CVEPack | Version-signature mapping + inert Spring differential | Advanced/Ultra | ≤3 GETs | No |
| CORSPlus | Null/evil/subdomain credentialed matrix | Advanced/Ultra | ≤12 GETs | No |
| CertHistory | crt.sh age + subdomain harvest (target untouched) | All | 1 archive req | No |
| AXFRPlus | Zone-transfer sweep across all NS (names only) | Advanced/Ultra | DNS-only | No |
| SubPermute | Offline permutation + DNS confirm | All | ≤50 DNS | No |
| BackupPlus | 30-suffix vendored expansion | Advanced/Ultra | ≤61 GETs | No |
| FaviconPlus | 8-path icon sweep + hash groups | Advanced/Ultra | ≤9 GETs | No |
| DebugMethods | DEBUG/TRACE/TEST live probes, empty bodies | Advanced/Ultra | ≤8 reqs | No |
| EncodePoly | Encoding canary matrix, no exploit payloads | Advanced/Ultra | ≤13 GETs | No |
| DiffOracle | Boolean oracle differential, repeat-stable | Advanced/Ultra | ≤8 GETs | No |
| GFClassify | GF-pattern classifier, fully offline | All | 0 reqs | No |
| Soap | SOAP/WSDL discovery + op harvest, no envelope POSTs | Advanced/Ultra | ≤9 GETs | No |
| Nsecwalk | NSEC chain walk (40 hops), NSEC3 detect | Advanced/Ultra | DNS-only | No |
| Wafdetect | Canary block-behavior matrix + vendor ID | Advanced/Ultra | ≤5 GETs | No |
| Oauthpack | redirect_uri confusion pack, Location inspected never followed | Advanced/Ultra | ≤17 reqs | No |
| Ppollute | Deep-merge sink + URL/message source static match | Advanced/Ultra | ≤6 GETs | No |
| Swscope | Root-scope and foreign importScripts review | Advanced/Ultra | ≤6 GETs | No |
| Timeoracle | Median-gated sleep differential, repeat-stable | Advanced/Ultra | ≤11 GETs | No |
| Jwtconfirm | Unsigned-token acceptance differential (adversarial) | Advanced/Ultra + adversarial | ≤7 reqs | No |
| Schematype | Schema type-confusion probes (query + JSON body) | Advanced/Ultra (Active) | ≤5/vector | No |
| Schemarequired | Required-param omission differential | Advanced/Ultra (Active) | ≤3/vector | No |
| Schemacontent | Content-Type confusion with garbage-type control | Advanced/Ultra (Active) | ≤4/vector | No |
| Codesecrets | Local tfstate/env/docker/k8s secrets + misconfigs | All (needs ANPU_CODE_DIR) | 0 reqs, ≤300 files | No |
| SBOM | CycloneDX 1.4 inventory from resolved deps (Deps artifact) | Whenever Deps resolves | 0 extra reqs | No |

Exact module enablement can also be controlled through `anpu.yaml`. See [configuration.md](configuration.md).

NSEC walking honors `ANPU_DNS_RESOLVER` (host or `host:port`, default `8.8.8.8`) so labs can point it at an internal resolver; nameserver hostnames are resolved through it before dialing.

Wave 0 infra: `internal/integrations/registry.go` holds install recipes for 80+ free external binaries (`anpu tools install <name>`); `internal/http/budget.go` is the global per-tool request budget ledger consulted before payload-pack expansion; `internal/scope/scope.go` enforces `--scope-file` with a hard stop before any request. Every new probe follows house style: explicit request budget, baseline-subtract, echo-guard, warn-and-skip (never fatal).

## Wave 2 — external wrappers

All 84 free binaries run through one data-driven runner (`internal/integrations/generic.go` + `specs.go`): real CLI vectors with read-only/bounded flags, timeout + 2MB output caps, structured parsing where output shapes are stable (ffuf/gobuster/wfuzz/dirsearch hits, nikto lines, nmap/masscan/rustscan ports, wpscan/semgrep/trivy/osv/grype/searchsploit JSON, openredirex `[FOUND]` chains → Medium, dotdotpwn `VULNERABLE!` verdicts → High), plus URL/host mining and a summary finding carrying the exact repro command. openredirex runs stdin URLs at `-c 10`; dotdotpwn runs the http-module read-only confirm (`-f /etc/hosts` + `-k localhost` per upstream EXAMPLES, depth 4, adversarial-gated) and keeps its own run report in its Reports directory. **Zero installs needed:** when a binary is absent (or `--auto-install` fails), the stage runs its embedded native fallbacks (`specs.go: embeddedFallbacks`) — e.g. ffuf → Dirs+BackupPlus, subzy → Takeover+TakeoverPlus, jsluice → the native Jsluice port + secrets pack — and names them in an `*-embedded` finding. Fallbacks already enabled as native stages are filtered out at pipeline build, so nothing probes twice; a fully covered stage disables with an install pointer. Missing prerequisites (`ANPU_CODE_DIR`, parameterized URL) warn-and-skip; mass-DNS resolvers default to public DNS; adversarial tools need `--adversarial --confirm-authorized`. The 9 remaining manual-recipe tools (ssrfmap, nosqlmap, graphqlmap, jwt_tool, hakoriginfinder, jsluice, anew, massdns, mobsf) run as embedded-only stages — ANPU never guesses their CLI flags. Per-tool request budgets are enforced globally via the ledger (`hiddenparams` 64, `backupplus` 61, `apiversion`/`apiconsole` 11). Toggles live in `ModuleConfig` `wrapper` tags (`--only ffuf`, `external:` YAML map). `anpu tools install <name>` (or `--all --yes`, or `--auto-install` mid-scan) adds full binary depth, verified on PATH/Go-bin including `go env`-based detection when `GOPATH` is unset. Genuinely non-embeddable: screenshots (need headless Chrome), MobSF (needs your APK + operator server), anpu's own `anew`/massdns utils.

## Wave 3 — keyless feeds

`internal/feeds`: CISA KEV cache (`anpu feeds update`, exploited-in-wild → Confirmed + CISA ref in scoring), FIRST EPSS (opt-in `ANPU_EPSS=1`), GitHub Advisory notes, URLhaus + ThreatFox reputation (`anpu feeds check`, surfaced as warnings), OSV Rust/RubyGems via Cargo.lock/Gemfile.lock harvest, vendored `wordlists/` subsets (`anpu wordlists update` refreshes from SecLists, opt-in). PhishTank is excluded — its API requires a key.

## Wave 4 — workflow

`anpu query` (finding filter over saved JSON), `anpu import` (Burp XML / ZAP JSON / HAR → findings, import-only), notify fan-out (`watch --webhook/--discord/--telegram`), CSV/Markdown export (`show --format csv|md`), scope hard-stop (`--scope-file`), budget ledger wired into `ScanContext` (hiddenparams capped at 64), drift monitor with parser pins (`anpu drift`).

## Pipeline phases and runtime gates

Stages run phase by phase — Foundation (passive intel) → Discovery (crawlers, enumerators) → Targeted (probes of discovered surface) → Active (differentials, confirmations, timing-sensitive work) — so every stage's inputs exist before its consumers run. Within a phase, snapshot-safe stages run concurrently (`--parallel 8` default, deterministic in-order merge). Reports carry a per-phase wall-time ledger plus the top-5 slowest stages (terminal `Phases:`/`Slowest:` lines, HTML phase section, `phase_timings`/`slowest_stages` in JSON) so the next speed pass is data-driven.

Runtime gates skip quietly with a reason (`[--]`, never a warning or finding) when a stage has nothing useful to do: stack gates (`wpscan`/`droopescan`/`joomscan`/`cmseek` run only when the fingerprinted stack matches, fail-open on unknown), the amass yield gate (skips slow enumeration once natives already delivered ≥10 subdomains; verbose run receipts log yield-vs-time for every wrapper), the parameter-corpus gate (reflection testers need a parameterized URL), the adversarial gate (state-touching tools need `--adversarial --confirm-authorized`), and the safe-purity filter (active native fallbacks never run implicitly on `safe`).

## Recon

Recon establishes the initial attack-surface picture. It observes DNS results and web metadata such as `robots.txt`, `sitemap.xml`, `security.txt` (RFC 9116 contact), redirect chains, and source-map references.

The output is used by later stages rather than being treated as a vulnerability by itself.

## Technology

Technology detection uses observed signals from headers, cookies, HTML, and JavaScript to identify likely servers, frameworks, CMSs, CDNs, and libraries (~130 fingerprints). Version information is only reported when supported by observed evidence.

When WordPress is detected, a bounded mini-pack runs: exact version via `readme.html`, user enumeration via `wp-json/wp/v2/users`, and `xmlrpc.php` surface check (max 3 extra GETs, read-only).

## TLS

TLS analysis checks certificate validity and expiration, hostname matching, supported protocol versions, and HTTP-to-HTTPS behavior where applicable.

## Headers and cookies

The headers analyzer checks security-related HTTP response headers and server disclosure. The cookie analyzer evaluates `Secure`, `HttpOnly`, and `SameSite` attributes with context-aware findings.

These checks are low-impact because they inspect HTTP behavior rather than attempting exploitation.

## Endpoint discovery and bounded crawling

Endpoint discovery now uses a bounded same-host crawler. The crawler starts at the target URL, records normalized links/forms/scripts/API references, and follows only same-host HTTP(S) document URLs. Obvious static assets are recorded as endpoints but are not recursively crawled.

Safe profile includes API/AuthZ anonymous probing as designed behavior (GET-only, no credentials required).

The crawl remains bounded by profile:

- `safe`: target page only (`1` page, depth `0`)
- `advanced`: up to `25` pages, depth `2`
- `ultra`: up to `100` pages, depth `4`

The crawler performs GET requests only; it never submits forms, attempts authentication, or brute-forces paths. All requests go through ANPU's shared HTTP client, preserving redirect and local-network protections.

A page-limit warning is emitted when the configured bound is reached. This makes scan scope visible rather than silently truncating discovery.

## Subdomains

Subdomain discovery fans out to keyless passive indexes (Certificate Transparency via crt.sh and CertSpotter, Common Crawl, urlscan.io, hackertarget, Anubis-DB) with a ≤60s per-stage deadline. Advanced and above add dnsgen-style name permutations; ultra adds DNS brute-force candidates.

ANPU validates and resolves candidates through its shared network-safety controls before performing active requests.

## Takeover

Takeover checks every discovered subdomain against 21 provider fingerprints (CNAME suffix + unclaimed-resource body string, both required) plus a generic dangling-CNAME check: any CNAME whose target is NXDOMAIN in public DNS is flagged for verification, catching providers the table has never heard of.

## Port scanning

The port scanner uses TCP connect probes against a curated set of common service ports. ANPU includes sanity/false-positive safeguards so environments that accept unexpected connections do not blindly turn every port into a finding.

Port scanning is enabled for `ultra` discovery and is not part of the default safe profile. When a CDN/edge provider is fingerprinted (broad name matching, not just four vendors), every open-port finding and the summary carry an edge caveat: verify against the origin before acting.

## Sensitive paths

The directory/path engine probes a controlled set of sensitive paths and establishes a soft-404 baseline. This helps distinguish genuinely exposed resources from applications that return the same generic page for arbitrary paths. WAF/vendor block pages served as 200 are vetoed via shared block markers (`internal/fpmatch`), and 401/403/406 responses are classified as WAF noise vs present-but-protected candidates — the latter surface as warnings, never as exposure findings. Backup/exposed-config/actuator/debug/SOAP engines apply the same shared template matching (catch-all baseline + lazy site-root shell check) so SPA catch-alls produce no false exposures.

## Secret detection

The secret scanner examines discovered assets for supported credential, token, and private-key patterns. Findings are evidence-backed and samples are redacted before being reported.

The scanner limits per-asset scan size to avoid unbounded regex work on unusually large responses.

Beyond bundles, the stage fetches referenced webpack chunks (max 5) and `sourceMappingURL` maps (max 3, same-origin) and scans their original source too; relative and template-literal route references are resolved for the endpoint list, and up to 20 email addresses are harvested from a bounded set of pages.

## API discovery

With no flags, the API stage probes well-known schema locations (`openapi.json`, `swagger.json`, GraphQL introspection at `/graphql` and siblings) using read-only requests. Discovered schemas feed AuthZ comparison and Active testing exactly like explicitly supplied `--openapi` / `--graphql` inputs.

## Authorization

With two identities configured (`--authz-token` / `--authz-cookie` / `--authz-header`), AuthZ compares responses per endpoint. Fully anonymous scans instead force-browse sensitive endpoints (admin consoles, account areas, APIs) once each and flag 200 responses that should have been denied.

## CORS

The CORS analyzer tests behavior with attacker-controlled origins and checks cases such as:

- wildcard origin with credentials;
- wildcard origin without credentials;
- arbitrary-origin reflection with credentials.

A detected behavior is reported with the response evidence observed by the analyzer.

## HTTP methods

The methods analyzer reviews advertised methods and performs a live TRACE test where appropriate. TRACE findings require an actual successful behavior rather than merely an `Allow` header containing the word `TRACE`.

## Nuclei

Nuclei is optional. ANPU invokes a real `nuclei` executable when available and parses its JSONL output into the common finding model.

ANPU does not silently download or install Nuclei. When it is unavailable, ANPU reports a warning and continues with built-in analysis.

Check availability with:

```sh
anpu tools
```

## OWASP ZAP

ZAP runs full (`zap-full-scan.py`) or baseline scans via Docker or a local `zap.sh` when either is present (podman is accepted as a Docker-compatible runtime; `ZAP_BINARY` overrides discovery). Without external ZAP, an embedded fallback performs real passive checks — clickjacking framing policy, sensitive `robots.txt` paths, mixed content, and verbose error pages — instead of skipping.

## XSS confirmation (Dalfox)

Dalfox confirms XSS on discovered parameterized URLs. When pages carry no query strings, the embedded fallback mines common parameter names with distinct canaries (one spray request per page) and confirms only reflected ones with an inert payload — no external binary required.

## GraphQL abuse suite

Beyond introspection disclosure, the API stage runs four safe read-only checks on every known GraphQL endpoint: array-batched queries (brute-force amplification past request-count limiters), `Did-you-mean` field suggestions (schema reconstruction aid), queries over GET (CSRF exposure), and unbounded query depth (DoS exposure, tested only when introspection succeeded so the probe is schema-valid). No mutations are ever sent.

## Active testing & OOB confirmation

The Active engine probes query/path vectors with per-rule request budgets. Signal discipline: error-based SQLi is baseline-subtracted (High/Medium, never Critical on a string match), and a boolean-differential rule (`' AND '1'='1` vs `' AND '1'='2`, stability-gated) confirms blind SQLi at High/High. Single-technique differentials are capped at Medium and tagged needs-review — fully earned High/High requires a 200×3 same-content-type baseline, a random control, and an evidence bundle. The same contract now covers XSS (baseline + random control + reflection-context classification; comment/script context capped at Medium), command injection (baseline-subtracted canary marker earns High with echo-guard, bare error strings capped at Medium, never Critical), HTTP smuggling (length differentials capped at Medium), and blind timing (double-sleep capped at Medium as a same-family repeat). Nuclei/ZAP matches with no captured evidence (`evidence.unavailable`) are capped at Medium/Medium. Dedup keeps max severity but flags `disputed-sources` + needs-review when merged sources span 2+ severity ranks.

Ultra-only confirmations (Phase 3, wired via `active.SetUltraConfirm` in `runScan` — advanced behavior is byte-identical): an XSS finding whose second benign tag family (`<u>` vs `<b>`) also reflects unescaped rises to High confidence; a command-injection error signal raised by two metacharacter families (pipe vs `;` vs backtick) clears the review flag at Medium/Medium; a blind-timing double-sleep whose 2s/5s delays scale with the sleep argument upgrades to High/High (`delay-scaling-confirmed`). Smuggling deliberately has no ultra upgrade — length differentials cannot confirm a desync at any budget. Schema-declared API parameters flow into the engine as query and JSON-body vectors, lighting up the POST branches of the SQLi/NoSQL/SSRF rules. SSRF covers AWS/Alibaba/DigitalOcean metadata plus a single canary for non-URL-looking parameters.

`--oob-interactsh` (opt-in) registers one session on the public interactsh fleet and upgrades blind SSRF, XXE, and Log4Shell from "injected" to CONFIRMED when a callback carrying the probe nonce is observed (12s window per probe). Without the flag, behavior is byte-identical to in-band-only mode. Callback metadata goes to interactsh servers — only use against targets you own or are authorized to test. Your own listener stays supported via `--oob-host` (manual verification).

A cache-poisoning oracle probes unkeyed headers (X-Forwarded-Host and friends) with an inert canary on cacheable pages only, then re-requests clean: persistence proves cache-key exclusion (High/High), reflection without persistence is a Medium candidate. Non-cacheable reflection stays silent (host-header territory).

## Engine capability matrix (what each check can and cannot prove)

Severity/confidence below are what the engine emits today, verified against the rule code. **Proven** means the claim is earned by execution proof or a corroborated differential; **capped** is what the same engine emits without that proof. Rows marked † exceed the corroboration contract today (single-signal evidence at High-or-worse) — treat them with extra review; they are scheduled hardening candidates, not falsehoods.

### Active differentials and confirmations

| Engine (rule ID) | Proves (best claim) | Without that proof (cap) |
|---|---|---|
| `sqli-boolean-differential` | TRUE≈baseline + FALSE diverges + 200×3 same CT + random control → **High/High** | **Medium/Medium** + `single-technique` review |
| `xss-reflected` | Tag reflected unescaped, baseline + control clean, executable context → **High/Medium**; ultra second tag family → **High/High** | **Medium/Medium** + review (comment/script context, missing control) |
| `cmd-injection-indicator` | Canary marker differential + echo-guard → **High/Low** | **Medium/Low** + review (bare error strings); ultra second family clears review at Medium/Medium; never Critical |
| `blind-timing` | Double 5s sleep → **Medium/Medium** + `timing-differential` review | — ; ultra 2s/5s delay scaling → **High/High** |
| `http-smuggling` | — (length differentials cannot confirm a desync) | **Medium/Low** + `single-technique` review; no ultra upgrade by design |
| `log4shell-jndi` | OOB callback → **Critical/High** | Reflection → **High/Medium** (Critical needs the callback) |
| `ssrf` | OOB callback → **Critical/High** | Metadata content reflected → **Critical/Low** † |
| `rfi` | OOB callback → **Critical/High** | Inclusion signal reflected → **Critical/Medium** † |
| `xxe` | OOB callback or entity expansion → **Critical/High** | Error disclosure → Medium; status change → Low (severity stays Critical †) |
| `ssti-math-probe` | Benign math evaluated server-side + echo-guard → **Critical/High** | — (execution proof is the gate) |
| `code-inject` | Arithmetic evaluated + baseline-subtracted → **Critical/Medium** † | Single reflected evaluation at Critical — review manually |
| `path-traversal` | `/etc/passwd`/`win.ini` content marker → **High/High** | Marker required; no marker, no finding |
| `open-redirect` | External `Location` observed, never followed → **Medium/High** | Same-site/subdomain echoes excluded (not CWE-601) |
| `crlf` | Canary header appears in response → **Medium/High** | — |
| `host-header` | Nonce reflected in body/`Location` → **High/High** | `Location` redirect = reset-poisoning path |
| `cache-poison` | Clean re-request persists → **High/High** | **Medium/Medium** reflection-only candidate |
| `sqli-error` | Error string, baseline-subtracted → **High/Medium** † | Single string match — second family wanted |
| `ldap` / `xpath` / `ssi` | Error/marker string, baseline-subtracted → **High/Medium** † | Single string match — second family wanted |
| `nosql` | Operator differential; status-change/auth-bypass → **High/High** | Baseline differential otherwise (Medium+) |
| `deserial` (adversarial) | Error disclosure, baseline-subtracted → **Critical/Medium** † | Single error string at Critical — review manually |
| `file-upload` (adversarial) | Polyglot accepted at upload endpoint → **Critical/Medium** † | Heuristic acceptance — confirm exploitability manually |
| `jwt-weak-verification` (adversarial) | alg:none acceptance differential → **High/Medium** | Heuristic reflection — confirm with a forged session |
| `mass-assignment` / `business-logic-tamper` / `prototype-pollution` (adversarial) | Reflection/status differential → **High/Medium** | Heuristic — confirm business impact manually |
| `schematype` / `schemarequired` | Garbage-type/omission differential → **Medium/Medium** | — |
| `schemacontent` | Garbage-type differential → **Low/Medium** | — |
| `bypass-403` | Dissimilar bypass vs denied baseline + root control → **Medium/Medium** | Catch-all fallbacks rejected |
| `race` / `session-fixation` / `password-policy` / `logout` / `exposed-session` / `rate-limit` | Status/length/timing heuristic → **Medium/Low–Medium** | Heuristic tier — confirm impact manually |
| `formula` / `buffer` / `hpp` | Reflection/error differential → **Medium/Low–Medium** | Indicator tier, not proof |

### Exposure and discovery natives

| Engine | Proves (best claim) | Without that proof (cap) |
|---|---|---|
| `dirs` | 200 + differs from soft-404 baseline + root shell + no WAF markers → **High/High** (critical paths; Medium/Low/Info lower tiers) | Suppressed otherwise; 401/403/406 → warnings only, never findings |
| `backup` / `backupplus` | Same gates; source/archive content → **High/Medium** | Suppressed otherwise; intentional binaries downgraded |
| `exposedgit` | `ref:` + `[core]` dual markers → **High/High** | Single marker → Medium |
| `exposedconfig` / `actuator` / `debugpages` / `soap` / `apiconsole` / `saml` | Content marker + control/root difference → **High/Medium or better** (confirmed markers reach High confidence) | WAF block pages vetoed; heapdump uses header-triple vs root |
| `originip` | Title equality **plus** body similarity → **Low/Medium** | Title-only match insufficient |
| `portscan` | TCP connect → **Info/Confirmed** | Sanity probe suppresses liars; CDN caveat on every finding |

### Pipeline converters (not detectors)

| Stage | Rule |
|---|---|
| Nuclei / ZAP converters | Template/alert severities kept **only with captured evidence**; `evidence.unavailable` caps at **Medium/Medium** |
| `dedup` | Same DedupKey merges at max severity/confidence; ≥2-rank severity spans flag `disputed-sources` + needs-review |
| `feeds` (KEV) | Catalog listing appends reference always, but upgrades to Confirmed **only if already High** — a listing corroborates, never manufactures certainty |

## Master Ghost Core (P0)

Undetectable transport via `--ghost`:
- **Ghost Transport** (`http/ghost.go`): utls (Chrome 131 JA3, h2, GREASE) + stable header set in Chrome 131 order (`GhostHeaderOrder`). Note: Go's stdlib serializes h1 headers sorted, so true wire-order control needs an fhttp-style fork (tracked); ghost still removes all scanner-specific header behaviors.
- **Proxy Pool** (`http/proxy_pool.go`): RoundRobin per-request rotation with healthcheck, SOCKS5 via `x/net/proxy` (fixes `client.go:644` leak)
- **Jitter** (`http/jitter.go`): Pareto 800-3500ms lognormal (replaces uniform 50-250ms in `client.go:590`)
- **Canary suppression** (`active/canary.go`): `ghostPrefix` (default `anpu` → `""` when `--ghost`, no `anpu-` substring), `XSSCanary`/`CacheCanary`/`HostCanary`/`RedirectCanaryDomain`/`XXECanary`/`OOBNoncePrefix`/`CmdCanary`/`CRLFCanaryHeader`/`SSICanary`/`RFICanaryPath`/`HPPPollutedValue`/`XXEEntity`/`Log4ShellNonce`/`DeserialPayload`/`UploadMarker`/`SessionFixationCanary` all ghost-aware (verified by `TestGhostCanariesContainNoAnpu`)
- **Pipeline sharding** (`scanner/pipeline.go:99`): `GhostWorkers` (default 4) shards endpoints across workers; `ArtifactPool.Add` thread-safe (`interface.go:136`); recon publishes endpoint URLs to the pool (Vault entries only ever hold real harvested values, never placeholders)

## Master Coverage (P1)

New injection families (Benign/LowImpact, RequestBudget 3, non-adversarial):
| Rule | ID | CWE | Payload | Signal |
|---|---|---|---|---|
| LDAP | `ldap-injection` | CWE-90 | `*)(uid=*))(|(uid=*` | LDAP error/reflection |
| XPath | `xpath-injection` | CWE-643 | `' or '1'='1` | XPath syntax error |
| SSI | `ssi-injection` | CWE-97 | `<!--#exec cmd="echo" -->` | SSI directive reflection |
| HPP | `hpp-injection` | CWE-235 | `?id=1&id=2` | duplicate param body diff |
| RFI | `rfi-indicator` | CWE-98 | `http://evil.invalid/canary` | inclusion signal / OOB |
| Code Injection | `code-injection` | CWE-94 | `1337*1337` | arithmetic eval |
| Buffer | `buffer-overflow-indicator` | CWE-120 | `A*10000` | 5xx / truncation |
| Formula | `formula-injection` | CWE-1236 | `=cmd|' /C calc'!A0` | verbatim reflection |

Auth/Session (adversarial-gated, RequestBudget 2–3):
- `session-fixation` (CWE-384): pre-set JSESSIONID/PHPSESSID reuse
- `exposed-session-id` (CWE-598): `;jsessionid=` / `PHPSESSID` in URLs
- `logout-invalidation` (CWE-613): session cookie not cleared on logout
- `password-policy-weak` (CWE-521): trivial passwords accepted

Rate-limit (API4):
- `api-rate-limit-missing` (CWE-770): 10 rapid GETs, no 429/X-RateLimit

IDOR/BOLA (Q5 resolved: advanced default, safe stays clean):
- `idor-tester` (authz/idor.go, `modules.IDOR`, toggle `idor`): numeric `id|user_id|order_id` id+1 replay under contextB, RequestBudget 5, same-URL diff `authz/scanner.go:40`. On for advanced/ultra (read-only GETs, like Active), off for safe.

## Adversarial (authorized ultra)

Hazardous probes are gated behind `--adversarial --confirm-authorized` on authorized ultra targets only (Benign/LowImpact only, no `SafetyDestructive`, no data destruction). They reuse the stateful session (`ScanContext.Session{Jar,Vault,Extractors}` + `ArtifactPool`, `client.DoWithSession` via `anpuhttp` with `Jar` cookie replay, `pipeline.go:124-126` propagate) and vector upgrade (`VectorHeader` enabled, `max 6→20`, `VectorWebSocket` via `jsintel.go` `wss?://`).

* **Stateful multi-step:** login → CSRF → IDOR/mass-assign chaining via shared `Vault` (real harvested values only) and `Extractors` plus the `ArtifactPool` endpoint feed published after Recon.
* **Header/body/WS:** `apiVectorsFor` now emits `VectorHeader` (Host/Origin/Referrer) + `VectorWebSocket` (`ws://`/`wss://` same-host from JS intel) + `VectorJSONBody` (already) — tested by `ExtractWebSocketVectors` and `route.Sample`.
* **Time+OOB & soft-404:** `soft404.go` mirrors `dirs.go:122,176` baselineA/B + root + `similarity 0.85`, `route/classifier.go` `3–5 samples when count>10` (4 default, 3 if ≤7, 5 if >20), gate `active/scanner.go:50-115` `status!=200||CT!~html/json||soft404>0.85 skip` fail-open.
* **IDOR/mass-assign/JWT/race/smuggling/proto-pollute:** 6 rules `jwt-weak-verification` (alg:none), `mass-assignment` (auto-binding), `business-logic-tamper`, `race-condition` (2 concurrent `GET` via `anpuhttp` budget 8), `http-smuggling` (CL.TE/TE.CL via `DoWithHeaders` budget 5, `CWE-444`), `prototype-pollution` (`__proto__`) + existing `sqli-boolean-differential` hardened (`StatusCode/Len/CT` triple, `200×3 same CT` else `single-technique` tag+snippets+random control, keep High) — all `SafetyLowImpact` `RequestBudget 5–8` via `anpuhttp`, budget respected via `RequestsMade`.
* **GraphQL alias flood:** `graphql_abuse.go` `CheckGraphQLAliasFlood` 100 aliases `a0…a99` `postGraphQLBody` via `anpuhttp` counted toward API `10s×3` budget (max 4 when introspect OK) — `CWE-770` `Low` DoS.
* **Evidence bundles:** `EvidenceBundle{Curl,RequestMethod/URL,ResponseStatus,ResponseSnippets,NeedsReview,Technique,Snippets}` `omitempty` (fixture `anpu scan --only headers` byte-identical), dedup `Param|CWE` key + `canonicalize query` (`?b=2&a=1→a=1&b=2`) `finding.go:222` + `dedup.go:21-58`, HTML `curl` + bundle + FP disclaimer `reporting/html.go:162-191` (`single-technique High kept High but tagged needs review, 200×3 same CT + random control + bundle required for fully earned High/High`). `Grade F 9.0` via `max+volumeBonus 1.5 cap10` (`scoring.go:106`).

Run: `anpu scan https://authorized.example.com --profile ultra --adversarial --confirm-authorized --oob-interactsh`

## Safety boundary

All active HTTP requests use ANPU's shared client and target-validation path. The scanner is designed to reject loopback/private/local destinations unless the application is explicitly run with the local-network testing override used by controlled fixtures.

These guardrails reduce accidental harm; they do not grant authorization. Only scan systems you own or are explicitly authorized to test.
