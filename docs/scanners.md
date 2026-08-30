# Scanner and Engine Reference

ANPU combines built-in analyzers with an optional Nuclei integration. The scanner pipeline normalizes results into the shared finding model, deduplicates overlapping findings, scores them deterministically, and writes reports.

## Engine matrix

| Engine | What it checks | Profile scope | Activity | External dependency |
|---|---|---|---|---|
| Recon | DNS, robots.txt, sitemap.xml, redirects, source maps | All | Passive | No |
| Technology | Server/framework/CMS/CDN/library signals | All | Passive | No |
| TLS | Certificate validity, expiry, hostname, protocols, HTTPS behavior | All | Passive | No |
| Headers | CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, disclosure headers | All | Passive | No |
| Cookies | Secure, HttpOnly, SameSite attributes | All | Passive | No |
| Endpoints / Crawler | Same-origin pages, links, forms, scripts, API/path references | All | Bounded GETs | No |
| Subdomains | Certificate Transparency logs; DNS brute-force in deep | Standard/Deep | Active | No |
| PortScan | TCP connect scan of common service ports | Deep | Active | No |
| Dirs | Sensitive-path probing with soft-404 baseline | Standard/Deep | Active | No |
| Secrets | Supported API-key, token, and private-key patterns in discovered assets | Standard/Deep | Active | No |
| CORS | Wildcard, reflection, and credential behavior | Standard/Deep | Active | No |
| Methods | `OPTIONS`/`Allow` behavior and live TRACE verification | Standard/Deep | Active | No |
| Nuclei | Profile-scoped external vulnerability templates | Standard/Deep when available | Active | Nuclei binary |
| ZAP | Reserved active-scanner interface | Planned | Not implemented | ZAP driver |

Exact module enablement can also be controlled through `anpu.yaml`. See [configuration.md](configuration.md).

## Recon

Recon establishes the initial attack-surface picture. It observes DNS results and web metadata such as `robots.txt`, `sitemap.xml`, redirect chains, and source-map references.

The output is used by later stages rather than being treated as a vulnerability by itself.

## Technology

Technology detection uses observed signals from headers, cookies, HTML, and JavaScript to identify likely servers, frameworks, CMSs, CDNs, and libraries. Version information is only reported when supported by observed evidence.

## TLS

TLS analysis checks certificate validity and expiration, hostname matching, supported protocol versions, and HTTP-to-HTTPS behavior where applicable.

## Headers and cookies

The headers analyzer checks security-related HTTP response headers and server disclosure. The cookie analyzer evaluates `Secure`, `HttpOnly`, and `SameSite` attributes with context-aware findings.

These checks are low-impact because they inspect HTTP behavior rather than attempting exploitation.

## Endpoint discovery and bounded crawling

Endpoint discovery now uses a bounded same-origin crawler. The crawler starts at the target URL, records normalized links/forms/scripts/API references, and follows only same-host HTTP(S) document URLs. Obvious static assets are recorded as endpoints but are not recursively crawled.

The crawl remains bounded by profile:

- `safe`: target page only (`1` page, depth `0`)
- `standard`: up to `25` pages, depth `2`
- `deep`: up to `100` pages, depth `4`

The crawler performs GET requests only; it never submits forms, attempts authentication, or brute-forces paths. All requests go through ANPU's shared HTTP client, preserving redirect and local-network protections.

A page-limit warning is emitted when the configured bound is reached. This makes scan scope visible rather than silently truncating discovery.

## Subdomains

Subdomain discovery uses Certificate Transparency results and profile-gated DNS enumeration. Deep scans add DNS brute-force candidates.

ANPU validates and resolves candidates through its shared network-safety controls before performing active requests.

## Port scanning

The port scanner uses TCP connect probes against a curated set of common service ports. ANPU includes sanity/false-positive safeguards so environments that accept unexpected connections do not blindly turn every port into a finding.

Port scanning is enabled for deep discovery and is not part of the default safe profile.

## Sensitive paths

The directory/path engine probes a controlled set of sensitive paths and establishes a soft-404 baseline. This helps distinguish genuinely exposed resources from applications that return the same generic page for arbitrary paths.

## Secret detection

The secret scanner examines discovered assets for supported credential, token, and private-key patterns. Findings are evidence-backed and samples are redacted before being reported.

The scanner limits per-asset scan size to avoid unbounded regex work on unusually large responses.

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

The ZAP integration is currently an extension point only. The CLI and scanner interface reserve the integration, but the active ZAP driver is not implemented in this MVP.

Do not describe ZAP as an active scanner in release material until its driver is implemented and tested.

## Safety boundary

All active HTTP requests use ANPU's shared client and target-validation path. The scanner is designed to reject loopback/private/local destinations unless the application is explicitly run with the local-network testing override used by controlled fixtures.

These guardrails reduce accidental harm; they do not grant authorization. Only scan systems you own or are explicitly authorized to test.
