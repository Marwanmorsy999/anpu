# Comparison with other tools

ANPU is a single-binary, multi-stage web security scanner. It overlaps
with several well-established tools but is not a replacement for any of
them. This page states what each tool does that ANPU does not, and where
ANPU's claims are backed by measurement.

## Subdomain enumeration — subfinder / amass

| | subfinder / amass | ANPU |
|---|---|---|
| What it covers | Passive + active subdomain enumeration across dozens of sources | Passive indexes (CT logs, Common Crawl, urlscan, CertSpotter, hackertarget, Anubis-DB) plus a small built-in DNS brute list on ultra profile ([internal/subdomains](../internal/subdomains)) |
| Detection method | Aggregation of many third-party sources | Same passive sources; fewer sources |
| What ANPU does NOT do | — | Does not run amass-style recursive permutation at scale; does not brute-force large wordlists by default |

Reference: [internal/subdomains/subdomains.go](../internal/subdomains/subdomains.go).

## HTTP probing — httpx

| | httpx | ANPU |
|---|---|---|
| What it covers | Fast HTTP probing: status, title, tech fingerprint, ports, CDN detection | HTTP probing is an internal step inside stages (headers, cookies, technology, TLS); not a standalone prober |
| Detection method | Concurrent HTTP requests with rich output | Same transport, narrower scope |
| What ANPU does NOT do | — | Does not emit a standalone probe list or support mass port scanning; use httpx for that |

Reference: [internal/http/client.go](../internal/http/client.go).

## Template-based vulnerability scanning — nuclei

| | nuclei | ANPU |
|---|---|---|
| What it covers | Thousands of community templates for CVEs, misconfigs, exposures | A subset of exposure checks implemented natively in Go; optional nuclei integration in ultra profile ([internal/integrations](../internal/integrations)) |
| Detection method | Template matching against responses | Native analyzers + optional nuclei invocation |
| What ANPU does NOT do | — | Does not ship or maintain a template ecosystem; when nuclei is absent, ANPU degrades to its embedded fallback with a warning |

Reference: [docs/scanners.md](scanners.md), [internal/integrations](../internal/integrations).

## Subdomain takeover — subzy / tko-subs

| | subzy / tko-subs | ANPU |
|---|---|---|
| What it covers | Targeted takeover fingerprinting per provider | Takeover checks as part of the exposure pack ([internal/takeover](../internal/takeover)) |
| Detection method | Provider-specific CNAME/response fingerprints | Same class of fingerprinting, narrower provider set |
| What ANPU does NOT do | — | Does not cover every provider subzy does; verify with a dedicated takeover tool for high-stakes assets |

Reference: [internal/takeover](../internal/takeover).

## What ANPU measures

Every claim about detection coverage is backed by the honesty benchmark:
[docs/benchmark.md](benchmark.md) (planted-signal fixture, verdicts, misses).
ANPU reports its own misses; see the MISS rows in that table. No superiority
claim is made that the bench cannot reproduce.