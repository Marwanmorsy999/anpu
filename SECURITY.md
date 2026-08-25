# Security Policy

## Responsible use of ANPU

ANPU is an authorized web security analysis tool. It performs active network requests against the target you point it at.

**Only scan targets you own or are explicitly authorized to test.** Unauthorized scanning of systems you do not control or have written permission to test may be illegal in your jurisdiction, even when using the `safe` profile.

ANPU's built-in guardrails reduce the risk of accidental harm, but they are not a substitute for authorization. ANPU cannot verify that you are authorized to test a given target — that is your responsibility.

## Built-in safety boundaries

- **Local-network protection**: by default, ANPU refuses to scan targets that resolve to loopback, private, or link-local addresses, including cloud metadata endpoints such as `169.254.169.254`. This also applies to redirects: ANPU will not follow a redirect that leads into a private address range.
- **Passive-by-default**: the `safe` profile (the default) uses low-impact analysis such as HTTP header inspection, TLS inspection, robots.txt/sitemap.xml fetches, and link/form extraction. It does not enable Nuclei active checks unless you opt into a profile or configuration that enables the integration.
- **No destructive actions**: ANPU never attempts to submit forms, brute-force credentials, exploit a suspected vulnerability, or bypass authentication.
- **No shell execution of target-controlled data**: content returned by a target is parsed as data and is never passed to a shell or interpreted as a command.
- **Timeouts and concurrency limits**: requests are bounded and redirect chains are capped to reduce the chance of hanging or overwhelming a target.
- **No fabricated evidence**: findings without concrete observed evidence are explicitly marked as unavailable rather than displaying invented detail.

## Reporting a vulnerability in ANPU itself

If you find a security issue in ANPU's own code — for example, a bug that could let a malicious target compromise the machine running ANPU — please report it privately rather than opening a public issue.

Use GitHub's private security advisory flow:

**Repository → Security → Advisories → Report a vulnerability**

Please include:

- A description of the issue and its potential impact
- Steps to reproduce (a minimal mock HTTP server is ideal; do not demonstrate the issue against a real third-party site)
- Any suggested fix, if available

### Response targets

- Acknowledgement: within 2 business days
- Initial triage: within 5 business days
- Target resolution: within 7 days for critical/high issues and within 30 days for moderate/low issues

These are response targets rather than contractual guarantees. Please give maintainers reasonable time to investigate and fix a vulnerability before public disclosure.
