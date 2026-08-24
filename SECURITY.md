# Security Policy

## Responsible use of ANPU

ANPU is an authorized web security analysis tool. It performs active
network requests against the target you point it at.

**Only scan targets you own or are explicitly authorized to test.**
Unauthorized scanning of systems you do not control or have written
permission to test may be illegal in your jurisdiction (e.g. under
computer misuse / fraud statutes) even when using the `safe` profile.

ANPU's built-in guardrails (see below) reduce the risk of *accidental*
harm, but they are not a substitute for authorization. ANPU cannot
verify that you are authorized to test a given target — that is your
responsibility.

## Built-in safety boundaries

- **Local-network protection**: by default, ANPU refuses to scan targets
  that resolve to loopback, private, or link-local addresses (including
  cloud metadata endpoints like `169.254.169.254`), to prevent a scan
  from accidentally targeting your own infrastructure. This also applies
  to redirects: ANPU will not follow a redirect that leads into a
  private address range.
- **Passive-by-default**: the `safe` profile (the default) sticks to
  passive/low-impact analysis — HTTP header inspection, TLS handshake
  inspection, robots.txt/sitemap.xml fetches, and link/form extraction.
  It does not run Nuclei's active template checks unless you opt into
  `standard` or `deep`, or explicitly enable `nuclei: true` in config.
- **No destructive actions**: ANPU never attempts to submit forms,
  brute-force credentials, exploit a suspected vulnerability, or bypass
  authentication.
- **No shell execution of target-controlled data**: content returned by
  a target (headers, HTML, JS) is only ever parsed as data. It is never
  passed to a shell or interpreted as a command.
- **Timeouts and concurrency limits**: every request is bounded by a
  timeout, and redirect chains are capped, to avoid hanging or
  overwhelming a target.
- **No fabricated evidence**: findings without concrete observed
  evidence are explicitly marked "Evidence unavailable" rather than
  showing invented detail.

## Reporting a vulnerability in ANPU itself

If you find a security issue in ANPU's own code (e.g. something that
would let a malicious *target* compromise the machine running ANPU),
please report it privately rather than opening a public issue:

- Open a private security advisory on GitHub
  (`Security` tab → `Report a vulnerability`) on this repository, or
- Email the maintainers listed in `CONTRIBUTING.md`.

Please include:
- A description of the issue and its potential impact
- Steps to reproduce (a minimal mock HTTP server is ideal — do not
  demonstrate the issue against a real third-party site)
- Any suggested fix, if you have one

We aim to acknowledge reports within a few days. Please give us a
reasonable amount of time to fix an issue before public disclosure.
