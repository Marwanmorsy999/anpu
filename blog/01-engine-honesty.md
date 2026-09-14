<!-- DRAFT for human publishing. Suggested title below; verify the
matrix quotes against docs/scanners.md ("Engine capability matrix")
before posting, as rule IDs and caps evolve. -->

# Engine honesty: why most scanners lie to you

Most vulnerability scanners have a quiet incentive problem: a scan that
reports nothing looks broken, so borderline signals get promoted into
findings. Reflected input becomes "XSS". An error string becomes "SQL
injection". Nobody can tell from the report how much was proven and how
much was guessed — and the guess is billed at the same severity as the
proof.

ANPU is built on the opposite rule: **a claim without proof is capped,
and some claims without proof are not findings at all.**

## Proven vs capped, in a public table

Every active check in ANPU documents two columns ([engine capability
matrix](https://github.com/Marwanmorsy999/anpu/blob/main/docs/scanners.md#engine-capability-matrix-what-each-check-can-and-cannot-prove)):
what it can *prove* at best, and what it emits *without that proof*.

A few rows, quoted verbatim:

- **SSTI math probe**: benign math evaluated server-side → Critical.
  Without execution proof? *No finding at all.* Not a low. Nothing.
- **Path traversal**: `/etc/passwd` content marker → High. No marker,
  no finding.
- **Reflected XSS**: tag reflected unescaped in executable context,
  baseline and random control clean → High/Medium. Comment context or a
  missing control? Medium/Medium plus a needs-review flag.
- **Command injection**: shell-error strings alone never exceed Medium —
  and can never reach Critical, by construction.
- **HTTP smuggling**: length differentials *cannot* confirm a desync,
  so there is deliberately no upgrade path. Medium/Low with review,
  forever.

The pattern: the engine states its price of certainty up front, in the
repo, where anyone can audit it.

## The corroboration contract

The general rule behind the table: High confidence requires a
baseline, a random control, and a second independent signal. A single
technique — one payload family, one error string, one reflection —
stays Medium or lower and carries a `needs-review` flag with the reason
(`single-technique`, `disputed-sources`). Findings that disagree across
engines keep the highest severity (never silently downgrade a real
issue) but are flagged as disputed.

## Even the gaps are listed

Rows marked † in the matrix exceed the contract today
(single-evidence signals sitting at High-or-worse). They are not hidden
and not defended — they are listed as scheduled hardening candidates.
A scanner that tells you exactly where its own calibration is weak is
more useful than one that pretends every row is equally proven.

## The point

Scanner output is an input to human judgment. Judgment needs to know
which findings are proof and which are leads. ANPU's entire reporting
model — evidence blocks, score explanations, capped confidences,
published miss rates — exists to preserve that distinction instead of
flattening it into a scarier-looking PDF.

Try it against something you own: `anpu scan https://staging.example.com`.
Read the evidence field of every High before you believe it — that is
what it is for.
