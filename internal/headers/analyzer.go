// Package headers analyzes HTTP response headers for the presence and
// quality of common security headers (CSP, HSTS, X-Content-Type-Options,
// Referrer-Policy, Permissions-Policy) and for server/technology
// disclosure via headers like Server and X-Powered-By.
//
// Missing headers are not automatically treated as high-severity
// vulnerabilities: severity and confidence are assigned based on
// context (e.g. missing HSTS on an HTTPS site is more meaningful than
// on a plain HTTP redirect target).
package headers

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// Analyzer implements scanner.Scanner for security header inspection.
type Analyzer struct {
	client *anpuhttp.Client
}

func New(client *anpuhttp.Client) *Analyzer { return &Analyzer{client: client} }

func (a *Analyzer) Name() string { return "headers" }

func (a *Analyzer) Available(ctx context.Context) bool { return true }

func (a *Analyzer) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	resp, err := a.client.Get(ctx, sc.Target.Raw)
	if err != nil {
		return scanner.StageResult{}, fmt.Errorf("fetching target for header analysis: %w", err)
	}

	isHTTPS := strings.HasPrefix(strings.ToLower(resp.FinalURL), "https://")

	var findings []models.Finding
	if posture := checkPosture(resp, sc.Target.Raw); posture != nil {
		findings = append(findings, *posture)
	}
	// Quality checks below only fire on present-but-weak headers; absence
	// is owned by the single posture finding above.
	findings = append(findings, checkCSP(resp, sc.Target.Raw)...)
	findings = append(findings, checkCSPReportOnly(resp, sc.Target.Raw)...)
	findings = append(findings, checkCOOP(resp, sc.Target.Raw)...)
	findings = append(findings, checkHSTS(resp, sc.Target.Raw, isHTTPS)...)
	findings = append(findings, checkXCTO(resp, sc.Target.Raw)...)
	findings = append(findings, checkServerDisclosure(resp, sc.Target.Raw)...)

	return scanner.StageResult{Findings: findings}, nil
}

func headerEvidence(h http.Header, name string) models.Evidence {
	v := h.Get(name)
	if v == "" {
		return models.Evidence{
			Observed: fmt.Sprintf("%s: <absent>", name),
			Location: "HTTP response headers",
		}
	}
	return models.Evidence{
		Observed: fmt.Sprintf("%s: %s", name, v),
		Location: "HTTP response headers",
	}
}

func finding(id, title, desc string, sev models.Severity, conf models.Confidence,
	target, url string, ev models.Evidence, impact, remediation, cwe string, refs []string) models.Finding {
	return models.Finding{
		ID:              id,
		Title:           title,
		Description:     desc,
		Severity:        sev,
		Confidence:      conf,
		Category:        models.CategoryHeaders,
		CWE:             cwe,
		Target:          target,
		URL:             url,
		Evidence:        ev,
		Source:          models.SourceHeaders,
		DetectionMethod: "passive HTTP response header inspection",
		Impact:          impact,
		Remediation:     remediation,
		References:      refs,
	}
}

func checkCSP(resp *anpuhttp.Response, target string) []models.Finding {
	v := resp.Header.Get("Content-Security-Policy")
	if v != "" {
		// Header is present — analyze quality.
		return checkCSPQuality(v, target, resp.FinalURL, resp.Header)
	}
	// Absent: owned by the posture finding.
	return nil
}

func checkHSTS(resp *anpuhttp.Response, target string, isHTTPS bool) []models.Finding {
	v := resp.Header.Get("Strict-Transport-Security")
	if v != "" {
		// Header is present — analyze quality.
		return checkHSTSQuality(v, target, resp.FinalURL)
	}
	if !isHTTPS {
		return []models.Finding{finding(
			"headers-missing-hsts-http",
			"Strict-Transport-Security not applicable (site served over HTTP)",
			"The response was served over plain HTTP, so Strict-Transport-Security has no effect. This is noted for completeness; see TLS findings for whether HTTPS is available at all.",
			models.SeverityInfo,
			models.ConfidenceHigh,
			target, resp.FinalURL,
			headerEvidence(resp.Header, "Strict-Transport-Security"),
			"", "Serve the site over HTTPS and set Strict-Transport-Security once HTTPS is available.",
			"", nil,
		)}
	}
	return []models.Finding{finding(
		"headers-missing-hsts",
		"Strict-Transport-Security header not set",
		"The HTTPS response does not include Strict-Transport-Security (HSTS). Without HSTS, browsers may still attempt an initial plain-HTTP connection, which can be intercepted (SSL stripping) before any redirect to HTTPS occurs.",
		models.SeverityMedium,
		models.ConfidenceMedium,
		target, resp.FinalURL,
		headerEvidence(resp.Header, "Strict-Transport-Security"),
		"An attacker positioned on the network path (e.g. on public WiFi) may be able to intercept or downgrade the initial connection before HSTS would otherwise force HTTPS.",
		"Add Strict-Transport-Security with a meaningful max-age (e.g. 15552000 or higher) once the site reliably serves HTTPS on all subdomains that need it. Consider includeSubDomains and preload only after verifying all subdomains support HTTPS.",
		"CWE-319",
		[]string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"},
	)}
}

func checkXCTO(resp *anpuhttp.Response, target string) []models.Finding {
	v := strings.ToLower(strings.TrimSpace(resp.Header.Get("X-Content-Type-Options")))
	if v == "nosniff" || v == "" {
		// Present-and-good, or absent (owned by the posture finding).
		return nil
	}
	desc := fmt.Sprintf("The response includes X-Content-Type-Options but with an unexpected value (%q) rather than \"nosniff\".", v)
	return []models.Finding{finding(
		"headers-missing-xcto",
		"X-Content-Type-Options not set to nosniff",
		desc,
		models.SeverityLow,
		models.ConfidenceMedium,
		target, resp.FinalURL,
		headerEvidence(resp.Header, "X-Content-Type-Options"),
		"Increases exposure to MIME-sniffing based attacks in older/less strict browsers, particularly if the site ever serves user-controlled content.",
		"Set the header `X-Content-Type-Options: nosniff` on all responses.",
		"CWE-116",
		[]string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"},
	)}
}

func checkServerDisclosure(resp *anpuhttp.Response, target string) []models.Finding {
	var out []models.Finding
	if v := resp.Header.Get("Server"); v != "" && looksLikeVersionDisclosure(v) {
		out = append(out, finding(
			"headers-server-disclosure",
			"Server header discloses version information",
			"The Server header includes what appears to be specific version information, which can help an attacker identify known vulnerabilities affecting that exact version.",
			models.SeverityInfo,
			models.ConfidenceMedium,
			target, resp.FinalURL,
			headerEvidence(resp.Header, "Server"),
			"Version disclosure narrows the search space for an attacker looking for known CVEs affecting the disclosed software version.",
			"Configure the web server/reverse proxy to omit or generalize the Server header (e.g. `Server: nginx` instead of `Server: nginx/1.18.0 (Ubuntu)`).",
			"CWE-200",
			[]string{"https://owasp.org/www-project-web-security-testing-guide/"},
		))
	}
	if v := resp.Header.Get("X-Powered-By"); v != "" {
		out = append(out, finding(
			"headers-x-powered-by-disclosure",
			"X-Powered-By header discloses backend technology",
			"The X-Powered-By header discloses backend framework/technology information that is not needed by clients.",
			models.SeverityInfo,
			models.ConfidenceHigh,
			target, resp.FinalURL,
			headerEvidence(resp.Header, "X-Powered-By"),
			"Assists attacker reconnaissance by narrowing down the technology stack in use.",
			"Disable or strip the X-Powered-By header at the framework/server level.",
			"CWE-200",
			nil,
		))
	}
	return out
}

func looksLikeVersionDisclosure(v string) bool {
	digits := 0
	dots := 0
	for _, r := range v {
		if r >= '0' && r <= '9' {
			digits++
		}
		if r == '.' {
			dots++
		}
	}
	return digits >= 2 && dots >= 1
}

// checkCSPReportOnly detects the case where Content-Security-Policy-Report-Only
// is present but no enforced Content-Security-Policy header exists (issue #5).
// Report-Only mode logs violations but does not block anything — it provides
// zero runtime protection on its own.
func checkCSPReportOnly(resp *anpuhttp.Response, target string) []models.Finding {
	enforced := resp.Header.Get("Content-Security-Policy")
	reportOnly := resp.Header.Get("Content-Security-Policy-Report-Only")
	if reportOnly == "" || enforced != "" {
		// Either no report-only header, or an enforced policy is also present — fine.
		return nil
	}
	return []models.Finding{finding(
		"headers-csp-report-only-only",
		"Content-Security-Policy is in report-only mode with no enforced policy",
		"The response includes a Content-Security-Policy-Report-Only header but no enforced Content-Security-Policy. "+
			"Report-Only mode collects violation reports but does not block any content — it offers no runtime protection against XSS or data injection.",
		models.SeverityMedium,
		models.ConfidenceHigh,
		target, resp.FinalURL,
		models.Evidence{
			Observed: fmt.Sprintf(
				"Content-Security-Policy-Report-Only: %s\nContent-Security-Policy: <absent>",
				reportOnly,
			),
			Location: "HTTP response headers",
		},
		"Attackers can still inject and execute arbitrary scripts — the Report-Only policy will log the violations but will not prevent them.",
		"Promote the report-only policy to an enforced Content-Security-Policy once you have confirmed it does not break legitimate functionality. "+
			"Keep the Report-Only header in parallel during the transition to catch regressions.",
		"CWE-693",
		[]string{
			"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only",
			"https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
		},
	)}
}

// postureRow is one line of the security-headers posture checklist.
type postureRow struct {
	header string // display name
	absent bool
	sev    models.Severity
	why    string // one-line reason the header matters
}

// checkPosture collapses all absent-header presence checks into a single
// finding with a per-header checklist, instead of one row per header.
// Present-but-weak headers still get their own quality findings above.
func checkPosture(resp *anpuhttp.Response, target string) *models.Finding {
	h := resp.Header
	rows := []postureRow{
		{"Content-Security-Policy", h.Get("Content-Security-Policy") == "", models.SeverityLow, "no CSP — XSS blast radius is larger"},
		{"Cross-Origin-Opener-Policy", strings.TrimSpace(h.Get("Cross-Origin-Opener-Policy")) == "", models.SeverityLow, "no COOP — cross-origin window references allowed"},
		{"Cross-Origin-Embedder-Policy", strings.TrimSpace(h.Get("Cross-Origin-Embedder-Policy")) == "", models.SeverityInfo, "no COEP — weaker Spectre-class isolation"},
		{"Cross-Origin-Resource-Policy", strings.TrimSpace(h.Get("Cross-Origin-Resource-Policy")) == "", models.SeverityInfo, "no CORP — resources embeddable cross-origin"},
		{"X-Content-Type-Options", strings.ToLower(strings.TrimSpace(h.Get("X-Content-Type-Options"))) != "nosniff", models.SeverityLow, "no nosniff — MIME-sniffing confusion possible"},
		{"Permissions-Policy", h.Get("Permissions-Policy") == "", models.SeverityInfo, "unused browser features left enabled"},
		{"Referrer-Policy", h.Get("Referrer-Policy") == "", models.SeverityInfo, "referrer defaults may leak URLs to third parties"},
		{"Framing (X-Frame-Options / frame-ancestors)", !framingProtected(h.Get("X-Frame-Options"), h.Get("Content-Security-Policy")), models.SeverityLow, "page can be framed — clickjacking"},
	}
	absent := 0
	sev := models.SeverityInfo
	var lines, observed []string
	for _, r := range rows {
		mark := "present"
		if r.absent {
			absent++
			mark = "absent"
			if r.sev.Rank() > sev.Rank() {
				sev = r.sev
			}
		}
		lines = append(lines, fmt.Sprintf("  [%s] %s (%s) — %s", mark, r.header, r.sev, r.why))
		observed = append(observed, fmt.Sprintf("%s: %s", r.header, mark))
	}
	if absent == 0 {
		return nil
	}
	desc := fmt.Sprintf("Security headers posture: %d of %d recommended headers absent on %s.\n\n%s\n\nTighten headers incrementally: CSP (report-only first, then enforce), framing (frame-ancestors 'self'), nosniff, then the isolation trio (COOP/COEP/CORP).",
		absent, len(rows), resp.FinalURL, strings.Join(lines, "\n"))
	f := finding(
		"headers-posture",
		fmt.Sprintf("Security headers posture — %d of %d recommended headers absent", absent, len(rows)),
		desc,
		sev,
		models.ConfidenceMedium,
		target, resp.FinalURL,
		models.Evidence{Observed: strings.Join(observed, "; "), Location: "HTTP response headers"},
		"Each absent header removes one layer of browser-enforced defense; a single injection flaw elsewhere has a larger blast radius.",
		"Work through the checklist above in order; every row names its header and fix.",
		"CWE-693",
		[]string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"},
	)
	return &f
}

// framingProtected reports whether X-Frame-Options or CSP frame-ancestors
// blocks arbitrary framing (mirrors the clickjack stage verdict for the
// target page so the posture checklist stays consistent with it).
func framingProtected(xfo, csp string) bool {
	for _, dir := range strings.Split(strings.ToLower(csp), ";") {
		if strings.HasPrefix(strings.TrimSpace(dir), "frame-ancestors") {
			return true
		}
	}
	switch strings.ToUpper(strings.TrimSpace(xfo)) {
	case "DENY", "SAMEORIGIN":
		return true
	}
	return false
}

// checkCOOP detects a weak Cross-Origin-Opener-Policy header (issue #3).
// Absence is owned by the posture finding; only explicit unsafe-none
// earns its own row. COOP isolates a browsing context group so
// cross-origin documents cannot get a reference to the window object.
func checkCOOP(resp *anpuhttp.Response, target string) []models.Finding {
	v := strings.TrimSpace(resp.Header.Get("Cross-Origin-Opener-Policy"))
	lower := strings.ToLower(v)

	// "same-origin" and "same-origin-allow-popups" both provide meaningful isolation.
	if lower == "same-origin" || lower == "same-origin-allow-popups" {
		return nil
	}

	if v == "" {
		// Header is absent — owned by the posture finding.
		return nil
	}

	// Header is present but set to "unsafe-none" — explicitly disabled.
	if lower == "unsafe-none" {
		return []models.Finding{finding(
			"headers-coop-unsafe-none",
			"Cross-Origin-Opener-Policy is set to unsafe-none (isolation disabled)",
			"The response sets Cross-Origin-Opener-Policy: unsafe-none, which explicitly opts out of cross-origin isolation. "+
				"This is equivalent to not setting the header and provides no protection against XS-Leak or Spectre-class attacks.",
			models.SeverityLow,
			models.ConfidenceMedium,
			target, resp.FinalURL,
			headerEvidence(resp.Header, "Cross-Origin-Opener-Policy"),
			"Cross-origin pages may be able to probe timing or state information from this origin's window object.",
			"Change to 'Cross-Origin-Opener-Policy: same-origin' unless cross-origin popup window access is required by the application.",
			"CWE-346",
			[]string{
				"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
			},
		)}
	}

	return nil
}
