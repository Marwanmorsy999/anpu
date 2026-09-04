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
	findings = append(findings, checkCSP(resp, sc.Target.Raw)...)
	findings = append(findings, checkCSPReportOnly(resp, sc.Target.Raw)...)
	findings = append(findings, checkCOOP(resp, sc.Target.Raw)...)
	findings = append(findings, checkHSTS(resp, sc.Target.Raw, isHTTPS)...)
	findings = append(findings, checkXCTO(resp, sc.Target.Raw)...)
	findings = append(findings, checkReferrerPolicy(resp, sc.Target.Raw)...)
	findings = append(findings, checkPermissionsPolicy(resp, sc.Target.Raw)...)
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
	return []models.Finding{finding(
		"headers-missing-csp",
		"Content-Security-Policy header not set",
		"The response does not include a Content-Security-Policy header. CSP is a defense-in-depth control that restricts which sources of scripts, styles, and other resources a browser is allowed to load, mitigating the impact of cross-site scripting (XSS).",
		models.SeverityLow,
		models.ConfidenceMedium,
		target, resp.FinalURL,
		headerEvidence(resp.Header, "Content-Security-Policy"),
		"Without CSP, a successful injection vulnerability elsewhere on the site (e.g. reflected/stored XSS) has a larger blast radius, since the browser has no additional restriction on injected script execution.",
		"Define a Content-Security-Policy appropriate to the application (start with a report-only policy to avoid breaking functionality, then enforce). At minimum restrict script-src and object-src.",
		"CWE-693",
		[]string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"},
	)}
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
	if v == "nosniff" {
		return nil
	}
	sev := models.SeverityLow
	desc := "The response does not include X-Content-Type-Options: nosniff. Without it, some browsers may try to guess (\"sniff\") the content type of a response rather than trusting the declared Content-Type, which has historically enabled certain content-type confusion attacks."
	if v != "" {
		desc = fmt.Sprintf("The response includes X-Content-Type-Options but with an unexpected value (%q) rather than \"nosniff\".", v)
	}
	return []models.Finding{finding(
		"headers-missing-xcto",
		"X-Content-Type-Options not set to nosniff",
		desc,
		sev,
		models.ConfidenceMedium,
		target, resp.FinalURL,
		headerEvidence(resp.Header, "X-Content-Type-Options"),
		"Increases exposure to MIME-sniffing based attacks in older/less strict browsers, particularly if the site ever serves user-controlled content.",
		"Set the header `X-Content-Type-Options: nosniff` on all responses.",
		"CWE-116",
		[]string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"},
	)}
}

func checkReferrerPolicy(resp *anpuhttp.Response, target string) []models.Finding {
	v := resp.Header.Get("Referrer-Policy")
	if v != "" {
		return nil
	}
	return []models.Finding{finding(
		"headers-missing-referrer-policy",
		"Referrer-Policy header not set",
		"The response does not set Referrer-Policy. Without it, browsers fall back to default behavior that may leak the full referring URL (including any sensitive query parameters) to third-party destinations when users click outbound links.",
		models.SeverityInfo,
		models.ConfidenceMedium,
		target, resp.FinalURL,
		headerEvidence(resp.Header, "Referrer-Policy"),
		"Potential leakage of sensitive URL parameters (tokens, IDs) to third parties via the Referer header on outbound navigation.",
		"Set Referrer-Policy to a conservative value such as strict-origin-when-cross-origin or no-referrer, particularly on pages that may include sensitive data in the URL.",
		"CWE-200",
		[]string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"},
	)}
}

func checkPermissionsPolicy(resp *anpuhttp.Response, target string) []models.Finding {
	v := resp.Header.Get("Permissions-Policy")
	if v != "" {
		return nil
	}
	return []models.Finding{finding(
		"headers-missing-permissions-policy",
		"Permissions-Policy header not set",
		"The response does not set Permissions-Policy. This header lets a site explicitly disable browser features/APIs (camera, microphone, geolocation, etc.) it doesn't use, reducing the impact of any injected script that might try to abuse them.",
		models.SeverityInfo,
		models.ConfidenceLow,
		target, resp.FinalURL,
		headerEvidence(resp.Header, "Permissions-Policy"),
		"Low direct impact on its own; mainly relevant as defense-in-depth alongside CSP.",
		"Set Permissions-Policy to disable browser features the application does not use.",
		"",
		[]string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"},
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

// checkCOOP detects a missing or weak Cross-Origin-Opener-Policy header (issue #3).
// COOP isolates a browsing context group so cross-origin documents cannot get a
// reference to the window object, mitigating XS-Leaks and Spectre-class attacks
// that require cross-origin window access.
func checkCOOP(resp *anpuhttp.Response, target string) []models.Finding {
	v := strings.TrimSpace(resp.Header.Get("Cross-Origin-Opener-Policy"))
	lower := strings.ToLower(v)

	// "same-origin" and "same-origin-allow-popups" both provide meaningful isolation.
	if lower == "same-origin" || lower == "same-origin-allow-popups" {
		return nil
	}

	if v == "" {
		// Header is absent — browsers default to unsafe-none.
		return []models.Finding{finding(
			"headers-missing-coop",
			"Cross-Origin-Opener-Policy header not set",
			"The response does not include a Cross-Origin-Opener-Policy (COOP) header. "+
				"Without COOP, cross-origin pages opened by this page can obtain a reference to its window object, "+
				"enabling XS-Leak attacks and weakening process isolation that protects against Spectre-class side-channel attacks.",
			models.SeverityLow,
			models.ConfidenceMedium,
			target, resp.FinalURL,
			headerEvidence(resp.Header, "Cross-Origin-Opener-Policy"),
			"Cross-origin pages may be able to probe timing or state information from this origin's window object, leaking sensitive data.",
			"Add 'Cross-Origin-Opener-Policy: same-origin' to responses. "+
				"If your application opens cross-origin popups that need a window reference, use 'same-origin-allow-popups' instead.",
			"CWE-346",
			[]string{
				"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
				"https://web.dev/why-coop-coep/",
			},
		)}
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
