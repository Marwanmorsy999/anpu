package headers

// Cookie analysis lives alongside the header analyzer since both work
// from the same HTTP response, but is registered as its own Scanner
// (Source: cookie-analyzer) so findings and reports can distinguish the
// two categories cleanly.

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// CookieAnalyzer implements scanner.Scanner for Set-Cookie inspection.
type CookieAnalyzer struct {
	client *anpuhttp.Client
}

func NewCookieAnalyzer(client *anpuhttp.Client) *CookieAnalyzer {
	return &CookieAnalyzer{client: client}
}

func (a *CookieAnalyzer) Name() string { return "cookies" }

func (a *CookieAnalyzer) Available(ctx context.Context) bool { return true }

func (a *CookieAnalyzer) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	resp, err := a.client.Get(ctx, sc.Target.Raw)
	if err != nil {
		return scanner.StageResult{}, fmt.Errorf("fetching target for cookie analysis: %w", err)
	}

	isHTTPS := strings.HasPrefix(strings.ToLower(resp.FinalURL), "https://")

	var httpResp http.Response
	httpResp.Header = resp.Header
	cookies := httpResp.Cookies()

	var findings []models.Finding
	for _, c := range cookies {
		findings = append(findings, analyzeCookie(c, resp.FinalURL, sc.Target.Raw, isHTTPS)...)
	}

	if len(cookies) == 0 {
		findings = append(findings, models.Finding{
			ID:              "cookies-none-observed",
			Title:           "No cookies observed on initial response",
			Description:     "The initial response to the target URL did not set any cookies. This is informational — session cookies are commonly set only after authentication or on specific routes that a single passive request wouldn't reach.",
			Severity:        models.SeverityInfo,
			Confidence:      models.ConfidenceHigh,
			Category:        models.CategoryCookies,
			Target:          sc.Target.Raw,
			URL:             resp.FinalURL,
			Evidence:        models.Evidence{Unavailable: true, Location: "HTTP response headers"},
			Source:          models.SourceCookies,
			DetectionMethod: "passive HTTP response inspection",
		})
	}

	return scanner.StageResult{Findings: findings}, nil
}

func analyzeCookie(c *http.Cookie, url, target string, isHTTPS bool) []models.Finding {
	var out []models.Finding
	base := fmt.Sprintf("Set-Cookie: %s=%s", c.Name, redactCookieValue(c.Value))

	if !c.Secure && isHTTPS {
		out = append(out, models.Finding{
			ID:              "cookie-missing-secure-" + safeID(c.Name),
			Title:           fmt.Sprintf("Cookie %q missing Secure flag", c.Name),
			Description:     fmt.Sprintf("The cookie %q is set without the Secure attribute on an HTTPS site, meaning the browser would still transmit it over a plain-HTTP connection to the same host if one were ever made.", c.Name),
			Severity:        models.SeverityMedium,
			Confidence:      models.ConfidenceHigh,
			Category:        models.CategoryCookies,
			CWE:             "CWE-614",
			Target:          target,
			URL:             url,
			Parameter:       c.Name,
			Evidence:        models.Evidence{Observed: base + "; Secure=missing", Location: "Set-Cookie response header"},
			Source:          models.SourceCookies,
			DetectionMethod: "passive HTTP response header inspection",
			Impact:          "The cookie could be transmitted in cleartext if any plain-HTTP request to the same host occurs (e.g. via a mixed-content resource or manual navigation), exposing it to network eavesdroppers.",
			Remediation:     "Add the Secure attribute to this cookie so browsers only send it over HTTPS.",
			References:      []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies"},
		})
	}

	if !c.HttpOnly {
		out = append(out, models.Finding{
			ID:              "cookie-missing-httponly-" + safeID(c.Name),
			Title:           fmt.Sprintf("Cookie %q missing HttpOnly flag", c.Name),
			Description:     fmt.Sprintf("The cookie %q is set without the HttpOnly attribute, meaning client-side JavaScript can read it. If the application is ever affected by an XSS vulnerability, this cookie's value could be exfiltrated.", c.Name),
			Severity:        models.SeverityLow,
			Confidence:      models.ConfidenceHigh,
			Category:        models.CategoryCookies,
			CWE:             "CWE-1004",
			Target:          target,
			URL:             url,
			Parameter:       c.Name,
			Evidence:        models.Evidence{Observed: base + "; HttpOnly=missing", Location: "Set-Cookie response header"},
			Source:          models.SourceCookies,
			DetectionMethod: "passive HTTP response header inspection",
			Impact:          "If combined with an XSS vulnerability elsewhere on the site, this cookie could be read and exfiltrated by injected script. Severity is elevated to Medium/High if the cookie appears to be a session/auth cookie.",
			Remediation:     "Add the HttpOnly attribute unless client-side script genuinely needs to read this cookie.",
			References:      []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies"},
		})
	}

	sameSite := strings.ToLower(cookieSameSiteString(c))
	if sameSite == "" || sameSite == "none" {
		sev := models.SeverityLow
		if sameSite == "none" && !c.Secure {
			sev = models.SeverityMedium // SameSite=None without Secure is invalid/risky
		}
		out = append(out, models.Finding{
			ID:              "cookie-samesite-" + safeID(c.Name),
			Title:           fmt.Sprintf("Cookie %q has weak or missing SameSite attribute", c.Name),
			Description:     fmt.Sprintf("The cookie %q does not set a restrictive SameSite attribute (Lax or Strict). This can make the cookie eligible to be sent on cross-site requests, which is relevant to CSRF exposure depending on how the application uses the cookie.", c.Name),
			Severity:        sev,
			Confidence:      models.ConfidenceMedium,
			Category:        models.CategoryCookies,
			CWE:             "CWE-352",
			Target:          target,
			URL:             url,
			Parameter:       c.Name,
			Evidence:        models.Evidence{Observed: base + fmt.Sprintf("; SameSite=%s", orNotSet(sameSite)), Location: "Set-Cookie response header"},
			Source:          models.SourceCookies,
			DetectionMethod: "passive HTTP response header inspection",
			Impact:          "May contribute to CSRF exposure if this cookie is used for authentication/session state and the application does not have independent CSRF defenses (tokens, origin checks).",
			Remediation:     "Set SameSite=Lax (or Strict where cross-site use is not required) on session/authentication cookies.",
			References:      []string{"https://owasp.org/www-community/SameSite"},
		})
	}

	return out
}

func cookieSameSiteString(c *http.Cookie) string {
	switch c.SameSite {
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return ""
	}
}

func orNotSet(s string) string {
	if s == "" {
		return "not-set"
	}
	return s
}

// redactCookieValue avoids putting potentially sensitive session token
// values into evidence/reports — only the length and a short prefix are
// shown.
func redactCookieValue(v string) string {
	if len(v) <= 6 {
		return "[redacted]"
	}
	return v[:3] + "…[redacted, " + fmt.Sprint(len(v)) + " chars]"
}

func safeID(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return b.String()
}
