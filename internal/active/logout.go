package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// logoutRule detects logout/session invalidation failures (CWE-613).
// It attempts to infer whether a session persists after a logout endpoint
// is hit by probing the same session cookie.
//
// Safety: LowImpact — hits logout-like endpoints discovered via recon,
// adversarial-gated, no forced logout of real users (target is scan target only).
type logoutRule struct{}

func (r *logoutRule) ID() models.ActiveRuleID    { return "logout-invalidation" }
func (r *logoutRule) Name() string               { return "Logout Session Invalidation" }
func (r *logoutRule) Safety() models.SafetyLevel { return models.SafetyLowImpact }
func (r *logoutRule) RequestBudget() int         { return 3 }

func looksLikeLogoutURL(raw string) bool {
	lower := strings.ToLower(raw)
	return strings.Contains(lower, "logout") || strings.Contains(lower, "signout") || strings.Contains(lower, "sign-off") || strings.Contains(lower, "logoff")
}

func (r *logoutRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}
	if !IsAdversarialEnabled() {
		return result, nil
	}
	if !looksLikeLogoutURL(v.URL) {
		return result, nil
	}
	// Step 1: establish a session by GETting the logout URL to capture cookies
	resp1, err := client.Get(ctx, v.URL)
	result.RequestsMade++
	if err != nil || resp1 == nil {
		return result, nil
	}
	cookies := resp1.Header.Values("Set-Cookie")
	if len(cookies) == 0 {
		return result, nil // no session to test
	}
	// Extract a session cookie name/value (first)
	sessionCookie := strings.Split(cookies[0], ";")[0]
	if !strings.Contains(strings.ToLower(sessionCookie), "session") && !strings.Contains(strings.ToLower(sessionCookie), "sess") && !strings.Contains(strings.ToLower(sessionCookie), "auth") {
		return result, nil
	}
	// Step 2: hit logout with that cookie (if the endpoint is logout, this should invalidate)
	logoutResp, err := client.DoWithHeaders(ctx, "GET", v.URL, map[string]string{
		"Cookie": sessionCookie,
	})
	result.RequestsMade++
	if err != nil || logoutResp == nil {
		return result, nil
	}
	// Check if Set-Cookie after logout still contains same session ID (not cleared/invalidated)
	afterCookies := logoutResp.Header.Values("Set-Cookie")
	stillValid := false
	for _, c := range afterCookies {
		if strings.Contains(c, strings.Split(sessionCookie, "=")[0]) && !strings.Contains(strings.ToLower(c), "expires=thu, 01 jan 1970") && !strings.Contains(strings.ToLower(c), "max-age=0") {
			stillValid = true
			break
		}
	}
	if len(afterCookies) == 0 {
		stillValid = true // server didn't clear session at all
	}
	// Step 3: try to reuse same session cookie on a protected-like endpoint (same URL)
	reuseResp, err := client.DoWithHeaders(ctx, "GET", v.URL, map[string]string{
		"Cookie": sessionCookie,
	})
	result.RequestsMade++
	if err == nil && reuseResp != nil && stillValid && reuseResp.StatusCode == 200 {
		result.Found = true
		result.Payload = sessionCookie
		result.Evidence = fmt.Sprintf("Logout endpoint %q did not invalidate session %q — same cookie reused successfully (status %d, Set-Cookie after logout: %q)", v.URL, sessionCookie, reuseResp.StatusCode, strings.Join(afterCookies, "; "))
		return result, nil
	}
	return result, nil
}

func (r *logoutRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	return models.Finding{
		ID:              fmt.Sprintf("active-logout-%d", time.Now().UnixNano()),
		Title:           fmt.Sprintf("Session not invalidated on logout at %s", res.Vector.URL),
		Description:     fmt.Sprintf("The logout endpoint at %s did not clear the session cookie %q — the same session could be reused after logout (evidence: %s). This violates secure session lifecycle.", res.Vector.URL, res.Payload, res.Evidence),
		Severity:        models.SeverityMedium,
		Confidence:      models.ConfidenceMedium,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-613",
		OWASP:           "A07:2021 - Identification and Authentication Failures",
		Target:          target,
		URL:             res.Vector.URL,
		Source:          models.SourceActive,
		DetectionMethod: "logout invalidation probe: establish session, hit logout, reuse cookie (adversarial)",
		Evidence:        models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("GET %s with session %s", res.Vector.URL, res.Payload)},
		Impact:          "Stolen session cookies remain valid after the user logs out, allowing attackers who captured the cookie to maintain access.",
		Remediation:     "On logout, server must invalidate the session server-side, clear the cookie (Expires in past, Max-Age 0), and rotate any session tokens.",
		References:      []string{"https://owasp.org/www-community/vulnerabilities/Insufficient_Session_Expiration", "https://cwe.mitre.org/data/definitions/613.html"},
		FirstSeen:       time.Now(),
	}
}
