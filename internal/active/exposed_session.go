package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// exposedSessionRule detects session IDs exposed in URL (CWE-200 / CWE-598).
// It checks for ;jsessionid= or PHPSESSID in URLs or redirects.
//
// Safety: Benign — GET only, checks URL patterns, adversarial-gated.
type exposedSessionRule struct{}

func (r *exposedSessionRule) ID() models.ActiveRuleID    { return "exposed-session-id" }
func (r *exposedSessionRule) Name() string               { return "Exposed Session Identifier in URL" }
func (r *exposedSessionRule) Safety() models.SafetyLevel { return models.SafetyBenign }
func (r *exposedSessionRule) RequestBudget() int         { return 2 }

func (r *exposedSessionRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}
	if !IsAdversarialEnabled() {
		return result, nil
	}
	if v.Kind != models.VectorQueryParam && v.Kind != models.VectorPathSegment {
		return result, nil
	}
	resp, err := client.Get(ctx, v.URL)
	result.RequestsMade++
	if err != nil || resp == nil {
		return result, nil
	}
	body := string(resp.Body)
	lowerBody := strings.ToLower(body)
	finalURL := strings.ToLower(resp.FinalURL)
	loc := strings.ToLower(resp.Header.Get("Location"))
	// Look for ;jsessionid= pattern in body links, final URL, or Location
	indicators := []string{";jsessionid=", "phpsessid=", "jsessionid=", "sessionid=", ";sessionid="}
	for _, ind := range indicators {
		if strings.Contains(lowerBody, ind) || strings.Contains(finalURL, ind) || strings.Contains(loc, ind) {
			result.Found = true
			result.Payload = ind
			result.Evidence = fmt.Sprintf("Session identifier %q found exposed in URL: body contains %v, finalURL %q, Location %q (status %d)", ind, strings.Contains(lowerBody, ind), resp.FinalURL, resp.Header.Get("Location"), resp.StatusCode)
			return result, nil
		}
	}
	// Also check response headers for URL rewriting that leaks session
	if resp.Header.Get("Set-Cookie") == "" && strings.Contains(finalURL, "jsessionid") {
		result.Found = true
		result.Payload = "jsessionid"
		result.Evidence = fmt.Sprintf("Final URL exposes session %q (no Set-Cookie, status %d)", resp.FinalURL, resp.StatusCode)
		return result, nil
	}
	return result, nil
}

func (r *exposedSessionRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	return models.Finding{
		ID:              fmt.Sprintf("active-exposed-sess-%d", time.Now().UnixNano()),
		Title:           fmt.Sprintf("Session ID exposed in URL at %s", res.Vector.URL),
		Description:     fmt.Sprintf("A session identifier was found in the URL (pattern %q) — URLs are logged, cached, and leak via Referer, enabling session theft. Evidence: %s", res.Payload, res.Evidence),
		Severity:        models.SeverityMedium,
		Confidence:      models.ConfidenceMedium,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-598",
		OWASP:           "A07:2021 - Identification and Authentication Failures",
		Target:          target,
		URL:             res.Vector.URL,
		Parameter:       res.Payload,
		Source:          models.SourceActive,
		DetectionMethod: "exposed session probe: GET page, check body/URL/Location for ;jsessionid= / PHPSESSID (adversarial)",
		Evidence:        models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("GET %s", res.Vector.URL)},
		Impact:          "Session IDs in URLs leak via browser history, logs, Referer headers, and shoulder surfing, enabling hijacking.",
		Remediation:     "Store session IDs in Secure, HttpOnly, SameSite cookies only — never in URLs. Disable URL rewriting for session tracking.",
		References:      []string{"https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url", "https://cwe.mitre.org/data/definitions/598.html"},
		FirstSeen:       time.Now(),
	}
}
