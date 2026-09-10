package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

// sessionFixationRule detects session fixation by testing whether the
// server accepts a pre-set session identifier (CWE-384).
// It sends a request with an attacker-chosen JSESSIONID/PHPSESSID and
// checks if the app reuses it rather than regenerating.
//
// Safety: LowImpact — pre-set cookie is sent, no hijacking attempt is
// confirmed beyond reflection; adversarial-gated.
type sessionFixationRule struct{}

func (r *sessionFixationRule) ID() models.ActiveRuleID    { return "session-fixation" }
func (r *sessionFixationRule) Name() string               { return "Session Fixation" }
func (r *sessionFixationRule) Safety() models.SafetyLevel { return models.SafetyLowImpact }
func (r *sessionFixationRule) RequestBudget() int         { return 3 }

func (r *sessionFixationRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}
	if !IsAdversarialEnabled() {
		return result, nil
	}
	// Only test page-level vectors (noisy, needs session cookie context)
	if v.Kind != models.VectorQueryParam && v.Kind != models.VectorPathSegment {
		return result, nil
	}
	canary := SessionFixationCanary()
	probeResp, err := client.DoWithHeaders(ctx, "GET", v.URL, map[string]string{
		"Cookie": "JSESSIONID=" + canary + "; PHPSESSID=" + canary,
	})
	result.RequestsMade++
	if err != nil || probeResp == nil {
		return result, nil
	}
	// Check if response echoes our canary in Set-Cookie (server accepted it) or body
	setCookie := probeResp.Header.Get("Set-Cookie")
	body := string(probeResp.Body)
	if strings.Contains(setCookie, canary) || strings.Contains(strings.ToLower(body), strings.ToLower(canary)) {
		result.Found = true
		result.Payload = canary
		result.Evidence = fmt.Sprintf("Session fixation candidate: pre-set JSESSIONID/PHPSESSID %q reflected in response (Set-Cookie: %q, body contains, status %d) — server may reuse attacker-supplied session ID", canary, setCookie, probeResp.StatusCode)
		return result, nil
	}
	// Also check that server did NOT issue a fresh session (no regeneration)
	if setCookie == "" && probeResp.StatusCode == 200 {
		// No Set-Cookie at all suggests session not regenerated — weak signal
		// Only flag if we can confirm the same session persists via second request
		second, err := client.DoWithHeaders(ctx, "GET", v.URL, map[string]string{
			"Cookie": "JSESSIONID=" + canary,
		})
		result.RequestsMade++
		if err == nil && second != nil && second.StatusCode == 200 {
			if len(second.Body) > 0 && strings.Contains(string(second.Body), canary) {
				result.Found = true
				result.Payload = canary
				result.Evidence = fmt.Sprintf("Session fixation via persistence: JSESSIONID %q survived across requests (second body contains)", canary)
				return result, nil
			}
		}
	}
	return result, nil
}

func randomHexShort(n int) string {
	hexStr := randomHex(n)
	if len(hexStr) >= n*2 {
		return hexStr[:n*2]
	}
	return hexStr
}

func (r *sessionFixationRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	return models.Finding{
		ID:              fmt.Sprintf("active-session-fix-%d", time.Now().UnixNano()),
		Title:           fmt.Sprintf("Session fixation at %s", res.Vector.URL),
		Description:     fmt.Sprintf("The application appears to accept a pre-set session identifier (JSESSIONID/PHPSESSID) %q without regenerating it — an attacker can fix a victim's session by setting this cookie beforehand. Evidence: %s", res.Payload, res.Evidence),
		Severity:        models.SeverityMedium,
		Confidence:      models.ConfidenceLow,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-384",
		OWASP:           "A07:2021 - Identification and Authentication Failures",
		Target:          target,
		URL:             res.Vector.URL,
		Source:          models.SourceActive,
		DetectionMethod: "session fixation probe: pre-set JSESSIONID sent, server reuse detected (adversarial)",
		Evidence:        models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("GET %s with Cookie: JSESSIONID=%s", res.Vector.URL, res.Payload)},
		Impact:          "Attackers can hijack authenticated sessions by forcing victims to use a known session ID.",
		Remediation:     "Regenerate session ID on authentication and privilege changes; reject attacker-supplied session IDs; set HttpOnly, Secure, SameSite on cookies.",
		References:      []string{"https://owasp.org/www-community/attacks/Session_fixation", "https://cwe.mitre.org/data/definitions/384.html"},
		FirstSeen:       time.Now(),
	}
}
