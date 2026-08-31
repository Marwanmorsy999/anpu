package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

// openRedirectRule detects open redirect vulnerabilities by injecting a
// known external domain and checking whether the response redirects there.
// Uses a benign canary domain that cannot cause real harm.
//
// Safety: benign — GET-only, canary domain resolves nowhere harmful.
type openRedirectRule struct{}

func (r *openRedirectRule) ID() models.ActiveRuleID  { return "open-redirect" }
func (r *openRedirectRule) Name() string             { return "Open Redirect" }
func (r *openRedirectRule) Safety() models.SafetyLevel { return models.SafetyBenign }
func (r *openRedirectRule) RequestBudget() int       { return 2 }

// canaryDomain is a domain that cannot be confused with a real destination.
// We check if the final URL (after redirect) lands on it or the Location
// header points there.
const redirectCanaryDomain = `anpu-redirect-canary.invalid`

var redirectPayloads = []string{
	`https://` + redirectCanaryDomain,
	`//` + redirectCanaryDomain,
	`/\` + redirectCanaryDomain,
	`https:` + redirectCanaryDomain,
}

func (r *openRedirectRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}

	for _, payload := range redirectPayloads {
		if result.RequestsMade >= r.RequestBudget() {
			break
		}
		injected, err := buildInjectedURL(v, payload)
		if err != nil {
			continue
		}
		resp, err := client.Get(ctx, injected)
		result.RequestsMade++
		if err != nil {
			continue
		}

		location := resp.Header.Get("Location")
		finalURL := resp.FinalURL

		if strings.Contains(location, redirectCanaryDomain) ||
			strings.Contains(finalURL, redirectCanaryDomain) ||
			(resp.StatusCode >= 300 && resp.StatusCode < 400 && strings.Contains(location, redirectCanaryDomain)) {
			result.Found = true
			result.Payload = payload
			result.Evidence = fmt.Sprintf(
				"Response redirected toward canary domain (status %d, Location: %q, FinalURL: %q)",
				resp.StatusCode, location, finalURL,
			)
			return result, nil
		}
	}
	return result, nil
}

func (r *openRedirectRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	return models.Finding{
		ID:          fmt.Sprintf("active-redirect-%d", time.Now().UnixNano()),
		Title:       fmt.Sprintf("Open redirect in parameter %q at %s", res.Vector.Name, res.Vector.URL),
		Description: fmt.Sprintf("Parameter %q at %s accepted an external URL and redirected the response toward it, confirming an open redirect vulnerability.", res.Vector.Name, res.Vector.URL),
		Severity:    models.SeverityMedium,
		Confidence:  models.ConfidenceHigh,
		Category:    models.CategoryVulnerability,
		CWE:         "CWE-601",
		OWASP:       "A01:2021 - Broken Access Control",
		Target:      target,
		URL:         res.Vector.URL,
		Parameter:   res.Vector.Name,
		Source:      models.SourceActive,
		DetectionMethod: "open redirect probe: canary external domain injected, redirect observed in response",
		Evidence:    models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("GET %s (payload in %s=%q)", res.Vector.URL, res.Vector.Name, res.Payload)},
		Impact:      "An attacker can craft URLs that redirect users to malicious sites, enabling phishing and credential harvesting under the legitimate domain.",
		Remediation: "Validate redirect destinations against an allowlist of trusted URLs. Never use raw user input as a redirect target.",
		References:  []string{"https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"},
		FirstSeen:   time.Now(),
	}
}
