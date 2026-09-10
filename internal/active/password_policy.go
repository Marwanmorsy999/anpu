package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

// passwordPolicyRule probes for weak password policy by detecting lack of
// complexity enforcement signals (adversarial, opt-in).
// It posts weak passwords to registration/change endpoints and checks
// whether they are accepted (200) vs rejected (400).
//
// Safety: LowImpact — attempts weak passwords on endpoints that look like
// password handling, adversarial-gated, no brute-force.
type passwordPolicyRule struct{}

func (r *passwordPolicyRule) ID() models.ActiveRuleID    { return "password-policy-weak" }
func (r *passwordPolicyRule) Name() string               { return "Weak Password Policy" }
func (r *passwordPolicyRule) Safety() models.SafetyLevel { return models.SafetyLowImpact }
func (r *passwordPolicyRule) RequestBudget() int         { return 3 }

func looksLikePasswordEndpoint(raw string, param string) bool {
	lowerURL := strings.ToLower(raw)
	lowerParam := strings.ToLower(param)
	if strings.Contains(lowerParam, "password") || strings.Contains(lowerParam, "passwd") || strings.Contains(lowerParam, "pwd") {
		return true
	}
	return strings.Contains(lowerURL, "register") || strings.Contains(lowerURL, "signup") || strings.Contains(lowerURL, "password") || strings.Contains(lowerURL, "reset")
}

func (r *passwordPolicyRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}
	if !IsAdversarialEnabled() {
		return result, nil
	}
	if !looksLikePasswordEndpoint(v.URL, v.Name) {
		return result, nil
	}
	weakPayloads := []string{"123", "password", "a"}
	for _, weak := range weakPayloads {
		if result.RequestsMade >= r.RequestBudget() {
			break
		}
		var resp *anpuhttp.Response
		var err error
		if v.Kind == models.VectorJSONBody {
			body, _ := buildJSONBody(v.Name, weak)
			resp, err = client.PostJSON(ctx, v.URL, body, nil)
			result.RequestsMade++
		} else {
			inj, e := buildInjectedURL(v, weak)
			if e != nil {
				continue
			}
			resp, err = client.Get(ctx, inj)
			result.RequestsMade++
		}
		if err != nil || resp == nil {
			continue
		}
		// If weak password is accepted (200) without complaint, policy is weak
		if resp.StatusCode == 200 {
			bodyLower := strings.ToLower(string(resp.Body))
			// Check that response doesn't contain rejection keywords
			if !strings.Contains(bodyLower, "too short") && !strings.Contains(bodyLower, "weak") && !strings.Contains(bodyLower, "complexity") && !strings.Contains(bodyLower, "requirements") {
				result.Found = true
				result.Payload = weak
				result.Evidence = fmt.Sprintf("Weak password %q accepted at %q (status 200, no complexity rejection in body len %d)", weak, v.URL, len(resp.Body))
				return result, nil
			}
		}
	}
	return result, nil
}

func (r *passwordPolicyRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	return models.Finding{
		ID:              fmt.Sprintf("active-pwdpolicy-%d", time.Now().UnixNano()),
		Title:           fmt.Sprintf("Weak password policy at %s", res.Vector.URL),
		Description:     fmt.Sprintf("Parameter %q at %s accepted a trivial password %q without enforcing complexity — the application permits weak passwords that are easily guessed. Evidence: %s", res.Vector.Name, res.Vector.URL, res.Payload, res.Evidence),
		Severity:        models.SeverityMedium,
		Confidence:      models.ConfidenceLow,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-521",
		OWASP:           "A07:2021 - Identification and Authentication Failures",
		Target:          target,
		URL:             res.Vector.URL,
		Parameter:       res.Vector.Name,
		Source:          models.SourceActive,
		DetectionMethod: "password policy probe: weak passwords accepted (adversarial)",
		Evidence:        models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("GET/POST %s with weak password %q", res.Vector.URL, res.Payload)},
		Impact:          "Attackers can set or brute-force trivial passwords, leading to account takeover.",
		Remediation:     "Enforce minimum length (≥8), complexity, breached-password checks, and rate limiting on password changes. Follow NIST 800-63B.",
		References:      []string{"https://pages.nist.gov/800-63-3/sp800-63b.html", "https://cwe.mitre.org/data/definitions/521.html"},
		FirstSeen:       time.Now(),
	}
}
