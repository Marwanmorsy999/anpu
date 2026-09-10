package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

// hppRule detects HTTP Parameter Pollution by injecting a duplicate
// parameter with a second value and observing whether the server
// concatenates, prefers, or otherwise mishandles the duplicated input.
//
// Safety: Benign — duplicate query param only, no state change.
type hppRule struct{}

func (r *hppRule) ID() models.ActiveRuleID    { return "hpp-injection" }
func (r *hppRule) Name() string               { return "HTTP Parameter Pollution" }
func (r *hppRule) Safety() models.SafetyLevel { return models.SafetyBenign }
func (r *hppRule) RequestBudget() int         { return 3 }

func (r *hppRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}
	if v.Kind != models.VectorQueryParam {
		return result, nil
	}
	// Build URL with duplicate param: ?id=1&id=2 style (append second occurrence)
	baselineResp, err := client.Get(ctx, v.URL)
	result.RequestsMade++
	if err != nil || baselineResp == nil {
		return result, nil
	}
	baselineBody := strings.ToLower(string(baselineResp.Body))
	baselineStatus := baselineResp.StatusCode

	// Construct polluted URL manually to preserve duplicate key.
	// Ghost mode uses HPPPollutedValue() (no `anpu` substring).
	pollutedValue := HPPPollutedValue()
	polluted := buildHPPURL(v.URL, v.Name, v.OriginalValue, pollutedValue)
	if polluted == "" {
		return result, nil
	}
	if result.RequestsMade >= r.RequestBudget() {
		return result, nil
	}
	resp, err := client.Get(ctx, polluted)
	result.RequestsMade++
	if err != nil || resp == nil {
		return result, nil
	}
	body := strings.ToLower(string(resp.Body))
	// Signal 1: both values appear (concatenation) — baseline didn't have second value
	if strings.Contains(body, strings.ToLower(pollutedValue)) && !strings.Contains(baselineBody, strings.ToLower(pollutedValue)) {
		// Confirm that polluted response differs meaningfully from baseline
		if body != baselineBody || resp.StatusCode != baselineStatus {
			result.Found = true
			result.Payload = v.Name + "=" + pollutedValue + " (duplicate)"
			result.Evidence = fmt.Sprintf("HPP signal: polluted value %q appeared in response (status %d vs %d baseline, body diff)", pollutedValue, resp.StatusCode, baselineStatus)
			return result, nil
		}
	}
	// Signal 2: status code flip due to pollution handling difference
	if resp.StatusCode != baselineStatus && resp.StatusCode < 500 {
		// Only flag if baseline was 200 and polluted changed it (but not error)
		if baselineStatus == 200 && resp.StatusCode != 200 {
			result.Found = true
			result.Payload = v.Name + "=" + pollutedValue
			result.Evidence = fmt.Sprintf("HPP signal: status %d -> %d after duplicate param %q", baselineStatus, resp.StatusCode, v.Name)
			return result, nil
		}
	}
	return result, nil
}

func buildHPPURL(rawURL, param, origValue, pollutedValue string) string {
	// Append duplicate: keep original and add second same-name param
	if strings.Contains(rawURL, "?") {
		return rawURL + "&" + param + "=" + pollutedValue
	}
	return rawURL + "?" + param + "=" + pollutedValue
}

func (r *hppRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	return models.Finding{
		ID:              fmt.Sprintf("active-hpp-%d", time.Now().UnixNano()),
		Title:           fmt.Sprintf("HTTP Parameter Pollution in parameter %q at %s", res.Vector.Name, res.Vector.URL),
		Description:     fmt.Sprintf("Parameter %q allowed duplicate injection (%q) to alter the server's response — duplicate parameter handling is inconsistent or concatenative, enabling HPP attacks.", res.Vector.Name, res.Payload),
		Severity:        models.SeverityMedium,
		Confidence:      models.ConfidenceMedium,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-235",
		OWASP:           "A03:2021 - Injection",
		Target:          target,
		URL:             res.Vector.URL,
		Parameter:       res.Vector.Name,
		Source:          models.SourceActive,
		DetectionMethod: "HPP probe: duplicate query param ?id=1&id=2 style triggered response change (baseline-subtracted)",
		Evidence:        models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("GET %s (duplicate %s)", res.Vector.URL, res.Payload)},
		Impact:          "HPP can bypass input validation, pollute array parameters, and alter backend logic that expects a single value.",
		Remediation:     "On the server, accept only the first or last occurrence of a duplicated parameter and validate against an allowlist. Frameworks should enforce single-value semantics.",
		References:      []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution"},
		FirstSeen:       time.Now(),
	}
}
