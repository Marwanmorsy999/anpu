package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// formulaRule detects CSV / spreadsheet formula injection via context-sensitive
// payloads like =cmd| or @SUM. Vulnerable apps that export user input to CSV
// without sanitizing formula prefixes enable exfil via DDE.
//
// Safety: Benign — formula prefix probes only, no execution.
type formulaRule struct{}

func (r *formulaRule) ID() models.ActiveRuleID    { return "formula-injection" }
func (r *formulaRule) Name() string               { return "Formula / CSV Injection" }
func (r *formulaRule) Safety() models.SafetyLevel { return models.SafetyBenign }
func (r *formulaRule) RequestBudget() int         { return 3 }

var formulaPayloads = []string{
	`=cmd|' /C calc'!A0`,
	`@SUM(1+1)*cmd|' /C calc'!A0`,
	`=2+5+cmd|' /C calc'!A0`,
}

func (r *formulaRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}
	if v.Kind != models.VectorQueryParam && v.Kind != models.VectorPathSegment && v.Kind != models.VectorJSONBody {
		return result, nil
	}
	baselineBody := ""
	if result.RequestsMade < r.RequestBudget() {
		if b, ok := formulaBaseline(ctx, client, v); ok {
			baselineBody = strings.ToLower(b)
			result.RequestsMade++
		}
	}
	for _, payload := range formulaPayloads {
		if result.RequestsMade >= r.RequestBudget() {
			break
		}
		body, status, ok := formulaProbe(ctx, client, v, payload)
		result.RequestsMade++
		if !ok {
			continue
		}
		lower := strings.ToLower(body)
		// Reflection of formula prefix without sanitization (no leading ' or escaping)
		if (strings.Contains(lower, "=cmd|") || strings.Contains(lower, "@sum")) && !strings.Contains(baselineBody, "=cmd|") {
			// Check that payload is reflected verbatim (not neutralized with leading single quote)
			if strings.Contains(body, payload) && !strings.Contains(body, "'"+payload) && !strings.Contains(body, "\\"+payload[:1]) {
				result.Found = true
				result.Payload = payload
				result.Evidence = fmt.Sprintf("Formula payload %q reflected verbatim (status %d, baseline absent) — CSV export likely injectable", payload, status)
				return result, nil
			}
		}
	}
	return result, nil
}

func formulaBaseline(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (string, bool) {
	if v.Kind == models.VectorJSONBody {
		b, _ := buildJSONBody(v.Name, v.OriginalValue)
		resp, err := client.PostJSON(ctx, v.URL, b, nil)
		if err != nil || resp == nil {
			return "", false
		}
		return string(resp.Body), true
	}
	resp, err := client.Get(ctx, v.URL)
	if err != nil || resp == nil {
		return "", false
	}
	return string(resp.Body), true
}

func formulaProbe(ctx context.Context, client *anpuhttp.Client, v models.InputVector, payload string) (string, int, bool) {
	if v.Kind == models.VectorJSONBody {
		b, _ := buildJSONBody(v.Name, payload)
		resp, err := client.PostJSON(ctx, v.URL, b, nil)
		if err != nil || resp == nil {
			return "", 0, false
		}
		return string(resp.Body), resp.StatusCode, true
	}
	inj, err := buildInjectedURL(v, payload)
	if err != nil {
		return "", 0, false
	}
	resp, err := client.Get(ctx, inj)
	if err != nil || resp == nil {
		return "", 0, false
	}
	return string(resp.Body), resp.StatusCode, true
}

func (r *formulaRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	return models.Finding{
		ID:              fmt.Sprintf("active-formula-%d", time.Now().UnixNano()),
		Title:           fmt.Sprintf("Formula / CSV injection in parameter %q at %s", res.Vector.Name, res.Vector.URL),
		Description:     fmt.Sprintf("Parameter %q reflected a spreadsheet formula prefix %q without neutralization — data exported to CSV will execute formulas in victims' spreadsheet applications.", res.Vector.Name, res.Payload),
		Severity:        models.SeverityMedium,
		Confidence:      models.ConfidenceLow,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-1236",
		OWASP:           "A03:2021 - Injection",
		Target:          target,
		URL:             res.Vector.URL,
		Parameter:       res.Vector.Name,
		Source:          models.SourceActive,
		DetectionMethod: "formula injection probe: =cmd| / @SUM reflected verbatim (baseline-subtracted)",
		Evidence:        models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("GET %s (payload in %s=%q)", res.Vector.URL, res.Vector.Name, res.Payload)},
		Impact:          "Attackers can inject formulas that exfiltrate data or execute commands when the CSV is opened.",
		Remediation:     "Prefix user input that starts with = + - @ with a single quote (') or escape formula metacharacters on CSV export.",
		References:      []string{"https://owasp.org/www-community/attacks/CSV_Injection"},
		FirstSeen:       time.Now(),
	}
}
