package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

// xpathRule detects XPath injection via boolean bypass probes.
// Payloads like ' or '1'='1 flip XPath predicates and surface as changed
// responses or XPath error disclosures.
//
// Safety: LowImpact — logic-preserving probes, no extraction.
type xpathRule struct{}

func (r *xpathRule) ID() models.ActiveRuleID    { return "xpath-injection" }
func (r *xpathRule) Name() string               { return "XPath Injection" }
func (r *xpathRule) Safety() models.SafetyLevel { return models.SafetyLowImpact }
func (r *xpathRule) RequestBudget() int         { return 3 }

var xpathPayloads = []string{
	`' or '1'='1`,
	`" or "1"="1`,
	`' or 1=1 or ''='`,
}

var xpathSignals = []string{
	"xpath",
	"xpath syntax",
	"expression failed",
	"invalid predicate",
	"xml path",
}

func (r *xpathRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}
	if v.Kind != models.VectorQueryParam && v.Kind != models.VectorPathSegment && v.Kind != models.VectorJSONBody {
		return result, nil
	}
	baselineBody := ""
	if result.RequestsMade < r.RequestBudget() {
		if b, ok := xpathBaseline(ctx, client, v); ok {
			baselineBody = strings.ToLower(b)
			result.RequestsMade++
		}
	}
	for _, payload := range xpathPayloads {
		if result.RequestsMade >= r.RequestBudget() {
			break
		}
		body, status, ok := xpathProbe(ctx, client, v, v.OriginalValue+payload)
		result.RequestsMade++
		if !ok {
			continue
		}
		lower := strings.ToLower(body)
		clean := strings.ReplaceAll(lower, strings.ToLower(payload), "")
		for _, sig := range xpathSignals {
			if strings.Contains(clean, sig) && !strings.Contains(baselineBody, sig) {
				result.Found = true
				result.Payload = payload
				result.Evidence = fmt.Sprintf("XPath injection signal %q appeared after payload %q (status %d)", sig, payload, status)
				return result, nil
			}
		}
		// Reflection of bypass pattern without neutralization
		if strings.Contains(lower, "1'='1") || strings.Contains(lower, `1"="1`) {
			if !strings.Contains(baselineBody, "1'='1") {
				result.Found = true
				result.Payload = payload
				result.Evidence = fmt.Sprintf("XPath bypass payload %q reflected in response (status %d)", payload, status)
				return result, nil
			}
		}
	}
	return result, nil
}

func xpathBaseline(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (string, bool) {
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

func xpathProbe(ctx context.Context, client *anpuhttp.Client, v models.InputVector, payload string) (string, int, bool) {
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

func (r *xpathRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	return models.Finding{
		ID:              fmt.Sprintf("active-xpath-%d", time.Now().UnixNano()),
		Title:           fmt.Sprintf("XPath injection in parameter %q at %s", res.Vector.Name, res.Vector.URL),
		Description:     fmt.Sprintf("Parameter %q provoked an XPath signal after injecting %q — the XPath query interpolates user input without sanitization.", res.Vector.Name, res.Payload),
		Severity:        models.SeverityHigh,
		Confidence:      models.ConfidenceMedium,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-643",
		OWASP:           "A03:2021 - Injection",
		Target:          target,
		URL:             res.Vector.URL,
		Parameter:       res.Vector.Name,
		Source:          models.SourceActive,
		DetectionMethod: "XPath injection probe: boolean bypass triggered error or reflection (baseline-subtracted)",
		Evidence:        models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("GET %s (payload in %s=%q)", res.Vector.URL, res.Vector.Name, res.Payload)},
		Impact:          "Attackers can bypass authentication, enumerate XML data stores, and exfiltrate sensitive nodes.",
		Remediation:     "Use parameterized XPath APIs or pre-compiled XPath with variable binding. Escape user input for XPath contexts.",
		References:      []string{"https://owasp.org/www-community/attacks/XPATH_Injection", "https://cwe.mitre.org/data/definitions/643.html"},
		FirstSeen:       time.Now(),
	}
}
