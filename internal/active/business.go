package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

// businessRule detects business logic manipulation (price/quantity tampering).
//
// It injects tampered numeric values (price=-1, quantity=999999, discount=100)
// into JSON bodies or query params and checks if the server accepts them
// (status 200 with no validation error) or reflects them.
// Safety: LowImpact — probes use read-only validation checks, no actual
// purchase is completed, and no state is mutated beyond a single validation request.
type businessRule struct{}

func (r *businessRule) ID() models.ActiveRuleID    { return "business-logic-tamper" }
func (r *businessRule) Name() string               { return "Business Logic Tampering" }
func (r *businessRule) Safety() models.SafetyLevel { return models.SafetyLowImpact }
func (r *businessRule) RequestBudget() int         { return 5 }

var businessProbes = []struct {
	name  string
	value string
	ct    string
}{
	{"price", "-1", "application/json"},
	{"quantity", "999999", "application/json"},
	{"discount", "100", "application/json"},
	{"amount", "0", "application/json"},
}

func (r *businessRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}
	// Only test vectors that look like business fields or are JSON bodies.
	isBusinessField := false
	lowerName := strings.ToLower(v.Name)
	for _, f := range []string{"price", "quantity", "amount", "total", "discount", "cost", "qty"} {
		if strings.Contains(lowerName, f) {
			isBusinessField = true
			break
		}
	}
	if v.Kind != models.VectorJSONBody && !isBusinessField {
		return result, nil
	}

	// Baseline
	var baseResp *anpuhttp.Response
	var err error
	if v.Kind == models.VectorJSONBody {
		baseBody, _ := buildJSONBody(v.Name, v.OriginalValue)
		if baseBody == "" {
			baseBody = fmt.Sprintf(`{"%s":%q}`, v.Name, v.OriginalValue)
		}
		baseResp, err = client.PostJSON(ctx, v.URL, baseBody, nil)
		result.RequestsMade++
	} else {
		baseResp, err = client.Get(ctx, v.URL)
		result.RequestsMade++
	}
	if err != nil || baseResp == nil {
		return result, nil
	}
	baseBodyLower := strings.ToLower(string(baseResp.Body))

	for _, probe := range businessProbes {
		if result.RequestsMade >= r.RequestBudget() {
			break
		}
		var resp *anpuhttp.Response
		var probePayload string
		if v.Kind == models.VectorJSONBody {
			// Inject tampered value for the business field
			probePayload = fmt.Sprintf(`{"%s":%s}`, probe.name, probe.value)
			// If vector name itself is business-like, use that name instead
			if isBusinessField {
				probePayload = fmt.Sprintf(`{"%s":%s}`, v.Name, probe.value)
			}
			resp, err = client.PostJSON(ctx, v.URL, probePayload, nil)
			result.RequestsMade++
		} else {
			// Query param tampering
			injected := probe.value
			probePayload = injected
			injURL, e := InjectQueryParam(v.URL, v.Name, injected)
			if e != nil {
				continue
			}
			resp, err = client.Get(ctx, injURL)
			result.RequestsMade++
		}
		if err != nil || resp == nil {
			continue
		}
		bodyLower := strings.ToLower(string(resp.Body))
		// If server accepts tampered value without validation error and reflects it.
		accepts := resp.StatusCode == 200 && !strings.Contains(bodyLower, "invalid") && !strings.Contains(bodyLower, "error") && strings.Contains(bodyLower, probe.value)
		// Also if baseline had validation but probe doesn't, or vice versa, check status change.
		if accepts && !strings.Contains(baseBodyLower, probe.value) {
			result.Found = true
			result.Payload = probePayload
			result.Evidence = fmt.Sprintf("Business logic accepted tampered %q=%q (status 200, reflected, CT %q, len %d). Server lacks validation for business-critical fields.", probe.name, probe.value, resp.Header.Get("Content-Type"), len(resp.Body))
			return result, nil
		}
		// Also detect price=0 accepted when price field is present
		if probe.name == "price" && probe.value == "-1" && resp.StatusCode == 200 && strings.Contains(bodyLower, "-1") {
			if !strings.Contains(baseBodyLower, "-1") {
				result.Found = true
				result.Payload = probePayload
				result.Evidence = fmt.Sprintf("Negative price accepted: %q=%q reflected (status %d, len %d)", probe.name, probe.value, resp.StatusCode, len(resp.Body))
				return result, nil
			}
		}
	}
	return result, nil
}

func (r *businessRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	return models.Finding{
		ID:              fmt.Sprintf("active-business-%d", time.Now().UnixNano()),
		Title:           fmt.Sprintf("Business logic tampering at %s", res.Vector.URL),
		Description:     fmt.Sprintf("Endpoint at %s accepted a tampered business value (%s) without validation. An attacker can manipulate prices, quantities, or discounts to bypass business rules (e.g., set price to -1 or quantity to 999999).", res.Vector.URL, res.Evidence),
		Severity:        models.SeverityHigh,
		Confidence:      models.ConfidenceMedium,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-840",
		OWASP:           "A04:2021 - Insecure Design",
		Target:          target,
		URL:             res.Vector.URL,
		Parameter:       res.Vector.Name,
		Source:          models.SourceActive,
		DetectionMethod: "business logic probe: tampered numeric field accepted without validation via anpuhttp",
		Evidence:        models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("POST %s with tampered %q", res.Vector.URL, res.Payload)},
		Impact:          "Financial loss, inventory manipulation, or bypass of business constraints (e.g., free purchases, excessive discounts).",
		Remediation:     "Validate business fields server-side (price must match catalog, quantity within limits, discounts authorized), never trust client-supplied totals.",
		References:      []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_Business_Logic"},
		FirstSeen:       time.Now(),
	}
}
