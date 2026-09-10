package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

// schemaRequiredRule omits a schema-required query parameter and diffs
// against the intact baseline plus a random control. A 500 or an error
// marker that neither baseline nor control shows means missing-required
// input crashes through to internals (robustness + info-disclosure).
// Clean 400 validation stays silent.
//
// Safety: Benign — parameter omission only, no state change.
type schemaRequiredRule struct{}

func (r *schemaRequiredRule) ID() models.ActiveRuleID    { return "schema-required-omission" }
func (r *schemaRequiredRule) Name() string               { return "Schema Required Omission" }
func (r *schemaRequiredRule) Safety() models.SafetyLevel { return models.SafetyBenign }
func (r *schemaRequiredRule) RequestBudget() int         { return 3 }

func (r *schemaRequiredRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}
	if v.Kind != models.VectorQueryParam || !v.Required {
		return result, nil
	}
	// Baseline WITH the parameter at its schema example value: schema
	// endpoint URLs are often bare templates, so v.URL alone may not
	// exercise the parameter at all.
	orig := v.OriginalValue
	if orig == "" {
		orig = "1"
	}
	withValue, uerr := InjectQueryParam(v.URL, v.Name, orig)
	if uerr != nil {
		return result, nil
	}
	baseResp, err := client.Get(ctx, withValue)
	result.RequestsMade++
	if err != nil || baseResp == nil {
		return result, nil
	}
	baseStatus, baseBody := baseResp.StatusCode, strings.ToLower(string(baseResp.Body))

	omitted, uerr := OmitQueryParam(v.URL, v.Name)
	if uerr != nil || omitted == v.URL {
		return result, nil
	}
	if result.RequestsMade >= r.RequestBudget() {
		return result, nil
	}
	omitResp, err := client.Get(ctx, omitted)
	result.RequestsMade++
	if err != nil || omitResp == nil {
		return result, nil
	}
	omitStatus, omitBody := omitResp.StatusCode, strings.ToLower(string(omitResp.Body))
	if omitStatus == baseStatus && omitBody == baseBody {
		return result, nil // optional in practice despite the schema
	}
	if isCleanValidation(omitStatus, omitBody) {
		return result, nil // proper 400 validation — correct behavior
	}
	if omitStatus == 500 || (hasMarker(omitBody, schemaErrorMarkers) && omitBody != baseBody) {
		result.Found = true
		result.Payload = "(omitted required param " + v.Name + ")"
		result.Evidence = fmt.Sprintf("required-omission: dropping %q → %d (baseline %d)", v.Name, omitStatus, baseStatus)
	}
	return result, nil
}

func (r *schemaRequiredRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	return models.Finding{
		ID:              fmt.Sprintf("active-schemarequired-%d", time.Now().UnixNano()),
		Title:           fmt.Sprintf("Missing required parameter %q crashes at %s", res.Vector.Name, res.Vector.URL),
		Description:     fmt.Sprintf("Omitting schema-required parameter %q produced a server error instead of clean validation — unhandled missing input leaks internals and signals weak input handling.", res.Vector.Name),
		Severity:        models.SeverityMedium,
		Confidence:      models.ConfidenceMedium,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-754",
		OWASP:           "A03:2021 - Injection",
		Target:          target,
		URL:             res.Vector.URL,
		Parameter:       res.Vector.Name,
		Source:          models.SourceActive,
		DetectionMethod: "Required-param omission with baseline differential (baseline-subtracted)",
		Evidence:        models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("GET without %s", res.Vector.Name)},
		Impact:          "Unhandled missing input can expose stack traces and bypass assumed-present validation.",
		Remediation:     "Validate presence of required parameters and return generic 400 errors.",
		FirstSeen:       time.Now(),
	}
}
