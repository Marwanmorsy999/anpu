package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// schemaTypeRule sends a schema-violating value for a schema-declared
// parameter type (integer gets a string, boolean gets "maybe", string
// gets an object marker, ...) and diffs against baseline + control.
//
// A 500 or an error-marker differential means weak server-side typing
// (often paired with verbose errors); a clean 400 validation response
// is correct behavior and stays silent.
//
// Safety: Benign — one benign mistyped value, no state change.
type schemaTypeRule struct{}

func (r *schemaTypeRule) ID() models.ActiveRuleID    { return "schema-type-confusion" }
func (r *schemaTypeRule) Name() string               { return "Schema Type Confusion" }
func (r *schemaTypeRule) Safety() models.SafetyLevel { return models.SafetyBenign }
func (r *schemaTypeRule) RequestBudget() int         { return 5 }

var schemaTypeViolations = map[string]string{
	"integer": "anpu7x",
	"number":  "anpu7x",
	"boolean": "maybe",
	"string":  `{"anpu":1}`,
	"array":   "anpustr",
	"object":  "anpustr",
}

var schemaErrorMarkers = []string{
	"traceback", "stack trace", "stacktrace", "exception", "fatal error",
	"unmarshal", "typeerror", "type error", "cannot convert", "cast",
	"nullpointer", "null pointer", "json.parse", "json parse",
}

var schemaValidationMarkers = []string{
	"validation failed", "validation error", "invalid type", "expected type",
	"must be a", "must be an", "is required", "bad request",
}

func (r *schemaTypeRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}
	if v.Schema == "" {
		return result, nil // crawler-discovered locations carry no schema
	}
	violation, ok := schemaTypeViolations[strings.ToLower(strings.TrimSpace(v.Schema))]
	if !ok {
		return result, nil
	}
	switch v.Kind {
	case models.VectorQueryParam:
		return r.testQuery(ctx, client, v, result, violation)
	case models.VectorJSONBody:
		return r.testBody(ctx, client, v, result, violation)
	default:
		return result, nil
	}
}

func (r *schemaTypeRule) testQuery(ctx context.Context, client *anpuhttp.Client, v models.InputVector, result models.ActiveRuleResult, violation string) (models.ActiveRuleResult, error) {
	baseResp, err := client.Get(ctx, v.URL)
	result.RequestsMade++
	if err != nil || baseResp == nil {
		return result, nil
	}
	baseStatus, baseBody := baseResp.StatusCode, strings.ToLower(string(baseResp.Body))

	controlURL, uerr := InjectQueryParam(v.URL, "anpucontrolxyz", "anputest9")
	if uerr != nil {
		return result, nil
	}
	controlResp, err := client.Get(ctx, controlURL)
	result.RequestsMade++
	if err != nil || controlResp == nil {
		return result, nil
	}
	controlStatus, controlBody := controlResp.StatusCode, strings.ToLower(string(controlResp.Body))

	if result.RequestsMade >= r.RequestBudget() {
		return result, nil
	}
	probeURL, uerr := InjectQueryParam(v.URL, v.Name, violation)
	if uerr != nil {
		return result, nil
	}
	probeResp, err := client.Get(ctx, probeURL)
	result.RequestsMade++
	if err != nil || probeResp == nil {
		return result, nil
	}
	probeStatus, probeBody := probeResp.StatusCode, strings.ToLower(string(probeResp.Body))
	if probeStatus == controlStatus && probeBody == controlBody {
		return result, nil // handled exactly like an unknown param
	}
	if isCleanValidation(probeStatus, probeBody) {
		return result, nil // proper 400 validation — correct behavior
	}
	if probeStatus == 500 || (hasMarker(probeBody, schemaErrorMarkers) && probeBody != baseBody) {
		result.Found = true
		result.Payload = v.Name + "=" + violation
		result.Evidence = fmt.Sprintf("schema type-confusion: declared %q got %q → %d (baseline %d, control %d)", v.Schema, violation, probeStatus, baseStatus, controlStatus)
	}
	return result, nil
}

func (r *schemaTypeRule) testBody(ctx context.Context, client *anpuhttp.Client, v models.InputVector, result models.ActiveRuleResult, violation string) (models.ActiveRuleResult, error) {
	baseBody := `{"` + v.Name + `":"baseline-value-anpu"}`
	baseResp, err := client.PostJSON(ctx, v.URL, baseBody, nil)
	result.RequestsMade++
	if err != nil || baseResp == nil {
		return result, nil
	}
	baseStatus, baseLower := baseResp.StatusCode, strings.ToLower(string(baseResp.Body))

	if result.RequestsMade >= r.RequestBudget() {
		return result, nil
	}
	probeBody := `{"` + v.Name + `":` + jsonString(violation) + `}`
	// String violations that are themselves JSON objects stay objects.
	if strings.HasPrefix(violation, "{") {
		probeBody = `{"` + v.Name + `":` + violation + `}`
	}
	probeResp, err := client.PostJSON(ctx, v.URL, probeBody, nil)
	result.RequestsMade++
	if err != nil || probeResp == nil {
		return result, nil
	}
	probeStatus, probeLower := probeResp.StatusCode, strings.ToLower(string(probeResp.Body))
	if probeStatus == baseStatus && probeLower == baseLower {
		return result, nil
	}
	if isCleanValidation(probeStatus, probeLower) {
		return result, nil
	}
	if probeStatus == 500 || hasMarker(probeLower, schemaErrorMarkers) {
		result.Found = true
		result.Payload = probeBody
		result.Evidence = fmt.Sprintf("schema type-confusion (body): declared %q got %q → %d (baseline %d)", v.Schema, violation, probeStatus, baseStatus)
	}
	return result, nil
}

func jsonString(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

func hasMarker(body string, markers []string) bool {
	for _, m := range markers {
		if strings.Contains(body, m) {
			return true
		}
	}
	return false
}

func isCleanValidation(status int, body string) bool {
	if status != 400 && status != 422 {
		return false
	}
	return hasMarker(body, schemaValidationMarkers)
}

func (r *schemaTypeRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	return models.Finding{
		ID:              fmt.Sprintf("active-schematype-%d", time.Now().UnixNano()),
		Title:           fmt.Sprintf("Schema type confusion in %q at %s", res.Vector.Name, res.Vector.URL),
		Description:     fmt.Sprintf("Parameter %q declares schema type %q but a mistyped value (%q) produced a server error instead of clean validation — weak typing plus verbose errors aid exploit development.", res.Vector.Name, res.Vector.Schema, res.Payload),
		Severity:        models.SeverityMedium,
		Confidence:      models.ConfidenceMedium,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-704",
		OWASP:           "A03:2021 - Injection",
		Target:          target,
		URL:             res.Vector.URL,
		Parameter:       res.Vector.Name,
		Source:          models.SourceActive,
		DetectionMethod: "Schema type-confusion probe with baseline + control (baseline-subtracted)",
		Evidence:        models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("mistyped %s", res.Payload)},
		Impact:          "Improper type handling can leak stack traces and enable follow-on injection.",
		Remediation:     "Validate types server-side and return generic 400 errors without internals.",
		FirstSeen:       time.Now(),
	}
}
