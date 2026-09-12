package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// massAssignRule detects mass-assignment / auto-binding vulnerabilities.
//
// It injects extra JSON fields that should be ignored (role, isAdmin, admin, price)
// into JSON body vectors and checks if the server reflects them or changes
// behavior (status 200 with modified body vs baseline).
// Safety: LowImpact — extra fields are ignored by correct handlers, no state change
// is verified via read-only reflection, not via actual privilege escalation.
type massAssignRule struct{}

func (r *massAssignRule) ID() models.ActiveRuleID    { return "mass-assignment" }
func (r *massAssignRule) Name() string               { return "Mass Assignment (Auto-Binding)" }
func (r *massAssignRule) Safety() models.SafetyLevel { return models.SafetyLowImpact }
func (r *massAssignRule) RequestBudget() int         { return 6 }

var massAssignProbes = []struct {
	field string
	value string
}{
	{"role", "admin"},
	{"isAdmin", "true"},
	{"admin", "true"},
	{"price", "-1"},
}

func (r *massAssignRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}
	if v.Kind != models.VectorJSONBody && v.Kind != models.VectorQueryParam {
		return result, nil
	}
	// Only test JSON bodies for mass assignment — query params are not auto-bound in most frameworks.
	if v.Kind != models.VectorJSONBody {
		return result, nil
	}

	// Baseline: original JSON body
	baseBody, err := buildJSONBody(v.Name, v.OriginalValue)
	if err != nil {
		baseBody = fmt.Sprintf(`{"%s":%q}`, v.Name, v.OriginalValue)
	}
	baseResp, err := client.PostJSON(ctx, v.URL, baseBody, nil)
	result.RequestsMade++
	if err != nil || baseResp == nil {
		return result, nil
	}
	baseStr := strings.ToLower(string(baseResp.Body))
	baseStatus := baseResp.StatusCode

	for _, probe := range massAssignProbes {
		if result.RequestsMade >= r.RequestBudget() {
			break
		}
		// Build JSON with extra field
		probeBody := fmt.Sprintf(`{"%s":%q,"%s":%q}`, v.Name, v.OriginalValue, probe.field, probe.value)
		// For boolean true probes, keep JSON boolean
		if probe.value == "true" {
			probeBody = fmt.Sprintf(`{"%s":%q,"%s":true}`, v.Name, v.OriginalValue, probe.field)
		}
		if probe.field == "price" {
			probeBody = fmt.Sprintf(`{"%s":%q,"%s":%s}`, v.Name, v.OriginalValue, probe.field, probe.value)
		}
		resp, err := client.PostJSON(ctx, v.URL, probeBody, nil)
		result.RequestsMade++
		if err != nil || resp == nil {
			continue
		}
		bodyLower := strings.ToLower(string(resp.Body))
		// Signal: server reflects the injected field name/value, or status changes from 4xx to 200, or body length changes significantly.
		reflects := strings.Contains(bodyLower, strings.ToLower(probe.field)) && strings.Contains(bodyLower, strings.ToLower(probe.value))
		statusChanged := baseStatus != 200 && resp.StatusCode == 200
		// Check for IDOR-like reflection in response (e.g., role field echoed)
		if reflects {
			// Confirm it wasn't already in baseline
			if strings.Contains(baseStr, strings.ToLower(probe.field)) && strings.Contains(baseStr, strings.ToLower(probe.value)) {
				continue
			}
			result.Found = true
			result.Payload = probeBody
			result.Evidence = fmt.Sprintf("Mass-assignment reflection: injected JSON field %q=%q reflected in response (status %d→%d, CT %q, len %d→%d). Server appears to auto-bind extra fields.", probe.field, probe.value, baseStatus, resp.StatusCode, resp.Header.Get("Content-Type"), len(baseResp.Body), len(resp.Body))
			return result, nil
		}
		if statusChanged && strings.Contains(bodyLower, "admin") {
			result.Found = true
			result.Payload = probeBody
			result.Evidence = fmt.Sprintf("Mass-assignment status change: baseline %d → %d after injecting %q=%q (len %d→%d). Possible privilege field accepted.", baseStatus, resp.StatusCode, probe.field, probe.value, len(baseResp.Body), len(resp.Body))
			return result, nil
		}
	}
	return result, nil
}

func (r *massAssignRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	return models.Finding{
		ID:              fmt.Sprintf("active-massassign-%d", time.Now().UnixNano()),
		Title:           fmt.Sprintf("Mass assignment auto-binding at %s", res.Vector.URL),
		Description:     fmt.Sprintf("JSON endpoint at %s auto-bound an extra field (%s) that should have been ignored. The server reflected the injected field in its response, indicating it maps request fields directly to internal objects without allowlisting.", res.Vector.URL, res.Evidence),
		Severity:        models.SeverityHigh,
		Confidence:      models.ConfidenceMedium,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-915",
		OWASP:           "A04:2021 - Insecure Design",
		Target:          target,
		URL:             res.Vector.URL,
		Parameter:       res.Vector.Name,
		Source:          models.SourceActive,
		DetectionMethod: "mass-assignment probe: extra JSON field reflected / status change via anpuhttp",
		Evidence:        models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("POST %s with extra JSON field", res.Vector.URL)},
		Impact:          "Attackers can escalate privileges (e.g., set role=admin, isAdmin=true), modify prices, or overwrite internal fields by adding extra JSON properties.",
		Remediation:     "Use explicit allowlists for bindable fields (e.g., DTOs with only expected properties), never auto-bind request body directly to ORM models, and drop unknown fields.",
		References:      []string{"https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"},
		FirstSeen:       time.Now(),
	}
}
