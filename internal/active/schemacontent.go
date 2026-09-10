package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

// schemaContentRule posts the same single-key JSON body under three
// Content-Types (application/json baseline, text/plain, and
// application/x-www-form-urlencoded) plus a garbage-type control. When
// a non-JSON type returns 200 with a body matching the JSON baseline
// while the control differs, the server parses bodies regardless of
// Content-Type — a parsing-confusion primitive (smuggling-adjacent,
// filter bypass).
//
// Safety: Benign — one benign key/value, no state change.
type schemaContentRule struct{}

func (r *schemaContentRule) ID() models.ActiveRuleID    { return "schema-content-confusion" }
func (r *schemaContentRule) Name() string               { return "Schema Content-Type Confusion" }
func (r *schemaContentRule) Safety() models.SafetyLevel { return models.SafetyBenign }
func (r *schemaContentRule) RequestBudget() int         { return 4 }

func (r *schemaContentRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}
	if v.Kind != models.VectorJSONBody {
		return result, nil
	}
	body := `{"` + v.Name + `":"baseline-value-anpu"}`
	baseResp, err := client.PostJSON(ctx, v.URL, body, nil)
	result.RequestsMade++
	if err != nil || baseResp == nil || baseResp.StatusCode != 200 {
		return result, nil // JSON itself not accepted — nothing to confuse
	}
	baseBody := strings.ToLower(string(baseResp.Body))

	probes := []struct {
		label string
		ctype string
	}{
		{"text/plain", "text/plain"},
		{"form-urlencoded", "application/x-www-form-urlencoded"},
	}
	for _, p := range probes {
		if result.RequestsMade >= r.RequestBudget()-1 {
			break
		}
		resp, err := client.PostRaw(ctx, v.URL, p.ctype, body, nil)
		result.RequestsMade++
		if err != nil || resp == nil || resp.StatusCode != 200 {
			continue
		}
		if wordOverlap(strings.ToLower(string(resp.Body)), baseBody) < 0.8 {
			continue
		}
		// Control: garbage content type must NOT parse the same way.
		if result.RequestsMade >= r.RequestBudget() {
			break
		}
		ctrl, err := client.PostRaw(ctx, v.URL, "application/x-anpu-control", body, nil)
		result.RequestsMade++
		if err != nil || ctrl == nil {
			continue
		}
		if ctrl.StatusCode == 200 && wordOverlap(strings.ToLower(string(ctrl.Body)), baseBody) >= 0.8 {
			continue // parses everything — no confusion signal, just lax
		}
		result.Found = true
		result.Payload = "Content-Type: " + p.ctype
		result.Evidence = fmt.Sprintf("content confusion: %s body parsed as JSON (200, %.0f%% overlap); garbage type differs", p.label, wordOverlap(strings.ToLower(string(resp.Body)), baseBody)*100)
		return result, nil
	}
	return result, nil
}

func wordOverlap(a, b string) float64 {
	setA := map[string]struct{}{}
	for _, w := range strings.Fields(a) {
		if len(w) > 2 {
			setA[w] = struct{}{}
		}
	}
	setB := map[string]struct{}{}
	for _, w := range strings.Fields(b) {
		if len(w) > 2 {
			setB[w] = struct{}{}
		}
	}
	if len(setA) == 0 || len(setB) == 0 {
		return 0
	}
	n := 0
	for w := range setA {
		if _, ok := setB[w]; ok {
			n++
		}
	}
	den := len(setA)
	if len(setB) < den {
		den = len(setB)
	}
	return float64(n) / float64(den)
}

func (r *schemaContentRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	return models.Finding{
		ID:              fmt.Sprintf("active-schemacontent-%d", time.Now().UnixNano()),
		Title:           fmt.Sprintf("Content-Type confusion at %s", res.Vector.URL),
		Description:     "The endpoint parses a JSON body sent under a non-JSON Content-Type identically to real JSON, while a garbage type is rejected — content sniffing that desyncs clients, WAFs, and caches that trust the declared type.",
		Severity:        models.SeverityLow,
		Confidence:      models.ConfidenceMedium,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-436",
		OWASP:           "A03:2021 - Injection",
		Target:          target,
		URL:             res.Vector.URL,
		Parameter:       res.Vector.Name,
		Source:          models.SourceActive,
		DetectionMethod: "Content-Type confusion probe with garbage-type control (baseline-subtracted)",
		Evidence:        models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("POST %s", res.Payload)},
		Impact:          "Type confusion lets attackers smuggle JSON past filters keyed on Content-Type.",
		Remediation:     "Reject unexpected Content-Types with 415; parse strictly per declared type.",
		FirstSeen:       time.Now(),
	}
}
