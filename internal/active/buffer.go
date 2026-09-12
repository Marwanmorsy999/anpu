package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// bufferRule detects buffer overflow / denial signals via oversized input.
// It sends a long run of "A" characters and looks for 500-class errors or
// truncation anomalies.
//
// Safety: LowImpact — oversized benign input only, one probe per vector.
type bufferRule struct{}

func (r *bufferRule) ID() models.ActiveRuleID    { return "buffer-overflow-indicator" }
func (r *bufferRule) Name() string               { return "Buffer Overflow Indicator" }
func (r *bufferRule) Safety() models.SafetyLevel { return models.SafetyLowImpact }
func (r *bufferRule) RequestBudget() int         { return 3 }

func (r *bufferRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}
	if v.Kind != models.VectorQueryParam && v.Kind != models.VectorPathSegment && v.Kind != models.VectorJSONBody {
		return result, nil
	}
	baselineResp, err := client.Get(ctx, v.URL)
	result.RequestsMade++
	if err != nil || baselineResp == nil {
		return result, nil
	}
	baselineStatus := baselineResp.StatusCode
	if baselineStatus != 200 {
		return result, nil
	}
	payload := strings.Repeat("A", 10000)
	var resp *anpuhttp.Response
	if v.Kind == models.VectorJSONBody {
		body, _ := buildJSONBody(v.Name, payload)
		resp, err = client.PostJSON(ctx, v.URL, body, nil)
		result.RequestsMade++
	} else {
		inj, e := buildInjectedURL(v, payload)
		if e != nil {
			return result, nil
		}
		resp, err = client.Get(ctx, inj)
		result.RequestsMade++
	}
	if err != nil || resp == nil {
		return result, nil
	}
	// Signal: server error after oversized input (but baseline was 200)
	if resp.StatusCode >= 500 && resp.StatusCode <= 599 {
		result.Found = true
		result.Payload = "A*10000"
		result.Evidence = fmt.Sprintf("Oversized payload (10000 bytes) caused server error %d (baseline 200) — possible buffer handling issue", resp.StatusCode)
		return result, nil
	}
	// Also check for unusually short response (truncation) when baseline had content
	if len(resp.Body) < 20 && len(baselineResp.Body) > 100 {
		result.Found = true
		result.Payload = "A*10000"
		result.Evidence = fmt.Sprintf("Oversized payload caused truncated response (len %d vs %d baseline, status %d)", len(resp.Body), len(baselineResp.Body), resp.StatusCode)
		return result, nil
	}
	return result, nil
}

func (r *bufferRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	return models.Finding{
		ID:              fmt.Sprintf("active-buffer-%d", time.Now().UnixNano()),
		Title:           fmt.Sprintf("Buffer handling anomaly in parameter %q at %s", res.Vector.Name, res.Vector.URL),
		Description:     fmt.Sprintf("Parameter %q showed anomalous behavior after oversized input (%q): %s — the server's buffer handling for large inputs may be insufficiently bounded.", res.Vector.Name, res.Payload, res.Evidence),
		Severity:        models.SeverityMedium,
		Confidence:      models.ConfidenceLow,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-120",
		OWASP:           "A03:2021 - Injection",
		Target:          target,
		URL:             res.Vector.URL,
		Parameter:       res.Vector.Name,
		Source:          models.SourceActive,
		DetectionMethod: "buffer probe: 10000-byte payload, server error or truncation vs 200 baseline",
		Evidence:        models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("GET %s (payload %s in %s)", res.Vector.URL, res.Payload, res.Vector.Name)},
		Impact:          "May indicate insufficient bounds checking, leading to denial of service or memory corruption in native handlers.",
		Remediation:     "Enforce maximum length validation on all user inputs and handle oversized data with explicit errors (413).",
		References:      []string{"https://cwe.mitre.org/data/definitions/120.html"},
		FirstSeen:       time.Now(),
	}
}
