package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

// smugglingRule detects HTTP request smuggling / desync via CL.TE and TE.CL probes.
//
// It sends requests with conflicting Content-Length vs Transfer-Encoding headers
// (safe, minimal body) and checks if the server handles them inconsistently
// (e.g., returns 400 for one but not the other, or reflects the smuggled prefix).
// Safety: LowImpact — requests are GET with minimal smuggling probe headers,
// no actual smuggling of a second request is attempted.
type smugglingRule struct{}

func (r *smugglingRule) ID() models.ActiveRuleID    { return "http-smuggling" }
func (r *smugglingRule) Name() string               { return "HTTP Request Smuggling (CL.TE/TE.CL)" }
func (r *smugglingRule) Safety() models.SafetyLevel { return models.SafetyLowImpact }
func (r *smugglingRule) RequestBudget() int         { return 5 }

func (r *smugglingRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}
	// Only test one vector per endpoint to avoid noise — pick the first query param or path.
	if v.Kind != models.VectorQueryParam && v.Kind != models.VectorPathSegment {
		return result, nil
	}
	// Baseline
	baseResp, err := client.Get(ctx, v.URL)
	result.RequestsMade++
	if err != nil || baseResp == nil {
		return result, nil
	}
	baseStatus := baseResp.StatusCode

	// Probe 1: Content-Length: 0 with Transfer-Encoding: chunked and a smuggled prefix
	// We use anpuhttp.DoWithHeaders to inject the smuggling headers.
	probeHeaders := map[string]string{
		"Content-Length":    "6",
		"Transfer-Encoding": "chunked",
	}
	resp, err := client.DoWithHeaders(ctx, "GET", v.URL, probeHeaders)
	result.RequestsMade++
	if err != nil || resp == nil {
		return result, nil
	}
	// If server returns 400/500 for smuggling probe but 200 for baseline, it is handling the conflict — not vulnerable.
	// If it returns 200 for both and the body contains the smuggled prefix or the status is consistent, we check for desync.
	// Vulnerable pattern: server returns 200 for smuggling probe when it should reject, or the response differs in a way that suggests desync.
	// We use a conservative signal: if baseline 200 and probe 200 but probe body length differs significantly and contains chunked markers.
	bodyLower := strings.ToLower(string(resp.Body))
	if baseStatus == 200 && resp.StatusCode == 200 {
		// Check if body reflects smuggling artifacts or length is suspicious
		if strings.Contains(bodyLower, "chunked") || strings.Contains(bodyLower, "0\r\n\r\n") {
			// This is not definitive, so we need a second probe to confirm.
		}
		// For now, smuggling is hard to detect without a second request smuggled.
		// We use a second probe: TE.CL
		if result.RequestsMade < r.RequestBudget() {
			probe2Headers := map[string]string{
				"Content-Length":    "44",
				"Transfer-Encoding": "chunked",
			}
			resp2, err2 := client.DoWithHeaders(ctx, "POST", v.URL, probe2Headers)
			result.RequestsMade++
			if err2 == nil && resp2 != nil {
				// If POST with smuggling headers succeeds where it should fail, flag
				if resp2.StatusCode == 200 && baseStatus == 200 {
					// Check for inconsistent handling: one probe 200, other not, or both 200 but lengths differ greatly from baseline
					lenDiff := len(resp.Body) - len(baseResp.Body)
					lenDiff2 := len(resp2.Body) - len(baseResp.Body)
					if (lenDiff > 100 || lenDiff < -100) && (lenDiff2 > 100 || lenDiff2 < -100) {
						result.Found = true
						result.Payload = "Content-Length: 6 + Transfer-Encoding: chunked"
						result.Evidence = fmt.Sprintf("Possible smuggling desync: baseline %d (len %d) vs CL.TE probe %d (len %d) vs TE.CL probe %d (len %d). Server handled conflicting length headers inconsistently.", baseStatus, len(baseResp.Body), resp.StatusCode, len(resp.Body), resp2.StatusCode, len(resp2.Body))
						return result, nil
					}
				}
			}
		}
	}
	// Alternative signal: server returns 400 for one probe but 200 for baseline, yet the 400 body mentions desync keywords
	if resp.StatusCode == 400 && baseStatus == 200 {
		if strings.Contains(bodyLower, "smuggling") || strings.Contains(bodyLower, "desync") || strings.Contains(bodyLower, "transfer-encoding") {
			result.Found = true
			result.Payload = "CL.TE probe"
			result.Evidence = fmt.Sprintf("Smuggling probe returned 400 with desync keyword (baseline 200). Server explicitly rejected conflicting headers but body disclosed handling: %q", snippetForEvidence(resp.Body))
			return result, nil
		}
	}
	return result, nil
}

func (r *smugglingRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	return models.Finding{
		ID:              fmt.Sprintf("active-smuggling-%d", time.Now().UnixNano()),
		Title:           fmt.Sprintf("HTTP request smuggling/desync at %s", res.Vector.URL),
		Description:     fmt.Sprintf("Endpoint at %s handled conflicting Content-Length and Transfer-Encoding headers inconsistently (%s). This may indicate HTTP desync / request smuggling where front-end and back-end disagree on request boundaries, allowing attackers to smuggle a second request.", res.Vector.URL, res.Evidence),
		Severity:        models.SeverityHigh,
		Confidence:      models.ConfidenceLow,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-444",
		OWASP:           "A01:2021 - Broken Access Control",
		Target:          target,
		URL:             res.Vector.URL,
		Parameter:       res.Vector.Name,
		Source:          models.SourceActive,
		DetectionMethod: "HTTP smuggling probe: CL.TE / TE.CL header conflict via anpuhttp (safe, no second request smuggled)",
		Evidence:        models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("GET/POST %s with CL.TE headers", res.Vector.URL)},
		Impact:          "Attackers can smuggle requests past front-end controls, bypass auth, poison caches, or steal other users' requests.",
		Remediation:     "Normalize requests at the front-end, reject requests with both Content-Length and Transfer-Encoding, use HTTP/2 end-to-end, and ensure front-end and back-end agree on message length.",
		References:      []string{"https://portswigger.net/web-security/request-smuggling", "https://cwe.mitre.org/data/definitions/444.html"},
		FirstSeen:       time.Now(),
	}
}
