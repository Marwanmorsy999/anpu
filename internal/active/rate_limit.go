package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

// rateLimitRule detects missing API rate limiting (CWE-770 / API4:2023).
// It sends 10 rapid GETs to the same endpoint and checks for 429 or
// X-RateLimit-* headers. Absence of throttling is flagged.
//
// Safety: LowImpact — 10 rapid GETs, no state change. Benign.
type rateLimitRule struct{}

func (r *rateLimitRule) ID() models.ActiveRuleID    { return "api-rate-limit-missing" }
func (r *rateLimitRule) Name() string               { return "Missing API Rate Limiting" }
func (r *rateLimitRule) Safety() models.SafetyLevel { return models.SafetyLowImpact }
func (r *rateLimitRule) RequestBudget() int         { return 10 }

func (r *rateLimitRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}
	// Only test query-param vectors that look like API endpoints
	if v.Kind != models.VectorQueryParam && v.Kind != models.VectorPathSegment {
		return result, nil
	}
	lowerURL := strings.ToLower(v.URL)
	if !strings.Contains(lowerURL, "/api") && !strings.Contains(lowerURL, "/v1") && !strings.Contains(lowerURL, "/v2") && !strings.Contains(lowerURL, "/graphql") && v.Kind != models.VectorQueryParam {
		return result, nil
	}
	// Only run on a few endpoints to bound volume — rate-limit is endpoint-wide, not per-param.
	// We run at most once per endpoint; the pipeline's route sampling already bounds it.

	var lastStatus int
	var saw429 bool
	var sawRateLimitHeader bool
	for i := 0; i < 10 && result.RequestsMade < r.RequestBudget(); i++ {
		resp, err := client.Get(ctx, v.URL)
		result.RequestsMade++
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 429 {
			saw429 = true
		}
		if resp.Header.Get("X-RateLimit-Remaining") != "" || resp.Header.Get("X-RateLimit-Limit") != "" || resp.Header.Get("Retry-After") != "" || resp.Header.Get("RateLimit-Remaining") != "" {
			sawRateLimitHeader = true
		}
		lastStatus = resp.StatusCode
		// If we see throttling, stop early — rate limiting is present.
		if saw429 || sawRateLimitHeader {
			return result, nil
		}
		select {
		case <-ctx.Done():
			return result, nil
		default:
		}
	}
	if !saw429 && !sawRateLimitHeader && lastStatus == 200 {
		result.Found = true
		result.Payload = "10x rapid GET"
		result.Evidence = fmt.Sprintf("No rate limiting observed after 10 rapid GETs to %q: no 429, no X-RateLimit-Remaining/Retry-After headers, final status %d. API4:2023 Unrestricted Resource Consumption.", v.URL, lastStatus)
		return result, nil
	}
	return result, nil
}

func (r *rateLimitRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	return models.Finding{
		ID:              fmt.Sprintf("active-ratelimit-%d", time.Now().UnixNano()),
		Title:           fmt.Sprintf("Missing rate limiting at %s", res.Vector.URL),
		Description:     fmt.Sprintf("The API endpoint at %s did not enforce rate limiting after 10 rapid requests — no 429 status or RateLimit headers were observed. Unrestricted consumption can lead to brute-force, scraping, and DoS. Evidence: %s", res.Vector.URL, res.Evidence),
		Severity:        models.SeverityMedium,
		Confidence:      models.ConfidenceLow,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-770",
		OWASP:           "API4:2023 - Unrestricted Resource Consumption",
		Target:          target,
		URL:             res.Vector.URL,
		Source:          models.SourceActive,
		DetectionMethod: "rate-limit probe: 10 rapid GETs, check 429 / X-RateLimit headers",
		Evidence:        models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("10x GET %s", res.Vector.URL)},
		Impact:          "Attackers can abuse the API for credential stuffing, data scraping, or resource exhaustion without throttling.",
		Remediation:     "Implement rate limiting (e.g., token bucket) with 429 responses and RateLimit headers. Enforce per-IP and per-user quotas on sensitive APIs.",
		References:      []string{"https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"},
		FirstSeen:       time.Now(),
	}
}
