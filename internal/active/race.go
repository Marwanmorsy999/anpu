package active

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

// raceRule detects race condition / time-of-check-time-of-use issues.
//
// It sends two concurrent requests with the same payload and checks for
// inconsistent responses (different status/length/CT, or one succeeds while
// other fails) which may indicate non-atomic handling.
// Safety: LowImpact — concurrent GETs only, no state mutation beyond
// what a single GET would do. Budget 8 to allow for baseline + 2×2 race.
type raceRule struct{}

func (r *raceRule) ID() models.ActiveRuleID    { return "race-condition" }
func (r *raceRule) Name() string               { return "Race Condition (Concurrent Requests)" }
func (r *raceRule) Safety() models.SafetyLevel { return models.SafetyLowImpact }
func (r *raceRule) RequestBudget() int         { return 8 }

func (r *raceRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}
	// Only test query params and path segments for race — JSON bodies are less race-prone via GET.
	if v.Kind != models.VectorQueryParam && v.Kind != models.VectorPathSegment {
		return result, nil
	}
	// Baseline: single request to establish normal response
	baseResp, err := client.Get(ctx, v.URL)
	result.RequestsMade++
	if err != nil || baseResp == nil {
		return result, nil
	}
	baseStatus := baseResp.StatusCode
	baseLen := len(baseResp.Body)
	baseCT := strings.ToLower(baseResp.Header.Get("Content-Type"))

	// Create a tampered URL that might trigger race-sensitive code (e.g., coupon apply)
	tamperedURL, err := buildInjectedURL(v, v.OriginalValue+"-race")
	if err != nil {
		tamperedURL = v.URL
	}

	// Launch two concurrent requests
	var wg sync.WaitGroup
	var resp1, resp2 *anpuhttp.Response
	var err1, err2 error
	wg.Add(2)
	go func() {
		defer wg.Done()
		resp1, err1 = client.Get(ctx, tamperedURL)
	}()
	go func() {
		defer wg.Done()
		resp2, err2 = client.Get(ctx, tamperedURL)
	}()
	wg.Wait()
	result.RequestsMade += 2
	if err1 != nil || resp1 == nil || err2 != nil || resp2 == nil {
		return result, nil
	}
	// Check for inconsistency: different status, large length delta, or CT change
	if resp1.StatusCode != resp2.StatusCode {
		result.Found = true
		result.Payload = "concurrent GET ×2"
		result.Evidence = fmt.Sprintf("Race inconsistency: concurrent requests to %q returned status %d vs %d (baseline %d, CT %q vs %q, len %d vs %d). Non-atomic handling suspected.", v.Name, resp1.StatusCode, resp2.StatusCode, baseStatus, resp1.Header.Get("Content-Type"), resp2.Header.Get("Content-Type"), len(resp1.Body), len(resp2.Body))
		return result, nil
	}
	// If both 200 but lengths differ significantly from baseline and each other
	if resp1.StatusCode == 200 && resp2.StatusCode == 200 {
		// If one matches baseline but other diverges, or lengths differ >10%
		lenDiff := absInt(len(resp1.Body) - len(resp2.Body))
		baselineDiff1 := absInt(len(resp1.Body) - baseLen)
		baselineDiff2 := absInt(len(resp2.Body) - baseLen)
		ct1 := strings.ToLower(resp1.Header.Get("Content-Type"))
		ct2 := strings.ToLower(resp2.Header.Get("Content-Type"))
		if ct1 != ct2 || ct1 != baseCT {
			// Only flag if lengths also differ, to avoid false positives from CT alone
			if lenDiff > 50 || baselineDiff1 > 100 || baselineDiff2 > 100 {
				result.Found = true
				result.Payload = "concurrent GET ×2"
				result.Evidence = fmt.Sprintf("Race CT/len variance: %q vs %q (baseline %q), len %d vs %d (baseline %d). Concurrent handling inconsistent.", ct1, ct2, baseCT, len(resp1.Body), len(resp2.Body), baseLen)
				return result, nil
			}
		}
		// Large length divergence between concurrent siblings
		if lenDiff > baseLen/5 && lenDiff > 100 {
			result.Found = true
			result.Payload = "concurrent GET ×2"
			result.Evidence = fmt.Sprintf("Race length divergence: concurrent responses len %d vs %d (baseline %d, status %d). Possible TOCTOU.", len(resp1.Body), len(resp2.Body), baseLen, resp1.StatusCode)
			return result, nil
		}
	}
	return result, nil
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func (r *raceRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	return models.Finding{
		ID:              fmt.Sprintf("active-race-%d", time.Now().UnixNano()),
		Title:           fmt.Sprintf("Possible race condition at %s", res.Vector.URL),
		Description:     fmt.Sprintf("Endpoint at %s returned inconsistent responses for concurrent identical requests (%s). This may indicate a race condition where non-atomic checks allow bypass (e.g., coupon double-use, balance overdraft).", res.Vector.URL, res.Evidence),
		Severity:        models.SeverityMedium,
		Confidence:      models.ConfidenceLow,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-362",
		OWASP:           "A04:2021 - Insecure Design",
		Target:          target,
		URL:             res.Vector.URL,
		Parameter:       res.Vector.Name,
		Source:          models.SourceActive,
		DetectionMethod: "race probe: 2 concurrent GETs via anpuhttp, compare status/len/CT vs baseline",
		Evidence:        models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("GET %s ×2 concurrent", res.Vector.URL)},
		Impact:          "Attackers can exploit timing windows to bypass limits, double-apply discounts, or cause inconsistent state.",
		Remediation:     "Use atomic operations, database transactions with proper isolation, and distributed locks for critical sections.",
		References:      []string{"https://owasp.org/www-community/vulnerabilities/Race_Condition"},
		FirstSeen:       time.Now(),
	}
}
