package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

// crlfRule detects CRLF injection by injecting a carriage-return + line-feed
// sequence and a unique header name, then checking whether that header
// appears in the response (indicating the CRLF was interpreted as a header
// separator rather than encoded).
//
// Safety: benign — injected header is harmless and GET-only.
type crlfRule struct{}

func (r *crlfRule) ID() models.ActiveRuleID    { return "crlf-injection" }
func (r *crlfRule) Name() string               { return "CRLF / Header Injection" }
func (r *crlfRule) Safety() models.SafetyLevel { return models.SafetyBenign }
func (r *crlfRule) RequestBudget() int         { return 2 }

const (
	crlfCanaryHeader = "X-Anpu-Crlf-Canary"
	crlfCanaryValue  = "detected"
)

var crlfPayloads = []string{
	"\r\n" + crlfCanaryHeader + ": " + crlfCanaryValue,
	"%0d%0a" + crlfCanaryHeader + ": " + crlfCanaryValue,
	"%0D%0A" + crlfCanaryHeader + ": " + crlfCanaryValue,
	"%0d%0a " + crlfCanaryHeader + ": " + crlfCanaryValue,
}

func (r *crlfRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}

	for _, payload := range crlfPayloads {
		if result.RequestsMade >= r.RequestBudget() {
			break
		}
		injected, err := buildInjectedURL(v, payload)
		if err != nil {
			continue
		}
		resp, err := client.Get(ctx, injected)
		result.RequestsMade++
		if err != nil {
			continue
		}

		// Check if our injected header appears in the response headers.
		if resp.Header.Get(crlfCanaryHeader) == crlfCanaryValue {
			result.Found = true
			result.Payload = payload
			result.Evidence = fmt.Sprintf(
				"Injected header %q: %q appeared in response headers after CRLF injection payload (status %d)",
				crlfCanaryHeader, crlfCanaryValue, resp.StatusCode,
			)
			return result, nil
		}

		// Also check the response body for header-splitting evidence.
		body := string(resp.Body)
		if strings.Contains(strings.ToLower(body), strings.ToLower(crlfCanaryHeader)) {
			result.Found = true
			result.Payload = payload
			result.Evidence = fmt.Sprintf(
				"Canary header name %q reflected in response body after CRLF payload (status %d) — possible log injection",
				crlfCanaryHeader, resp.StatusCode,
			)
			return result, nil
		}
	}
	return result, nil
}

func (r *crlfRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	return models.Finding{
		ID:              fmt.Sprintf("active-crlf-%d", time.Now().UnixNano()),
		Title:           fmt.Sprintf("CRLF / header injection in parameter %q at %s", res.Vector.Name, res.Vector.URL),
		Description:     fmt.Sprintf("Parameter %q accepted a CRLF sequence that was interpreted as a header separator, allowing injection of an arbitrary HTTP response header.", res.Vector.Name),
		Severity:        models.SeverityMedium,
		Confidence:      models.ConfidenceHigh,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-113",
		OWASP:           "A03:2021 - Injection",
		Target:          target,
		URL:             res.Vector.URL,
		Parameter:       res.Vector.Name,
		Source:          models.SourceActive,
		DetectionMethod: "CRLF injection probe: canary header injected via %0d%0a appeared in response",
		Evidence:        models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("GET %s (payload in %s)", res.Vector.URL, res.Vector.Name)},
		Impact:          "An attacker can inject arbitrary HTTP response headers, enabling cache poisoning, cookie injection, and XSS via header-based attacks.",
		Remediation:     "Strip or reject CR and LF characters from any user input before including it in HTTP response headers.",
		References:      []string{"https://owasp.org/www-community/vulnerabilities/HTTP_Response_Splitting"},
		FirstSeen:       time.Now(),
	}
}
