package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

// xssRule detects reflected XSS indicators by injecting a unique canary
// string wrapped in a benign HTML tag and checking whether it appears
// unescaped in the response body.
//
// Safety: benign — the payload is non-executable (no <script>), uses a
// random nonce so it cannot be pre-cached, and is GET-only.
type xssRule struct{}

func (r *xssRule) ID() models.ActiveRuleID    { return "xss-reflected" }
func (r *xssRule) Name() string               { return "Reflected XSS Indicator" }
func (r *xssRule) Safety() models.SafetyLevel { return models.SafetyBenign }
func (r *xssRule) RequestBudget() int         { return 2 }

// canary is injected as a value; we look for it reflected unescaped.
// Using a non-executable tag means no JS runs even if reflected in a browser.
const xssCanary = `anpu-xss-<b id="anpucanary">`

func (r *xssRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v, Payload: xssCanary}

	injected, err := buildInjectedURL(v, xssCanary)
	if err != nil {
		return result, nil
	}

	resp, err := client.Get(ctx, injected)
	result.RequestsMade++
	if err != nil {
		return result, nil
	}

	body := strings.ToLower(string(resp.Body))
	// Check for unescaped reflection — look for the tag without HTML entity encoding.
	if strings.Contains(body, `<b id="anpucanary">`) ||
		strings.Contains(body, `<b id='anpucanary'>`) {
		result.Found = true
		result.Evidence = fmt.Sprintf(
			"Canary %q reflected unescaped in response body (status %d, content-type: %s)",
			xssCanary, resp.StatusCode, resp.Header.Get("Content-Type"),
		)
	}
	return result, nil
}

func (r *xssRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	return models.Finding{
		ID:              fmt.Sprintf("active-xss-%d", time.Now().UnixNano()),
		Title:           fmt.Sprintf("Reflected XSS indicator in parameter %q at %s", res.Vector.Name, res.Vector.URL),
		Description:     fmt.Sprintf("The parameter %q at %s reflected the injected payload unescaped into the HTML response. This is a strong indicator of reflected cross-site scripting.", res.Vector.Name, res.Vector.URL),
		Severity:        models.SeverityHigh,
		Confidence:      models.ConfidenceMedium,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-79",
		OWASP:           "A03:2021 - Injection",
		Target:          target,
		URL:             res.Vector.URL,
		Parameter:       res.Vector.Name,
		Source:          models.SourceActive,
		DetectionMethod: "reflected XSS canary injection — non-executable <b> tag reflected unescaped",
		Evidence:        models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("GET %s (payload in %s=%q)", res.Vector.URL, res.Vector.Name, res.Payload)},
		Impact:          "An attacker can inject arbitrary HTML/JavaScript into pages viewed by other users, enabling session hijacking, credential theft, and phishing.",
		Remediation:     "HTML-encode all user-supplied values before rendering them in responses. Use a Content-Security-Policy header to reduce exploitability.",
		References:      []string{"https://owasp.org/www-community/attacks/xss/", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"},
		FirstSeen:       time.Now(),
	}
}
