package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

// sstiRule detects server-side template injection by injecting a math
// expression that template engines evaluate at render time.
// If the arithmetic result appears in the response, the engine executed
// our expression — a high-confidence SSTI signal.
//
// Safety: benign — arithmetic expressions are non-destructive.
type sstiRule struct{}

func (r *sstiRule) ID() models.ActiveRuleID  { return "ssti-math-probe" }
func (r *sstiRule) Name() string             { return "Server-Side Template Injection (Math Probe)" }
func (r *sstiRule) Safety() models.SafetyLevel { return models.SafetyBenign }
func (r *sstiRule) RequestBudget() int       { return 2 }

// Payloads that are evaluated by common template engines.
// The expected output (7777*7777 = 60481729) is unique enough to distinguish
// from coincidental matches.
var sstiPayloads = []struct {
	payload  string
	expected string
}{
	{`{{7777*7777}}`, `60481729`},     // Jinja2, Twig, Pebble
	{`${7777*7777}`, `60481729`},      // FreeMarker, Velocity
	{`<%= 7777*7777 %>`, `60481729`},  // ERB (Ruby)
	{`#{7777*7777}`, `60481729`},      // Thymeleaf
}

func (r *sstiRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}

	for _, probe := range sstiPayloads {
		if result.RequestsMade >= r.RequestBudget() {
			break
		}
		injected, err := buildInjectedURL(v, probe.payload)
		if err != nil {
			continue
		}
		resp, err := client.Get(ctx, injected)
		result.RequestsMade++
		if err != nil {
			continue
		}
		if strings.Contains(string(resp.Body), probe.expected) {
			result.Found = true
			result.Payload = probe.payload
			result.Evidence = fmt.Sprintf(
				"Template expression %q was evaluated server-side: expected output %q found in response (status %d)",
				probe.payload, probe.expected, resp.StatusCode,
			)
			return result, nil
		}
	}
	return result, nil
}

func (r *sstiRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	return models.Finding{
		ID: fmt.Sprintf("active-ssti-%d", time.Now().UnixNano()),
		Title: fmt.Sprintf("Server-side template injection in parameter %q at %s", res.Vector.Name, res.Vector.URL),
		Description: fmt.Sprintf("The template expression %q was evaluated by the server and its arithmetic result appeared in the response, confirming server-side template injection in parameter %q.", res.Payload, res.Vector.Name),
		Severity: models.SeverityCritical,
		Confidence: models.ConfidenceHigh,
		Category: models.CategoryVulnerability,
		CWE: "CWE-94",
		OWASP: "A03:2021 - Injection",
		Target: target,
		URL: res.Vector.URL,
		Parameter: res.Vector.Name,
		Source: models.SourceActive,
		DetectionMethod: "SSTI math-expression probe: arithmetic evaluated server-side and result reflected in response",
		Evidence: models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("GET %s (payload in %s=%q)", res.Vector.URL, res.Vector.Name, res.Payload)},
		Impact: "Remote code execution. An attacker can execute arbitrary code on the server by injecting template directives.",
		Remediation: "Never pass user-controlled input to template rendering functions. Use sandboxed template evaluation or allowlist the set of usable template expressions.",
		References: []string{"https://portswigger.net/web-security/server-side-template-injection", "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection"},
		FirstSeen: time.Now(),
	}
}
