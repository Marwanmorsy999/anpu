package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

// cmdInjectionRule detects command injection indicators using error-based
// detection. It injects shell metacharacters and looks for shell error
// messages or timing anomalies in the response.
//
// Safety: low-impact — uses metacharacters that trigger parse errors
// rather than executing commands. No sleep/ping payloads are used
// (those require timing analysis and carry higher risk).
type cmdInjectionRule struct{}

func (r *cmdInjectionRule) ID() models.ActiveRuleID  { return "cmd-injection-indicator" }
func (r *cmdInjectionRule) Name() string             { return "Command Injection Indicator" }
func (r *cmdInjectionRule) Safety() models.SafetyLevel { return models.SafetyLowImpact }
func (r *cmdInjectionRule) RequestBudget() int       { return 2 }

// Payloads use shell metacharacters that cause syntax errors when
// interpolated into a shell command — visible in error output.
var cmdPayloads = []string{
	`|echo anpu-cmdi-canary`,
	`||echo anpu-cmdi-canary`,
	`;echo anpu-cmdi-canary`,
	"`echo anpu-cmdi-canary`",
}

// cmdErrorSignals are error strings that appear when shell metacharacters
// are passed to OS command executors.
var cmdErrorSignals = []string{
	"sh:",
	"/bin/sh",
	"command not found",
	"syntax error",
	"unexpected token",
	"is not recognized as an internal",
	"'echo' is not recognized",
	"anpu-cmdi-canary", // direct execution of our echo
}

func (r *cmdInjectionRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}

	for _, payload := range cmdPayloads {
		if result.RequestsMade >= r.RequestBudget() {
			break
		}
		injected, err := buildInjectedURL(v, v.OriginalValue+payload)
		if err != nil {
			continue
		}
		resp, err := client.Get(ctx, injected)
		result.RequestsMade++
		if err != nil {
			continue
		}
		body := strings.ToLower(string(resp.Body))
		for _, sig := range cmdErrorSignals {
			if strings.Contains(body, strings.ToLower(sig)) {
				result.Found = true
				result.Payload = payload
				result.Evidence = fmt.Sprintf(
					"Command injection signal %q found in response after payload %q injected into parameter %q (status %d)",
					sig, payload, v.Name, resp.StatusCode,
				)
				return result, nil
			}
		}
	}
	return result, nil
}

func (r *cmdInjectionRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	return models.Finding{
		ID: fmt.Sprintf("active-cmdi-%d", time.Now().UnixNano()),
		Title: fmt.Sprintf("Command injection indicator in parameter %q at %s", res.Vector.Name, res.Vector.URL),
		Description: fmt.Sprintf("Shell metacharacters injected into parameter %q produced a shell error message or executed a test command, indicating the value is passed to a system shell without sanitization.", res.Vector.Name),
		Severity: models.SeverityCritical,
		Confidence: models.ConfidenceMedium,
		Category: models.CategoryVulnerability,
		CWE: "CWE-78",
		OWASP: "A03:2021 - Injection",
		Target: target,
		URL: res.Vector.URL,
		Parameter: res.Vector.Name,
		Source: models.SourceActive,
		DetectionMethod: "command injection probe: shell metacharacters triggered error message or command output in response",
		Evidence: models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("GET %s (payload appended to %s)", res.Vector.URL, res.Vector.Name)},
		Impact: "An attacker can execute arbitrary commands on the server operating system, leading to full server compromise.",
		Remediation: "Never pass user input to shell commands. Use language APIs that accept argument lists instead of shell strings. Validate input against strict allowlists.",
		References: []string{"https://owasp.org/www-community/attacks/Command_Injection", "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"},
		FirstSeen: time.Now(),
	}
}
