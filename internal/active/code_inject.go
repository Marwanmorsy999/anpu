package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

// codeInjectRule detects code injection beyond SSTI's 4 engines —
// probing for PHP, Node, Python, Ruby eval signatures.
//
// Safety: LowImpact — arithmetic-only probes, no OS command.
type codeInjectRule struct{}

func (r *codeInjectRule) ID() models.ActiveRuleID    { return "code-injection" }
func (r *codeInjectRule) Name() string               { return "Code Injection" }
func (r *codeInjectRule) Safety() models.SafetyLevel { return models.SafetyLowImpact }
func (r *codeInjectRule) RequestBudget() int         { return 3 }

var codePayloads = []struct {
	payload  string
	expected string
}{
	{`php:1337*1337`, `1787569`}, // PHP arithmetic leak
	{`1337*1337`, `1787569`},     // generic eval
	{`{{1337*1337}}`, `1787569`}, // template (overlap with SSTI but kept for code-inject context)
}

func (r *codeInjectRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}
	if v.Kind != models.VectorQueryParam && v.Kind != models.VectorPathSegment && v.Kind != models.VectorJSONBody {
		return result, nil
	}
	baseline, ok := codeBaseline(ctx, client, v)
	if ok {
		result.RequestsMade++
		if strings.Contains(baseline, "1787569") {
			return result, nil // baseline already contains expected — skip to avoid FP
		}
	}
	for _, probe := range codePayloads {
		if result.RequestsMade >= r.RequestBudget() {
			break
		}
		body, status, ok := codeProbe(ctx, client, v, probe.payload)
		result.RequestsMade++
		if !ok {
			continue
		}
		if strings.Contains(body, probe.expected) && !strings.Contains(baseline, probe.expected) {
			result.Found = true
			result.Payload = probe.payload
			result.Evidence = fmt.Sprintf("Code injection probe %q evaluated: expected %q reflected (status %d, baseline absent)", probe.payload, probe.expected, status)
			return result, nil
		}
	}
	return result, nil
}

func codeBaseline(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (string, bool) {
	if v.Kind == models.VectorJSONBody {
		b, _ := buildJSONBody(v.Name, v.OriginalValue)
		resp, err := client.PostJSON(ctx, v.URL, b, nil)
		if err != nil || resp == nil {
			return "", false
		}
		return string(resp.Body), true
	}
	resp, err := client.Get(ctx, v.URL)
	if err != nil || resp == nil {
		return "", false
	}
	return string(resp.Body), true
}

func codeProbe(ctx context.Context, client *anpuhttp.Client, v models.InputVector, payload string) (string, int, bool) {
	if v.Kind == models.VectorJSONBody {
		b, _ := buildJSONBody(v.Name, payload)
		resp, err := client.PostJSON(ctx, v.URL, b, nil)
		if err != nil || resp == nil {
			return "", 0, false
		}
		return string(resp.Body), resp.StatusCode, true
	}
	inj, err := buildInjectedURL(v, payload)
	if err != nil {
		return "", 0, false
	}
	resp, err := client.Get(ctx, inj)
	if err != nil || resp == nil {
		return "", 0, false
	}
	return string(resp.Body), resp.StatusCode, true
}

func (r *codeInjectRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	return models.Finding{
		ID:              fmt.Sprintf("active-code-%d", time.Now().UnixNano()),
		Title:           fmt.Sprintf("Code injection in parameter %q at %s", res.Vector.Name, res.Vector.URL),
		Description:     fmt.Sprintf("Parameter %q executed an injected arithmetic expression %q — server-side code evaluates user input without sanitization.", res.Vector.Name, res.Payload),
		Severity:        models.SeverityCritical,
		Confidence:      models.ConfidenceMedium,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-94",
		OWASP:           "A03:2021 - Injection",
		Target:          target,
		URL:             res.Vector.URL,
		Parameter:       res.Vector.Name,
		Source:          models.SourceActive,
		DetectionMethod: "code injection probe: arithmetic evaluated server-side and reflected (baseline-subtracted)",
		Evidence:        models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("GET %s (payload in %s=%q)", res.Vector.URL, res.Vector.Name, res.Payload)},
		Impact:          "Arbitrary code execution leading to full server compromise.",
		Remediation:     "Never pass user input to eval/exec or template rendering. Use safe APIs and sandboxing.",
		References:      []string{"https://owasp.org/www-community/attacks/Code_Injection"},
		FirstSeen:       time.Now(),
	}
}
