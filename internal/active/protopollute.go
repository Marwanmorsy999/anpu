package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// protoPolluteRule detects prototype pollution via JSON __proto__ / constructor.prototype injection.
//
// It injects `{"__proto__":{"polluted":"anpu"}}` or `{"constructor":{"prototype":{"polluted":"anpu"}}}` into JSON bodies
// and checks if the server reflects the polluted property or behaves differently.
// Safety: LowImpact — polluted property is a harmless canary string, no prototype is actually polluted server-side beyond the request scope.
type protoPolluteRule struct{}

func (r *protoPolluteRule) ID() models.ActiveRuleID    { return "prototype-pollution" }
func (r *protoPolluteRule) Name() string               { return "Prototype Pollution (JSON __proto__)" }
func (r *protoPolluteRule) Safety() models.SafetyLevel { return models.SafetyLowImpact }
func (r *protoPolluteRule) RequestBudget() int         { return 6 }

var protoPayloads = []string{
	`{"__proto__":{"anpu_polluted":"true"}}`,
	`{"constructor":{"prototype":{"anpu_polluted":"true"}}}`,
	`{"__proto__":{"toString":"polluted"}}`,
}

func (r *protoPolluteRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}
	if v.Kind != models.VectorJSONBody {
		return result, nil
	}
	// Baseline
	baseBody, _ := buildJSONBody(v.Name, v.OriginalValue)
	if baseBody == "" {
		baseBody = fmt.Sprintf(`{"%s":%q}`, v.Name, v.OriginalValue)
	}
	baseResp, err := client.PostJSON(ctx, v.URL, baseBody, nil)
	result.RequestsMade++
	if err != nil || baseResp == nil {
		return result, nil
	}
	baseLower := strings.ToLower(string(baseResp.Body))

	for _, payload := range protoPayloads {
		if result.RequestsMade >= r.RequestBudget() {
			break
		}
		// Merge payload with original field to keep it valid JSON
		// e.g., {"<orig>":"val", "__proto__":{...}}
		merged := fmt.Sprintf(`{"%s":%q`, v.Name, v.OriginalValue)
		inner := strings.TrimPrefix(payload, "{")
		inner = strings.TrimSuffix(inner, "}")
		if inner != "" {
			merged += "," + inner
		}
		merged += "}"
		resp, err := client.PostJSON(ctx, v.URL, merged, nil)
		result.RequestsMade++
		if err != nil || resp == nil {
			continue
		}
		bodyLower := strings.ToLower(string(resp.Body))
		// Signal 1: server reflects the polluted property name/value
		if strings.Contains(bodyLower, "anpu_polluted") && !strings.Contains(baseLower, "anpu_polluted") {
			result.Found = true
			result.Payload = payload
			result.Evidence = fmt.Sprintf("Prototype pollution reflection: payload %q reflected in response (status %d, CT %q, len %d→%d). Server merged __proto__ into object.", payload, resp.StatusCode, resp.Header.Get("Content-Type"), len(baseResp.Body), len(resp.Body))
			return result, nil
		}
		// Signal 2: server returns 500 or behaves differently when __proto__ is present (e.g., crashes due to pollution)
		if resp.StatusCode >= 500 && baseResp.StatusCode < 500 {
			result.Found = true
			result.Payload = payload
			result.Evidence = fmt.Sprintf("Prototype pollution caused status %d (baseline %d) with payload %q (CT %q). Server may have polluted Object prototype and crashed.", resp.StatusCode, baseResp.StatusCode, payload, resp.Header.Get("Content-Type"))
			return result, nil
		}
		// Signal 3: response contains polluted property in JSON output that wasn't in baseline
		if strings.Contains(bodyLower, "polluted") && !strings.Contains(baseLower, "polluted") {
			result.Found = true
			result.Payload = payload
			result.Evidence = fmt.Sprintf("Polluted string in response after %q (status %d, len %d→%d)", payload, resp.StatusCode, len(baseResp.Body), len(resp.Body))
			return result, nil
		}
	}
	return result, nil
}

func (r *protoPolluteRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	return models.Finding{
		ID:              fmt.Sprintf("active-protopollute-%d", time.Now().UnixNano()),
		Title:           fmt.Sprintf("Prototype pollution via JSON __proto__ at %s", res.Vector.URL),
		Description:     fmt.Sprintf("JSON endpoint at %s merged a __proto__ / constructor.prototype payload (%s) into its object graph. The server reflected the polluted property or crashed, indicating it does not guard against prototype pollution. Attackers can pollute Object.prototype to bypass auth, cause DoS, or achieve RCE in some contexts.", res.Vector.URL, res.Evidence),
		Severity:        models.SeverityHigh,
		Confidence:      models.ConfidenceMedium,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-1321",
		OWASP:           "A03:2021 - Injection",
		Target:          target,
		URL:             res.Vector.URL,
		Parameter:       res.Vector.Name,
		Source:          models.SourceActive,
		DetectionMethod: "prototype pollution probe: __proto__/constructor.prototype JSON via anpuhttp, reflected vs baseline",
		Evidence:        models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("POST %s with __proto__ payload", res.Vector.URL)},
		Impact:          "Attackers can pollute prototypes to modify application behavior, bypass security checks, cause DoS, or in Node.js achieve remote code execution via gadget chains.",
		Remediation:     "Use Object.create(null) for dictionaries, freeze prototypes, validate JSON keys and reject __proto__/constructor/prototype, or use a library that sanitizes them.",
		References:      []string{"https://owasp.org/www-community/vulnerabilities/Prototype_Pollution", "https://cwe.mitre.org/data/definitions/1321.html"},
		FirstSeen:       time.Now(),
	}
}
