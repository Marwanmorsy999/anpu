package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// ssiRule detects Server-Side Includes injection via directive probes.
// Payloads like <!--#exec cmd="echo anpu"--> surface when the server
// parses SSI without encoding.
//
// Safety: LowImpact — inert directives, no command execution is verified
// beyond reflection of the canary token.
type ssiRule struct{}

func (r *ssiRule) ID() models.ActiveRuleID    { return "ssi-injection" }
func (r *ssiRule) Name() string               { return "Server-Side Includes Injection" }
func (r *ssiRule) Safety() models.SafetyLevel { return models.SafetyLowImpact }
func (r *ssiRule) RequestBudget() int         { return 3 }

var ssiPayloads = []string{
	`<!--#echo var="DATE_LOCAL" -->`,
	`<!--#exec cmd="echo anpu-ssi-canary" -->`,
	`<!--#include virtual="/etc/passwd" -->`,
}

var ssiSignals = []string{
	"anpu-ssi-canary",
	"ssi",
	"server-side include",
}

// ssiPayloadsForScan returns SSI payloads and signals for this scan.
// Ghost mode uses SSICanary() (no `anpu` substring).
func ssiPayloadsForScan() ([]string, []string) {
	if !GhostEnabled {
		return ssiPayloads, ssiSignals
	}
	payload, signal := SSICanary()
	return []string{
			`<!--#echo var="DATE_LOCAL" -->`,
			payload,
			`<!--#include virtual="/etc/passwd" -->`,
		}, []string{
			signal,
			"ssi",
			"server-side include",
		}
}

func (r *ssiRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}
	if v.Kind != models.VectorQueryParam && v.Kind != models.VectorPathSegment && v.Kind != models.VectorJSONBody {
		return result, nil
	}
	baseline := ""
	if result.RequestsMade < r.RequestBudget() {
		if b, ok := ssiBaseline(ctx, client, v); ok {
			baseline = strings.ToLower(b)
			result.RequestsMade++
		}
	}
	payloads, signals := ssiPayloadsForScan()
	for _, payload := range payloads {
		if result.RequestsMade >= r.RequestBudget() {
			break
		}
		body, status, ok := ssiProbe(ctx, client, v, payload)
		result.RequestsMade++
		if !ok {
			continue
		}
		lower := strings.ToLower(body)
		clean := strings.ReplaceAll(lower, strings.ToLower(payload), "")
		for _, sig := range signals {
			if strings.Contains(clean, sig) && !strings.Contains(baseline, strings.ToLower(sig)) {
				result.Found = true
				result.Payload = payload
				result.Evidence = fmt.Sprintf("SSI signal %q appeared after payload %q (status %d)", sig, payload, status)
				return result, nil
			}
		}
		// Direct reflection of the directive pattern suggests parsing
		if strings.Contains(lower, "#exec") || strings.Contains(lower, "#include") {
			if !strings.Contains(baseline, "#exec") && !strings.Contains(baseline, "#include") {
				result.Found = true
				result.Payload = payload
				result.Evidence = fmt.Sprintf("SSI directive %q reflected in response (status %d)", payload, status)
				return result, nil
			}
		}
	}
	return result, nil
}

func ssiBaseline(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (string, bool) {
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

func ssiProbe(ctx context.Context, client *anpuhttp.Client, v models.InputVector, payload string) (string, int, bool) {
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

func (r *ssiRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	return models.Finding{
		ID:              fmt.Sprintf("active-ssi-%d", time.Now().UnixNano()),
		Title:           fmt.Sprintf("Server-Side Includes injection in parameter %q at %s", res.Vector.Name, res.Vector.URL),
		Description:     fmt.Sprintf("Parameter %q reflected an SSI directive after injecting %q — the server parses SSI without neutralizing user input.", res.Vector.Name, res.Payload),
		Severity:        models.SeverityHigh,
		Confidence:      models.ConfidenceMedium,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-97",
		OWASP:           "A03:2021 - Injection",
		Target:          target,
		URL:             res.Vector.URL,
		Parameter:       res.Vector.Name,
		Source:          models.SourceActive,
		DetectionMethod: "SSI probe: directive injection triggered reflection or SSI signal (baseline-subtracted)",
		Evidence:        models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("GET %s (payload in %s=%q)", res.Vector.URL, res.Vector.Name, res.Payload)},
		Impact:          "Attackers can include arbitrary files, execute commands where enabled, and deface the site.",
		Remediation:     "Disable SSI where unused. Encode user input before embedding in responses that may be SSI-parsed.",
		References:      []string{"https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection"},
		FirstSeen:       time.Now(),
	}
}
