package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// ldapRule detects LDAP injection via error and bypass signals.
// Payloads like *)(uid=*) or * trigger LDAP parse errors that surface in
// application responses when the filter is not neutralized.
//
// Safety: LowImpact — read-only filter probes, no data exfiltration attempts.
type ldapRule struct{}

func (r *ldapRule) ID() models.ActiveRuleID    { return "ldap-injection" }
func (r *ldapRule) Name() string               { return "LDAP Injection" }
func (r *ldapRule) Safety() models.SafetyLevel { return models.SafetyLowImpact }
func (r *ldapRule) RequestBudget() int         { return 3 }

var ldapPayloads = []string{
	`*)(uid=*))(|(uid=*`,
	`*`,
	`*)(objectClass=*`,
}

var ldapSignals = []string{
	"ldap",
	"search filter",
	"invalid dn syntax",
	"bad search filter",
	"ldap_error",
	"javax.naming",
}

func (r *ldapRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}
	if v.Kind != models.VectorQueryParam && v.Kind != models.VectorPathSegment && v.Kind != models.VectorJSONBody {
		return result, nil
	}
	baselineBody := ""
	if result.RequestsMade < r.RequestBudget() {
		body, ok := ldapBaseline(ctx, client, v)
		result.RequestsMade++
		if ok {
			baselineBody = strings.ToLower(body)
		}
	}
	for _, payload := range ldapPayloads {
		if result.RequestsMade >= r.RequestBudget() {
			break
		}
		body, status, ok := ldapProbe(ctx, client, v, payload)
		result.RequestsMade++
		if !ok {
			continue
		}
		lower := strings.ToLower(body)
		// Echo guard: skip if response merely echoed payload
		clean := strings.ReplaceAll(lower, strings.ToLower(payload), "")
		// Baseline-subtract: signal must be new
		for _, sig := range ldapSignals {
			if strings.Contains(clean, sig) && !strings.Contains(baselineBody, sig) {
				result.Found = true
				result.Payload = payload
				result.Evidence = fmt.Sprintf("LDAP injection signal %q appeared after payload %q (status %d, baseline absent)", sig, payload, status)
				return result, nil
			}
		}
		// Reflection of wildcard without filtering is also a candidate (low confidence)
		if strings.Contains(clean, "uid=*") || strings.Contains(clean, "objectclass") {
			if !strings.Contains(baselineBody, "uid=*") {
				result.Found = true
				result.Payload = payload
				result.Evidence = fmt.Sprintf("LDAP filter payload %q reflected in response (status %d) — filter not neutralized", payload, status)
				return result, nil
			}
		}
	}
	return result, nil
}

func ldapBaseline(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (string, bool) {
	if v.Kind == models.VectorJSONBody {
		body, _ := buildJSONBody(v.Name, v.OriginalValue)
		resp, err := client.PostJSON(ctx, v.URL, body, nil)
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

func ldapProbe(ctx context.Context, client *anpuhttp.Client, v models.InputVector, payload string) (string, int, bool) {
	if v.Kind == models.VectorJSONBody {
		b, _ := buildJSONBody(v.Name, payload)
		resp, err := client.PostJSON(ctx, v.URL, b, nil)
		if err != nil || resp == nil {
			return "", 0, false
		}
		return string(resp.Body), resp.StatusCode, true
	}
	injected, err := buildInjectedURL(v, payload)
	if err != nil {
		return "", 0, false
	}
	resp, err := client.Get(ctx, injected)
	if err != nil || resp == nil {
		return "", 0, false
	}
	return string(resp.Body), resp.StatusCode, true
}

func (r *ldapRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	return models.Finding{
		ID:              fmt.Sprintf("active-ldap-%d", time.Now().UnixNano()),
		Title:           fmt.Sprintf("LDAP injection in parameter %q at %s", res.Vector.Name, res.Vector.URL),
		Description:     fmt.Sprintf("Parameter %q provoked an LDAP-related error or reflection after injecting filter metacharacters %q — the application's LDAP filter does not neutralize user input.", res.Vector.Name, res.Payload),
		Severity:        models.SeverityHigh,
		Confidence:      models.ConfidenceMedium,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-90",
		OWASP:           "A03:2021 - Injection",
		Target:          target,
		URL:             res.Vector.URL,
		Parameter:       res.Vector.Name,
		Source:          models.SourceActive,
		DetectionMethod: "LDAP injection probe: filter metacharacters triggered LDAP error or reflection (baseline-subtracted)",
		Evidence:        models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("GET %s (payload in %s=%q)", res.Vector.URL, res.Vector.Name, res.Payload)},
		Impact:          "Attackers can bypass authentication, enumerate directory entries, and extract sensitive LDAP data.",
		Remediation:     "Use parameterized LDAP queries / proper filter escaping (RFC 4515). Never concatenate user input into LDAP filters.",
		References:      []string{"https://owasp.org/www-community/attacks/LDAP_Injection", "https://cwe.mitre.org/data/definitions/90.html"},
		FirstSeen:       time.Now(),
	}
}
