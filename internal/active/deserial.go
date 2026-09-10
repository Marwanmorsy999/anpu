package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

// deserialRule detects insecure deserialization (CWE-502) via magic-byte probe.
// It sends a base64-encoded Java serialization header (rO0AB) in a body
// parameter and checks for deserialization error disclosures.
//
// Safety: LowImpact — inert serialized stub, no gadget chain execution,
// adversarial-gated via low-confirm confidence.
type deserialRule struct{}

func (r *deserialRule) ID() models.ActiveRuleID    { return "insecure-deserialization" }
func (r *deserialRule) Name() string               { return "Insecure Deserialization" }
func (r *deserialRule) Safety() models.SafetyLevel { return models.SafetyLowImpact }
func (r *deserialRule) RequestBudget() int         { return 3 }

var deserialPayload = "rO0ABXQABWFucHU=" // base64 for Java TC_STRING "anpu" with header

// deserialPayloadForScan returns the Java serialization probe for this
// scan. Ghost mode uses DeserialPayload() (neutral TC_STRING, no `anpu`).
func deserialPayloadForScan() string {
	if !GhostEnabled {
		return deserialPayload
	}
	return DeserialPayload()
}

var deserialSignals = []string{
	"java.io",
	"objectinputstream",
	"deserialization",
	"readobject",
	"invalid stream header",
	"streamcorruptedexception",
	"com.fasterxml.jackson",
	"pickle",
	"unserialize",
}

func (r *deserialRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}
	if !IsAdversarialEnabled() {
		// Low confidence, keep adversarial-gated to avoid noise
		return result, nil
	}
	if v.Kind != models.VectorJSONBody && v.Kind != models.VectorQueryParam && v.Kind != models.VectorHeader {
		return result, nil
	}
	baselineBody := ""
	if result.RequestsMade < r.RequestBudget() {
		if b, ok := deserialBaseline(ctx, client, v); ok {
			baselineBody = strings.ToLower(b)
			result.RequestsMade++
		}
	}
	for _, payload := range []string{deserialPayloadForScan(), "O:8:\"stdClass\":0:{}"} { // Java + PHP stub
		if result.RequestsMade >= r.RequestBudget() {
			break
		}
		body, status, ok := deserialProbe(ctx, client, v, payload)
		result.RequestsMade++
		if !ok {
			continue
		}
		lower := strings.ToLower(body)
		clean := strings.ReplaceAll(lower, strings.ToLower(payload), "")
		for _, sig := range deserialSignals {
			if strings.Contains(clean, sig) && !strings.Contains(baselineBody, sig) {
				result.Found = true
				result.Payload = payload
				result.Evidence = fmt.Sprintf("Deserialization signal %q appeared after payload %q (status %d, baseline absent)", sig, payload, status)
				return result, nil
			}
		}
	}
	return result, nil
}

func deserialBaseline(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (string, bool) {
	if v.Kind == models.VectorJSONBody {
		b, _ := buildJSONBody(v.Name, v.OriginalValue)
		resp, err := client.PostJSON(ctx, v.URL, b, nil)
		if err != nil || resp == nil {
			return "", false
		}
		return string(resp.Body), true
	}
	if v.Kind == models.VectorHeader {
		resp, err := client.DoWithHeaders(ctx, "GET", v.URL, map[string]string{v.Name: v.OriginalValue})
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

func deserialProbe(ctx context.Context, client *anpuhttp.Client, v models.InputVector, payload string) (string, int, bool) {
	switch v.Kind {
	case models.VectorJSONBody:
		b, _ := buildJSONBody(v.Name, payload)
		resp, err := client.PostJSON(ctx, v.URL, b, nil)
		if err != nil || resp == nil {
			return "", 0, false
		}
		return string(resp.Body), resp.StatusCode, true
	case models.VectorHeader:
		resp, err := client.DoWithHeaders(ctx, "GET", v.URL, map[string]string{v.Name: payload})
		if err != nil || resp == nil {
			return "", 0, false
		}
		return string(resp.Body), resp.StatusCode, true
	default:
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
}

func (r *deserialRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	return models.Finding{
		ID:              fmt.Sprintf("active-deserial-%d", time.Now().UnixNano()),
		Title:           fmt.Sprintf("Insecure deserialization at %s (parameter %q)", res.Vector.URL, res.Vector.Name),
		Description:     fmt.Sprintf("Parameter %q caused a deserialization-related error disclosure after injecting %q — the server attempts to deserialize attacker-controlled input without integrity verification. Evidence: %s", res.Vector.Name, res.Payload, res.Evidence),
		Severity:        models.SeverityCritical,
		Confidence:      models.ConfidenceMedium,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-502",
		OWASP:           "A08:2021 - Software and Data Integrity Failures",
		Target:          target,
		URL:             res.Vector.URL,
		Parameter:       res.Vector.Name,
		Source:          models.SourceActive,
		DetectionMethod: "deserialization probe: rO0AB Java header / PHP serialized stub, error disclosure baseline-subtracted",
		Evidence:        models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("GET/POST %s with serialized payload %q", res.Vector.URL, res.Payload)},
		Impact:          "Insecure deserialization can lead to remote code execution, data tampering, and privilege escalation.",
		Remediation:     "Avoid deserializing user-controlled data. Use integrity checks (signatures), allowlists, and safe serialization formats (JSON).",
		References:      []string{"https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"},
		FirstSeen:       time.Now(),
	}
}
