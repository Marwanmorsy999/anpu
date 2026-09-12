package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// rfiRule detects Remote File Inclusion by injecting an external URL and
// checking for inclusion signals — parallel to path_traversal.go (LFI-only).
//
// Safety: LowImpact — fetches a benign canary URL (does not execute).
type rfiRule struct{}

func (r *rfiRule) ID() models.ActiveRuleID    { return "rfi-indicator" }
func (r *rfiRule) Name() string               { return "Remote File Inclusion Indicator" }
func (r *rfiRule) Safety() models.SafetyLevel { return models.SafetyLowImpact }
func (r *rfiRule) RequestBudget() int         { return 3 }

var rfiPayloads = []struct {
	payload string
	signal  string
}{
	{`http://evil.invalid/anpu-rfi-canary`, `anpu-rfi-canary`},
	{`https://evil.invalid/anpu-rfi-canary`, `anpu-rfi-canary`},
	{`//evil.invalid/anpu-rfi-canary`, `anpu-rfi-canary`},
}

// rfiPayloadsForScan returns RFI payloads for this scan. Ghost mode uses
// RFICanaryPath() (no `anpu` substring).
func rfiPayloadsForScan() []struct {
	payload string
	signal  string
} {
	if !GhostEnabled {
		return rfiPayloads
	}
	canary := RFICanaryPath()
	return []struct {
		payload string
		signal  string
	}{
		{`http://evil.invalid/` + canary, canary},
		{`https://evil.invalid/` + canary, canary},
		{`//evil.invalid/` + canary, canary},
	}
}

func (r *rfiRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}
	if v.Kind != models.VectorQueryParam && v.Kind != models.VectorPathSegment && v.Kind != models.VectorJSONBody {
		return result, nil
	}
	baselineBody := ""
	if result.RequestsMade < r.RequestBudget() {
		if b, ok := rfiBaseline(ctx, client, v); ok {
			baselineBody = strings.ToLower(b)
			result.RequestsMade++
		}
	}
	for _, probe := range rfiPayloadsForScan() {
		if result.RequestsMade >= r.RequestBudget() {
			break
		}
		body, status, ok := rfiProbe(ctx, client, v, probe.payload)
		result.RequestsMade++
		if !ok {
			continue
		}
		lower := strings.ToLower(body)
		clean := strings.ReplaceAll(lower, strings.ToLower(probe.payload), "")
		// Signal: canary echoed or include error
		if strings.Contains(clean, probe.signal) && !strings.Contains(baselineBody, probe.signal) {
			result.Found = true
			result.Payload = probe.payload
			result.Evidence = fmt.Sprintf("RFI payload %q reflected with signal %q (status %d, baseline absent)", probe.payload, probe.signal, status)
			return result, nil
		}
		// PHP include error disclosures
		if strings.Contains(clean, "failed to open stream") || strings.Contains(clean, "include(") || strings.Contains(clean, "require(") {
			if !strings.Contains(baselineBody, "failed to open stream") {
				result.Found = true
				result.Payload = probe.payload
				result.Evidence = fmt.Sprintf("RFI payload %q triggered include error disclosure (status %d)", probe.payload, status)
				return result, nil
			}
		}
		// OOB confirmation path when interactsh is available (URL-like only)
		if InteractSession != nil && looksLikeURLParam(v.Name, v.OriginalValue) && result.RequestsMade < r.RequestBudget() {
			nonce := oobNonce("anpurfi")
			oobURL := InteractSession.CallbackURL(nonce)
			if _, _, ok := rfiProbe(ctx, client, v, oobURL); ok {
				result.RequestsMade++
				if proto, remote, ok := InteractSession.WaitForCallback(nonce, oobWait); ok {
					result.Found = true
					result.OOBConfirmed = true
					result.OOBProtocol = proto
					result.OOBRemote = remote
					result.Payload = oobURL
					result.Evidence = fmt.Sprintf("OOB-confirmed RFI: server fetched %s, observed %s from %s", oobURL, proto, remote)
					return result, nil
				}
			}
		}
	}
	return result, nil
}

func rfiBaseline(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (string, bool) {
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

func rfiProbe(ctx context.Context, client *anpuhttp.Client, v models.InputVector, payload string) (string, int, bool) {
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

func (r *rfiRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	severity := models.SeverityCritical
	confidence := models.ConfidenceMedium
	method := "RFI probe: external URL injected, inclusion signal reflected (baseline-subtracted)"
	title := fmt.Sprintf("Remote File Inclusion indicator in parameter %q at %s", res.Vector.Name, res.Vector.URL)
	if res.OOBConfirmed {
		confidence = models.ConfidenceHigh
		title = fmt.Sprintf("Remote File Inclusion confirmed via OOB in parameter %q at %s", res.Vector.Name, res.Vector.URL)
		method = "RFI probe: external URL injected, outbound callback observed (CONFIRMED)"
	}
	return models.Finding{
		ID:              fmt.Sprintf("active-rfi-%d", time.Now().UnixNano()),
		Title:           title,
		Description:     fmt.Sprintf("Parameter %q allowed injection of an external URL %q and the response indicated file inclusion behavior (%s).", res.Vector.Name, res.Payload, res.Evidence),
		Severity:        severity,
		Confidence:      confidence,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-98",
		OWASP:           "A03:2021 - Injection",
		Target:          target,
		URL:             res.Vector.URL,
		Parameter:       res.Vector.Name,
		Source:          models.SourceActive,
		DetectionMethod: method,
		Evidence:        models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("GET %s (payload in %s=%q)", res.Vector.URL, res.Vector.Name, res.Payload)},
		Impact:          "RFI can lead to remote code execution, data disclosure, and server compromise by including attacker-controlled files.",
		Remediation:     "Disable allow_url_include and never pass user input to file inclusion APIs. Validate against an allowlist of permitted files.",
		References:      []string{"https://owasp.org/www-community/attacks/Remote_File_Inclusion"},
		FirstSeen:       time.Now(),
	}
}
