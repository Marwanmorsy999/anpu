package active

// host_header.go — Host Header Injection active rule.
//
// Host Header Injection (also called HTTP Host Header attacks) occurs when an
// application uses the HTTP Host header in security-sensitive operations —
// most commonly password reset link generation — without validating it against
// an allowlist of known-good values.  An attacker who forges the Host header
// can poison the generated URL so it points to an attacker-controlled domain,
// enabling:
//
//   - Password reset link poisoning (highest-impact, most common exploit)
//   - Cache poisoning (if a caching proxy reflects the Host into a cache key
//     or cached response)
//   - SSRF via internal routing that trusts the Host header
//   - Open redirect when Location headers echo the Host
//
// Detection approach (safe, reflection-based):
//
//  1. Send a GET with Host: <canary> and X-Forwarded-Host: <canary> where
//     <canary> is a nonce-suffixed subdomain of a non-existent TLD.
//  2. If the canary string appears verbatim in the response body → High
//     confidence reflection finding.
//  3. If the canary appears in a Location redirect header → High confidence
//     (open redirect via Host header — classic password-reset poisoning path).
//  4. Make at most 2 requests: baseline GET + poisoned GET.
//
// Safety: the canary domain does not resolve (non-existent TLD) and the rule
// never submits forms or triggers mutations.
//
// CWE-20: Improper Input Validation (Host header not validated)
// OWASP A03:2021 — Injection

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

type hostHeaderRule struct{}

func (r *hostHeaderRule) ID() models.ActiveRuleID    { return "host-header-injection" }
func (r *hostHeaderRule) Name() string               { return "Host Header Injection" }
func (r *hostHeaderRule) Safety() models.SafetyLevel { return models.SafetyBenign }
func (r *hostHeaderRule) RequestBudget() int         { return 2 }

// hostNonce generates a random canary subdomain label.
func hostNonce() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "anpu-canary-fallback"
	}
	return "anpu-" + hex.EncodeToString(b) + ".invalid"
}

func (r *hostHeaderRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}

	// Only test page-level vectors — skip XML body and header vectors which
	// have their own targeted rules.
	if v.Kind != models.VectorQueryParam && v.Kind != models.VectorPathSegment {
		return result, nil
	}

	canary := hostNonce()
	result.Payload = canary

	// Request 1: baseline (used only to establish that the endpoint responds).
	_, _ = client.Get(ctx, v.URL)
	result.RequestsMade++

	// Request 2: forged Host + X-Forwarded-Host.
	extra := map[string]string{
		"X-Forwarded-Host": canary,
		"X-Forwarded-For":  "127.0.0.1",
	}
	probeResp, probeErr := client.GetWithHost(ctx, v.URL, canary, extra)
	result.RequestsMade++
	if probeErr != nil {
		return result, nil
	}

	probeBody := string(probeResp.Body)

	// Signal 1: canary reflected in body.
	if strings.Contains(probeBody, canary) {
		result.Found = true
		result.Evidence = fmt.Sprintf(
			"Host header canary %q reflected in response body (status %d). "+
				"The application echoes the Host header into the response without validation.",
			canary, probeResp.StatusCode,
		)
		return result, nil
	}

	// Signal 2: canary in Location redirect header OR in final redirected URL.
	// The HTTP client follows redirects; check both the raw Location header
	// (present if the server sent it before the final hop) and the FinalURL
	// (where the client ended up after following redirects).
	loc := probeResp.Header.Get("Location")
	finalURL := probeResp.FinalURL
	if (loc != "" && strings.Contains(strings.ToLower(loc), strings.ToLower(canary))) ||
		strings.Contains(strings.ToLower(finalURL), strings.ToLower(canary)) {
		evidence := loc
		if evidence == "" {
			evidence = finalURL
		}
		result.Found = true
		result.Evidence = fmt.Sprintf(
			"Host header canary %q appeared in Location redirect header: %q (status %d). "+
				"This enables password-reset link poisoning — an attacker can redirect victims to an attacker-controlled domain.",
			canary, evidence, probeResp.StatusCode,
		)
		return result, nil
	}

	// Signal 3: forged Host caused a Location redirect containing the canary
	// in a header we haven't checked yet — already handled above.
	// No additional signals without OOB infrastructure.

	return result, nil
}

func (r *hostHeaderRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	confidence := models.ConfidenceHigh
	severity := models.SeverityHigh

	// Location-based reflection is the most dangerous (password reset poisoning).
	impact := "An attacker can poison password reset emails to redirect victims to an " +
		"attacker-controlled domain, capturing reset tokens. May also enable web cache poisoning " +
		"and internal SSRF if the Host header is used in backend routing."

	if strings.Contains(res.Evidence, "Location redirect") {
		impact = "Password reset link poisoning confirmed path: forged Host header appears in Location redirect. " +
			"An attacker who intercepts a password reset request (or triggers one themselves) can redirect " +
			"the victim's browser to attacker.example.com and steal the reset token."
	}

	return models.Finding{
		ID: fmt.Sprintf("active-host-header-%d", time.Now().UnixNano()),
		Title: fmt.Sprintf(
			"Host Header Injection at %s", res.Vector.URL,
		),
		Description: fmt.Sprintf(
			"The endpoint at %s uses the HTTP Host header in its response without validating it against an allowlist. "+
				"An attacker can forge the Host header (or set X-Forwarded-Host) to inject an arbitrary domain "+
				"into the application's response — most critically into password reset links, canonical URL generation, "+
				"and cache keys. Detection: %s",
			res.Vector.URL, res.Evidence,
		),
		Severity:        severity,
		Confidence:      confidence,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-20",
		OWASP:           "A03:2021 - Injection",
		Target:          target,
		URL:             res.Vector.URL,
		Parameter:       "Host header / X-Forwarded-Host header",
		Source:          models.SourceActive,
		DetectionMethod: "Forged Host header + X-Forwarded-Host with nonce canary; detected via body/redirect reflection",
		Evidence: models.Evidence{
			Observed:       res.Evidence,
			Location:       res.Vector.URL,
			RequestSummary: fmt.Sprintf("GET %s (Host: %s, X-Forwarded-Host: %s)", res.Vector.URL, res.Payload, res.Payload),
		},
		Impact: impact,
		Remediation: "Validate the Host header against a hard-coded allowlist of acceptable values before using it " +
			"in any URL generation, redirect, or cache key. In most frameworks: configure a list of ALLOWED_HOSTS " +
			"(Django), server_name (nginx), or ServerName/ServerAlias (Apache). Never use the Host header to " +
			"construct URLs in password reset emails — use a configured base URL instead.",
		References: []string{
			"https://portswigger.net/web-security/host-header",
			"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection",
			"https://cwe.mitre.org/data/definitions/20.html",
		},
		FirstSeen: time.Now(),
	}
}
