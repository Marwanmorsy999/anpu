package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

// ssrfRule detects SSRF by injecting cloud metadata endpoint URLs into
// parameters and checking for recognisable metadata content in the
// response — and, when an interactsh session is active, by confirming a
// real outbound callback (CONFIRMED, no content match needed).
//
// Safety: low-impact — probes metadata endpoints that are read-only.
// The local network guard in the HTTP client prevents ANPU itself from
// actually contacting internal services during testing.
type ssrfRule struct{}

func (r *ssrfRule) ID() models.ActiveRuleID    { return "ssrf-indicator" }
func (r *ssrfRule) Name() string               { return "SSRF Indicator" }
func (r *ssrfRule) Safety() models.SafetyLevel { return models.SafetyLowImpact }
func (r *ssrfRule) RequestBudget() int         { return 6 }

// ssrfPayloads target well-known cloud metadata endpoints (Master: 3→5).
// GCP (metadata.google.internal) needs Metadata-Flavor: Google,
// Azure (169.254.169.254 with api-version) needs Metadata:true header
// — both are sent in-band when looksLikeURLParam, plus OOB confirmation.
var ssrfPayloads = []string{
	`http://169.254.169.254/latest/meta-data/`,
	`http://100.100.100.200/latest/meta-data/`,
	`http://169.254.169.254/metadata/v1/`,
	`http://metadata.google.internal/computeMetadata/v1/`,
	`http://169.254.169.254/metadata/instance?api-version=2021-02-01`,
}

// ssrfCanary is the single probe used for non-URL-looking parameters.
const ssrfCanary = `http://169.254.169.254/latest/meta-data/hostname`

// ssrfSignals are strings that appear in cloud metadata responses.
var ssrfSignals = []string{
	"ami-id",
	"instance-id",
	"instance-type",
	"computemetadata",
	"metadata-flavor",
	"iam/security-credentials",
	"169.254.169.254",
	"local-ipv4",
	"droplet_id",
}

// maxInbandProbes caps content-match probes so OOB confirmation keeps
// budget headroom. Master: increased to allow header-gated payloads to be tried.
const maxInbandProbes = 5

func (r *ssrfRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}

	// URL-like parameters get the full payload set; anything else gets
	// one canary probe (cheap, occasionally surprising).
	payloads := ssrfPayloads
	if !looksLikeURLParam(v.Name, v.OriginalValue) {
		payloads = []string{ssrfCanary}
	}

	for _, payload := range payloads {
		if result.RequestsMade >= maxInbandProbes {
			break
		}
		body, status, ok := ssrfProbe(ctx, client, v, payload)
		result.RequestsMade++
		if !ok {
			continue
		}
		// Echo guard: exclude our own injected URL from signal matching.
		// A server that reflects the payload would otherwise FP on
		// "169.254.169.254" contained in the echo itself.
		cleanBody := strings.ReplaceAll(body, strings.ToLower(payload), "")
		for _, sig := range ssrfSignals {
			if strings.Contains(cleanBody, sig) {
				result.Found = true
				result.Payload = payload
				result.Evidence = fmt.Sprintf(
					"SSRF signal %q found in response body after injecting metadata URL into parameter %q (status %d)",
					sig, v.Name, status,
				)
				break
			}
		}
		if result.Found {
			break
		}
	}

	// OOB confirmation runs only when in-band was silent: a real outbound
	// callback proves SSRF even when no content is reflected.
	// URL-like vectors only (bounded cost).
	if !result.Found && InteractSession != nil && looksLikeURLParam(v.Name, v.OriginalValue) &&
		result.RequestsMade < r.RequestBudget() {
		nonce := oobNonce("anpussrf")
		if _, _, ok := ssrfProbe(ctx, client, v, InteractSession.CallbackURL(nonce)); ok {
			result.RequestsMade++
			if proto, remote, ok := InteractSession.WaitForCallback(nonce, oobWait); ok {
				result.Found = true
				result.OOBConfirmed = true
				result.OOBProtocol = proto
				result.OOBRemote = remote
				result.Payload = InteractSession.CallbackURL(nonce)
				result.Evidence = fmt.Sprintf(
					"OOB-confirmed SSRF: the server fetched the canary URL (nonce %s); interactsh observed a %s callback from %s. No response-content match was needed.",
					nonce, proto, remote,
				)
			}
		}
	}
	return result, nil
}

// ssrfProbe injects payload at the vector (POST JSON for body vectors,
// URL injection otherwise) and returns the lowercased body + status.
// Header-gated clouds (Master): GCP/Azure payloads are sent with the
// required metadata headers in-band when the vector looks like a URL param,
// matching //metadata.google.internal behavior. OOB still gates when not
// URL-like.
func ssrfProbe(ctx context.Context, client *anpuhttp.Client, v models.InputVector, payload string) (string, int, bool) {
	headers := ssrfHeadersForPayload(payload)
	if v.Kind == models.VectorJSONBody {
		jsonBody, err := buildJSONBody(v.Name, payload)
		if err != nil {
			return "", 0, false
		}
		var resp *anpuhttp.Response
		var err2 error
		if len(headers) > 0 {
			// JSON body with header-gated probe uses DoWithHeaders semantics via PostJSON with extra headers
			resp, err2 = client.PostJSON(ctx, v.URL, jsonBody, headers)
		} else {
			resp, err2 = client.PostJSON(ctx, v.URL, jsonBody, nil)
		}
		if err2 != nil || resp == nil {
			return "", 0, false
		}
		return strings.ToLower(string(resp.Body)), resp.StatusCode, true
	}
	injected, err := buildInjectedURL(v, payload)
	if err != nil {
		return "", 0, false
	}
	var resp *anpuhttp.Response
	if len(headers) > 0 && looksLikeURLParam(v.Name, v.OriginalValue) {
		resp, err = client.DoWithHeaders(ctx, "GET", injected, headers)
	} else {
		resp, err = client.Get(ctx, injected)
	}
	if err != nil || resp == nil {
		return "", 0, false
	}
	return strings.ToLower(string(resp.Body)), resp.StatusCode, true
}

// ssrfHeadersForPayload returns the required headers for header-gated cloud metadata.
func ssrfHeadersForPayload(payload string) map[string]string {
	lower := strings.ToLower(payload)
	if strings.Contains(lower, "metadata.google.internal") {
		return map[string]string{"Metadata-Flavor": "Google"}
	}
	if strings.Contains(lower, "169.254.169.254/metadata/instance") {
		return map[string]string{"Metadata": "true"}
	}
	return nil
}

// looksLikeURLParam returns true when the parameter name or value suggests
// it accepts a URL — a prerequisite for SSRF being likely.
func looksLikeURLParam(name, value string) bool {
	lower := strings.ToLower(name)
	for _, kw := range []string{"url", "uri", "link", "src", "source", "redirect", "callback", "webhook", "endpoint", "host", "proxy", "fetch", "load", "file", "path", "target", "dest"} {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") || strings.HasPrefix(value, "//")
}

func (r *ssrfRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	severity := models.SeverityCritical
	confidence := models.ConfidenceLow
	title := fmt.Sprintf("SSRF indicator in parameter %q at %s", res.Vector.Name, res.Vector.URL)
	description := fmt.Sprintf("Parameter %q accepted a cloud metadata URL and the server's response contained metadata content, indicating it made an outbound request to the injected URL (Server-Side Request Forgery).", res.Vector.Name)
	method := "SSRF probe: cloud metadata endpoint injected into URL-like parameter, metadata content found in response"
	if res.OOBConfirmed {
		confidence = models.ConfidenceHigh
		title = fmt.Sprintf("SSRF confirmed via out-of-band callback in parameter %q at %s", res.Vector.Name, res.Vector.URL)
		description = fmt.Sprintf("Parameter %q caused the server to make an outbound request to an attacker-influenced URL: the injected canary triggered a %s callback from %s observed by the OOB listener. This proves Server-Side Request Forgery with no reliance on reflected content.", res.Vector.Name, res.OOBProtocol, res.OOBRemote)
		method = "SSRF probe: canary URL injected, outbound callback observed out-of-band (CONFIRMED)"
	}
	summary := fmt.Sprintf("GET %s (payload in %s=%q)", res.Vector.URL, res.Vector.Name, res.Payload)
	if res.Vector.Kind == models.VectorJSONBody {
		summary = fmt.Sprintf("POST %s (JSON body key %s=%q)", res.Vector.URL, res.Vector.Name, res.Payload)
	}
	return models.Finding{
		ID:              fmt.Sprintf("active-ssrf-%d", time.Now().UnixNano()),
		Title:           title,
		Description:     description,
		Severity:        severity,
		Confidence:      confidence,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-918",
		OWASP:           "A10:2021 - Server-Side Request Forgery",
		Target:          target,
		URL:             res.Vector.URL,
		Parameter:       res.Vector.Name,
		Source:          models.SourceActive,
		DetectionMethod: method,
		Evidence:        models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: summary},
		Impact:          "An attacker can make the server contact internal services, cloud metadata endpoints, and other infrastructure, enabling credential theft, lateral movement, and data exfiltration.",
		Remediation:     "Validate and allowlist outbound URL destinations. Block access to cloud metadata IP ranges (169.254.169.254) at the network level. Use IMDSv2 with token requirement on AWS.",
		References:      []string{"https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/", "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"},
		FirstSeen:       time.Now(),
	}
}
