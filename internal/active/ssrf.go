package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

// ssrfRule detects SSRF indicators by injecting cloud metadata endpoint
// URLs into URL-like parameters and checking for recognisable metadata
// content in the response (error messages, IP ranges, or metadata keys).
//
// Safety: low-impact — probes metadata endpoints that are read-only.
// The local network guard in the HTTP client prevents ANPU itself from
// actually contacting internal services during testing.
type ssrfRule struct{}

func (r *ssrfRule) ID() models.ActiveRuleID  { return "ssrf-indicator" }
func (r *ssrfRule) Name() string             { return "SSRF Indicator" }
func (r *ssrfRule) Safety() models.SafetyLevel { return models.SafetyLowImpact }
func (r *ssrfRule) RequestBudget() int       { return 3 }

// ssrfPayloads target well-known cloud metadata endpoints.
var ssrfPayloads = []string{
	`http://169.254.169.254/latest/meta-data/`,
	`http://metadata.google.internal/computeMetadata/v1/`,
	`http://169.254.169.254/metadata/instance`,
	`http://[::ffff:169.254.169.254]/latest/meta-data/`,
}

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
}

func (r *ssrfRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}

	// SSRF is most useful when the parameter looks like a URL or path.
	if !looksLikeURLParam(v.Name, v.OriginalValue) {
		return result, nil
	}

	for _, payload := range ssrfPayloads {
		if result.RequestsMade >= r.RequestBudget() {
			break
		}
		injected, err := buildInjectedURL(v, payload)
		if err != nil {
			continue
		}
		resp, err := client.Get(ctx, injected)
		result.RequestsMade++
		if err != nil {
			continue
		}
		body := strings.ToLower(string(resp.Body))
		for _, sig := range ssrfSignals {
			if strings.Contains(body, sig) {
				result.Found = true
				result.Payload = payload
				result.Evidence = fmt.Sprintf(
					"SSRF signal %q found in response body after injecting metadata URL into parameter %q (status %d)",
					sig, v.Name, resp.StatusCode,
				)
				return result, nil
			}
		}
	}
	return result, nil
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
	return models.Finding{
		ID: fmt.Sprintf("active-ssrf-%d", time.Now().UnixNano()),
		Title: fmt.Sprintf("SSRF indicator in parameter %q at %s", res.Vector.Name, res.Vector.URL),
		Description: fmt.Sprintf("Parameter %q accepted a cloud metadata URL and the server's response contained metadata content, indicating it made an outbound request to the injected URL (Server-Side Request Forgery).", res.Vector.Name),
		Severity: models.SeverityCritical,
		Confidence: models.ConfidenceMedium,
		Category: models.CategoryVulnerability,
		CWE: "CWE-918",
		OWASP: "A10:2021 - Server-Side Request Forgery",
		Target: target,
		URL: res.Vector.URL,
		Parameter: res.Vector.Name,
		Source: models.SourceActive,
		DetectionMethod: "SSRF probe: cloud metadata endpoint injected into URL-like parameter, metadata content found in response",
		Evidence: models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("GET %s (payload in %s=%q)", res.Vector.URL, res.Vector.Name, res.Payload)},
		Impact: "An attacker can make the server contact internal services, cloud metadata endpoints, and other infrastructure, enabling credential theft, lateral movement, and data exfiltration.",
		Remediation: "Validate and allowlist outbound URL destinations. Block access to cloud metadata IP ranges (169.254.169.254) at the network level. Use IMDSv2 with token requirement on AWS.",
		References: []string{"https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/", "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"},
		FirstSeen: time.Now(),
	}
}
