// Package cors checks for CORS misconfigurations across the target's endpoints.
//
// Phase 12G extends the original checker with:
//   - Per-endpoint probing (previously only the root URL was checked)
//   - Subdomain wildcard detection (evil.<target> reflected)
//   - Null origin finding with correct severity/impact
//   - OWASP / CWE on all findings
//   - Deduplication: one finding per (URL, misconfiguration kind)
package cors

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// Scanner implements scanner.Scanner for CORS posture checks.
type Scanner struct {
	client *anpuhttp.Client
}

func New(client *anpuhttp.Client) *Scanner          { return &Scanner{client: client} }
func (s *Scanner) Name() string                     { return "cors" }
func (s *Scanner) Available(_ context.Context) bool { return true }

// corsProbe describes a single Origin value to inject and metadata about
// what kind of misconfiguration it tests for.
type corsProbe struct {
	originFn func(targetHost string) string // builds the Origin to send
	kind     string                         // label used for deduplication
}

// probes is the ordered list of CORS Origin probes.
// They are evaluated in order; the first match per URL wins.
var probes = []corsProbe{
	{
		// Arbitrary external attacker origin — tests for unrestricted reflection.
		originFn: func(_ string) string { return "https://anpu-cors-probe.evil.example.com" },
		kind:     "arbitrary-origin",
	},
	{
		// Null origin — sent by sandboxed iframes; some servers allowlist it.
		originFn: func(_ string) string { return "null" },
		kind:     "null-origin",
	},
	{
		// Subdomain of the target — tests for overly broad subdomain allowlisting.
		// e.g. if target is https://example.com, probe https://evil.example.com
		originFn: func(targetHost string) string {
			host := targetHost
			// Strip scheme.
			for _, pfx := range []string{"https://", "http://"} {
				host = strings.TrimPrefix(host, pfx)
			}
			// Strip port.
			if idx := strings.LastIndex(host, ":"); idx > strings.Index(host, ":") {
				host = host[:idx]
			}
			return "https://evil." + host
		},
		kind: "subdomain-origin",
	},
}

func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	var findings []models.Finding
	var warnings []string

	// Build the list of URLs to probe: root + all discovered page/API endpoints.
	// Deduplicate by URL.
	seenURL := map[string]bool{sc.Target.Raw: true}
	urls := []string{sc.Target.Raw}
	for _, ep := range sc.Endpoints {
		if ep.Category == models.EndpointAsset {
			continue // assets don't return CORS headers worth checking
		}
		if !seenURL[ep.URL] {
			seenURL[ep.URL] = true
			urls = append(urls, ep.URL)
		}
		// Cap at 20 URLs to avoid excessive requests.
		if len(urls) >= 20 {
			break
		}
	}

	// seenFinding deduplicates by (URL, kind) to avoid repeat findings when
	// multiple endpoints share the same misconfiguration.
	type findingKey struct{ url, kind string }
	seenFinding := map[findingKey]bool{}

	targetHost := sc.Target.Raw

	for _, url := range urls {
		select {
		case <-ctx.Done():
			warnings = append(warnings, "cors: context cancelled")
			return scanner.StageResult{Findings: findings, Warnings: warnings}, nil
		default:
		}

		for _, probe := range probes {
			origin := probe.originFn(targetHost)

			resp, err := s.client.DoWithHeaders(ctx, "GET", url,
				map[string]string{"Origin": origin})
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("cors: probe %s on %s: %v", probe.kind, url, err))
				continue
			}

			acao := resp.Header.Get("Access-Control-Allow-Origin")
			acac := strings.TrimSpace(strings.ToLower(resp.Header.Get("Access-Control-Allow-Credentials")))
			if acao == "" {
				continue
			}

			key := findingKey{url, probe.kind}
			f := s.evaluateResponse(sc, resp, url, origin, acao, acac, probe.kind)
			if f != nil && !seenFinding[key] {
				seenFinding[key] = true
				findings = append(findings, *f)
			}
		}
	}

	return scanner.StageResult{Findings: findings, Warnings: warnings}, nil
}

// evaluateResponse decides whether a CORS response constitutes a finding and
// what severity/title to assign.  Returns nil for non-findings.
func (s *Scanner) evaluateResponse(sc *scanner.ScanContext, resp *anpuhttp.Response,
	url, sentOrigin, acao, acac, kind string) *models.Finding {

	withCreds := acac == "true"

	switch {
	// Wildcard + credentials — browser spec violation but dangerous with some clients.
	case acao == "*" && withCreds:
		return corsF(sc, resp, url,
			"Wildcard CORS combined with credentials",
			"ACAO: * with ACAC: true violates the Fetch spec (browsers reject it), but non-browser clients "+
				"and some middleware honour both. Indicates confused security intent.",
			models.SeverityMedium, models.ConfidenceHigh, kind)

	// Wildcard without credentials — low risk but worth noting.
	case acao == "*":
		return corsF(sc, resp, url,
			"CORS allows any origin (wildcard)",
			"Access-Control-Allow-Origin: * allows any website to read responses from a visitor's browser. "+
				"If the endpoint ever returns user-specific data, that data becomes accessible to any page the victim visits.",
			models.SeverityLow, models.ConfidenceHigh, kind)

	// Arbitrary origin reflected + credentials — highest impact.
	case isReflected(acao, sentOrigin) && withCreds && kind == "arbitrary-origin":
		return corsF(sc, resp, url,
			"CORS reflects arbitrary origins with credentials — cross-origin data theft",
			fmt.Sprintf("The server reflected attacker-controlled Origin %q into ACAO and set ACAC: true. "+
				"Any website can read authenticated responses from %s in a victim's browser session — "+
				"full account-data disclosure.", sentOrigin, sc.Target.Host),
			models.SeverityHigh, models.ConfidenceHigh, kind)

	// Arbitrary origin reflected, no credentials — medium risk.
	case isReflected(acao, sentOrigin) && !withCreds && kind == "arbitrary-origin":
		return corsF(sc, resp, url,
			"CORS reflects arbitrary origins (no credentials)",
			fmt.Sprintf("The server reflected attacker-controlled Origin %q into ACAO without credentials. "+
				"Direct impact is limited to unauthenticated responses, but the permissive reflection "+
				"is a misconfiguration that will become critical if credentials are enabled later.", sentOrigin),
			models.SeverityMedium, models.ConfidenceHigh, kind)

	// Null origin reflected + credentials — sandbox iframe bypass.
	case isReflected(acao, "null") && withCreds && kind == "null-origin":
		return corsF(sc, resp, url,
			"CORS allows null origin with credentials — sandbox iframe bypass",
			"The server allows Origin: null with credentials. A sandboxed iframe (e.g. from a data: URI) "+
				"has the null origin and can therefore read authenticated responses from this endpoint, "+
				"enabling cross-origin data theft from a page controlled by an attacker.",
			models.SeverityHigh, models.ConfidenceHigh, kind)

	// Null origin without credentials.
	case isReflected(acao, "null") && !withCreds && kind == "null-origin":
		return corsF(sc, resp, url,
			"CORS allows null origin (no credentials)",
			"The server allows Origin: null. Sandboxed iframes can read unauthenticated responses. "+
				"Low impact now; escalates to high if credentials are later enabled.",
			models.SeverityLow, models.ConfidenceHigh, kind)

	// Subdomain origin reflected + credentials — subdomain takeover amplifier.
	case isReflected(acao, sentOrigin) && withCreds && kind == "subdomain-origin":
		return corsF(sc, resp, url,
			"CORS reflects subdomains with credentials — subdomain takeover amplifier",
			fmt.Sprintf("The server reflected subdomain Origin %q with credentials. "+
				"If any subdomain of the target is vulnerable to takeover, an attacker can host "+
				"a page there and read authenticated API responses from %s.", sentOrigin, sc.Target.Host),
			models.SeverityHigh, models.ConfidenceMedium, kind)

	// Subdomain origin reflected, no credentials.
	case isReflected(acao, sentOrigin) && !withCreds && kind == "subdomain-origin":
		return corsF(sc, resp, url,
			"CORS reflects subdomains (no credentials)",
			fmt.Sprintf("The server reflected subdomain Origin %q without credentials. "+
				"Combined with a subdomain takeover this allows cross-origin reads of unauthenticated data.", sentOrigin),
			models.SeverityLow, models.ConfidenceMedium, kind)
	}

	return nil
}

// isReflected returns true when acao matches the sentOrigin (case-insensitive).
func isReflected(acao, origin string) bool {
	return strings.EqualFold(strings.TrimSpace(acao), strings.TrimSpace(origin))
}

func corsF(sc *scanner.ScanContext, resp *anpuhttp.Response, url, title, desc string,
	sev models.Severity, conf models.Confidence, kind string) *models.Finding {
	return &models.Finding{
		ID:              fmt.Sprintf("cors-%s-%d", slug(kind), time.Now().UnixNano()),
		Title:           title,
		Description:     desc,
		Severity:        sev,
		Confidence:      conf,
		Category:        models.CategoryConfiguration,
		CWE:             "CWE-942",
		OWASP:           "A05:2021 - Security Misconfiguration",
		Target:          sc.Target.Raw,
		URL:             url,
		Source:          models.SourceCustom,
		DetectionMethod: fmt.Sprintf("CORS probe: sent Origin and inspected ACAO/ACAC response headers (%s)", kind),
		Evidence: models.Evidence{
			Observed: fmt.Sprintf(
				"Access-Control-Allow-Origin: %s\nAccess-Control-Allow-Credentials: %s",
				orNone(resp.Header.Get("Access-Control-Allow-Origin")),
				orNone(resp.Header.Get("Access-Control-Allow-Credentials")),
			),
			RequestSummary: fmt.Sprintf("GET %s (Origin: <probe>)", url),
			Location:       "HTTP response headers",
		},
		Impact: "Cross-origin reads of API responses leak whatever the endpoint returns for the victim's session.",
		Remediation: "Maintain an explicit allowlist of trusted origins. Never reflect the request Origin header verbatim. " +
			"Never combine ACAO: * with ACAC: true. Use null-origin only when sandboxed frames are an intentional design choice.",
		References: []string{
			"https://portswigger.net/web-security/cors",
			"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-Side_Testing/07-Testing_for_Cross_Origin_Resource_Sharing",
			"https://cwe.mitre.org/data/definitions/942.html",
		},
		FirstSeen: time.Now(),
	}
}

func orNone(v string) string {
	if v == "" {
		return "(not set)"
	}
	return v
}

func slug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
