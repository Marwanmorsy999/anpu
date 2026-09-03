// Package csrf detects missing CSRF protection on mutation endpoints.
//
// Strategy: for every endpoint the crawler tagged as an HTML form with a
// non-GET method, fetch the page that hosts the form and check whether
// the response body contains a recognisable CSRF token field.  No payload
// is injected and no form is ever submitted — this is a passive read-only
// check.
//
// False-positive controls:
//   - Only endpoints with Method == "POST" / "PUT" / "PATCH" / "DELETE"
//     and source "html-form" are probed (confirmed mutation endpoints).
//   - A broad set of common token field names and meta-tag patterns is
//     checked to avoid flagging apps that use non-standard names.
//   - Confidence is Medium — we can observe the form but cannot confirm
//     the server's enforcement logic.
package csrf

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// csrfTokenPattern matches common CSRF token input fields and meta tags.
// Covers: _token, csrf_token, authenticity_token, __RequestVerificationToken,
// _csrf, csrfmiddlewaretoken, and X-CSRF-TOKEN / X-XSRF-TOKEN meta tags.
var csrfTokenPattern = regexp.MustCompile(
	`(?i)(name|content)\s*=\s*["']?` +
		`(_token|csrf[_-]?token|authenticity[_-]token|__requestverificationtoken|` +
		`_csrf|csrfmiddlewaretoken|xsrf[_-]?token|x-csrf-token|x-xsrf-token)["']?`,
)

// isMutationMethod reports whether the HTTP method implies state change.
func isMutationMethod(method string) bool {
	switch strings.ToUpper(method) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	}
	return false
}

// isFormEndpoint returns true when the endpoint was discovered from an HTML
// form (as opposed to a link or JS reference) and carries a mutation method.
func isFormEndpoint(ep models.Endpoint) bool {
	if !isMutationMethod(ep.Method) {
		return false
	}
	for _, src := range ep.Sources {
		if src == "html-form" {
			return true
		}
	}
	return false
}

// Scanner is the pipeline stage for CSRF detection.
type Scanner struct {
	client *anpuhttp.Client
}

// New returns a csrf.Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

func (s *Scanner) Name() string                     { return "csrf-scanner" }
func (s *Scanner) Available(_ context.Context) bool { return true }

// Run fetches each mutation-form endpoint and checks for CSRF token fields.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	var findings []models.Finding
	var warnings []string

	for _, ep := range sc.Endpoints {
		if !isFormEndpoint(ep) {
			continue
		}

		select {
		case <-ctx.Done():
			warnings = append(warnings, "csrf-scanner: context cancelled, stopped early")
			return scanner.StageResult{Findings: findings, Warnings: warnings}, nil
		default:
		}

		resp, err := s.client.WithAuth(sc.Auth.RequestHeaders()).Get(ctx, ep.URL)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("csrf-scanner: GET %s: %v", ep.URL, err))
			continue
		}

		body := string(resp.Body)
		if csrfTokenPattern.MatchString(body) {
			// Token field present — no finding.
			continue
		}

		findings = append(findings, models.Finding{
			ID:    fmt.Sprintf("csrf-missing-%d", time.Now().UnixNano()),
			Title: fmt.Sprintf("Missing CSRF token on %s %s", ep.Method, ep.URL),
			Description: fmt.Sprintf(
				"The form at %s submits via %s but no recognisable CSRF token field was found in the page body. "+
					"Without a token, any authenticated user can be tricked into submitting the form from a third-party site.",
				ep.URL, ep.Method,
			),
			Severity:        models.SeverityMedium,
			Confidence:      models.ConfidenceMedium,
			Category:        models.CategoryVulnerability,
			CWE:             "CWE-352",
			OWASP:           "A01:2021 - Broken Access Control",
			Target:          sc.Target.Raw,
			URL:             ep.URL,
			Source:          models.SourceCSRF,
			DetectionMethod: "Fetched form page; no CSRF token input field or meta tag detected in response body",
			Evidence: models.Evidence{
				Observed:       fmt.Sprintf("Form method=%s, no CSRF token field found in %d-byte response", ep.Method, len(resp.Body)),
				Location:       ep.URL,
				RequestSummary: fmt.Sprintf("GET %s", ep.URL),
			},
			Impact:      "Cross-Site Request Forgery: an attacker can craft a page that submits this form on behalf of an authenticated victim.",
			Remediation: "Add a synchroniser token (e.g. a hidden _csrf field) to every state-changing form and validate it server-side on each submission.",
			References: []string{
				"https://owasp.org/www-community/attacks/csrf",
				"https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
			},
			FirstSeen: time.Now(),
		})
	}

	return scanner.StageResult{Findings: findings, Warnings: warnings}, nil
}
