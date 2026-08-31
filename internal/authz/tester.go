// Package authz implements ANPU's Phase 3 authorization testing engine.
//
// It takes two AuthContexts (A and B), a list of endpoints discovered
// during the main scan, and probes each endpoint under both identities.
// When the responses differ in a way that suggests an access-control
// problem, it records an AuthzAnomaly which is then converted to a
// Finding by the scanner stage.
//
// Design rules:
//   - GET-only: no mutations, no form submissions, no side effects.
//   - Explicit contexts only: no context guessing or derivation.
//   - One pair per endpoint: the same request sent twice, nothing more.
//   - Evidence is always concrete (status codes, body lengths, snippets).
//   - Credential values never appear in findings or evidence.
package authz

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

const (
	// maxBodySnippet is the maximum bytes stored as evidence in a probe
	// result.  Kept short so findings stay readable.
	maxBodySnippet = 256

	// significantBodyDelta is the minimum byte difference between two
	// bodies (as a fraction of the larger body) to classify as
	// AnomalyBodyDiffers.  Avoids false positives from timestamps,
	// nonces, and minor dynamic content.
	significantBodyDelta = 0.15

	// minBodySizeForDiff skips body comparison when both bodies are tiny
	// (e.g. empty 200 responses) — the signal is too weak.
	minBodySizeForDiff = 64
)

// Probe issues a single GET request under the given AuthContext and
// captures the result.
func Probe(
	ctx context.Context,
	client *anpuhttp.Client,
	authCtx models.AuthContext,
	url string,
) (models.AuthzProbeResult, error) {
	authed := client.WithAuth(authCtx.RequestHeaders())
	resp, err := authed.Get(ctx, url)
	if err != nil {
		return models.AuthzProbeResult{}, fmt.Errorf("probe %s (role=%s): %w", url, authCtx.EffectiveRole(), err)
	}

	snippet := ""
	if len(resp.Body) > 0 {
		b := resp.Body
		if len(b) > maxBodySnippet {
			b = b[:maxBodySnippet]
		}
		// Only include the snippet if it is valid UTF-8 text.
		if utf8.Valid(b) {
			snippet = strings.TrimSpace(string(b))
		}
	}

	return models.AuthzProbeResult{
		Role:        string(authCtx.EffectiveRole()),
		StatusCode:  resp.StatusCode,
		FinalURL:    resp.FinalURL,
		BodyLength:  len(resp.Body),
		BodySnippet: snippet,
		ContentType: resp.Header.Get("Content-Type"),
	}, nil
}

// Compare takes two probe results for the same URL and returns an
// AuthzAnomaly if the responses suggest an access-control problem, or
// nil if they look consistent.
func Compare(url, method string, a, b models.AuthzProbeResult) *models.AuthzAnomaly {
	// --- Redirect differs ---
	// One context ended up at a different URL (e.g. login redirect).
	if normalizeURL(a.FinalURL) != normalizeURL(b.FinalURL) {
		aRedirected := isLoginLike(a.FinalURL)
		bRedirected := isLoginLike(b.FinalURL)
		if aRedirected != bRedirected {
			return &models.AuthzAnomaly{
				URL: url, Method: method,
				Kind:     models.AnomalyRedirectDiffers,
				ContextA: a, ContextB: b,
			}
		}
	}

	// --- Access granted to B where A was denied ---
	// B gets 2xx, A got 4xx — classic privilege escalation.
	if is2xx(b.StatusCode) && is4xx(a.StatusCode) {
		return &models.AuthzAnomaly{
			URL: url, Method: method,
			Kind:     models.AnomalyAccessGranted,
			ContextA: a, ContextB: b,
		}
	}

	// --- Status meaningfully differs ---
	// Both got a response but with different status families.
	if statusFamily(a.StatusCode) != statusFamily(b.StatusCode) {
		// Only flag when the difference is security-relevant (not e.g. 301 vs 200).
		if isSecurityRelevantStatusPair(a.StatusCode, b.StatusCode) {
			return &models.AuthzAnomaly{
				URL: url, Method: method,
				Kind:     models.AnomalyStatusDiffers,
				ContextA: a, ContextB: b,
			}
		}
	}

	// --- Body significantly differs on matching 2xx ---
	// Both got through, but one sees substantially more data.
	if is2xx(a.StatusCode) && is2xx(b.StatusCode) {
		larger := a.BodyLength
		if b.BodyLength > larger {
			larger = b.BodyLength
		}
		if larger >= minBodySizeForDiff {
			delta := abs(a.BodyLength - b.BodyLength)
			if float64(delta)/float64(larger) >= significantBodyDelta {
				return &models.AuthzAnomaly{
					URL: url, Method: method,
					Kind:     models.AnomalyBodyDiffers,
					ContextA: a, ContextB: b,
				}
			}
		}
	}

	return nil
}

// ToFinding converts an AuthzAnomaly into a normalized ANPU Finding.
// Credential values never appear in the finding — only role labels,
// status codes, body lengths, and safe snippets.
func ToFinding(a *models.AuthzAnomaly, target string) models.Finding {
	roleA := a.ContextA.Role
	roleB := a.ContextB.Role

	var title, description, impact, remediation string
	var severity models.Severity
	var confidence models.Confidence
	var cwe, owasp string

	switch a.Kind {
	case models.AnomalyAccessGranted:
		title = fmt.Sprintf("Authorization bypass: %s accessed resource denied to %s", roleB, roleA)
		description = fmt.Sprintf(
			"The endpoint %s returned HTTP %d for role %q but HTTP %d for role %q. "+
				"This may indicate an insecure direct object reference (IDOR) or broken access control.",
			a.URL, a.ContextA.StatusCode, roleA, a.ContextB.StatusCode, roleB,
		)
		severity = models.SeverityHigh
		confidence = models.ConfidenceMedium
		impact = "A lower-privilege identity can access resources restricted to a higher-privilege identity."
		remediation = "Verify server-side authorization checks are enforced on every request, not just on the UI layer."
		cwe = "CWE-284"
		owasp = "A01:2021 - Broken Access Control"

	case models.AnomalyStatusDiffers:
		title = fmt.Sprintf("Access control discrepancy: %s vs %s on %s", roleA, roleB, a.URL)
		description = fmt.Sprintf(
			"Role %q received HTTP %d and role %q received HTTP %d for the same endpoint. "+
				"This suggests different access control outcomes that may warrant investigation.",
			roleA, a.ContextA.StatusCode, roleB, a.ContextB.StatusCode,
		)
		severity = models.SeverityMedium
		confidence = models.ConfidenceMedium
		impact = "Access control enforcement differs between identity contexts."
		remediation = "Audit server-side authorization logic for this endpoint; confirm each role's intended access level."
		cwe = "CWE-284"
		owasp = "A01:2021 - Broken Access Control"

	case models.AnomalyBodyDiffers:
		title = fmt.Sprintf("Response body discrepancy: %s vs %s on %s", roleA, roleB, a.URL)
		description = fmt.Sprintf(
			"Both role %q (%d bytes) and role %q (%d bytes) received HTTP 2xx for %s, "+
				"but response sizes differ significantly (>%.0f%%). "+
				"One identity may be receiving data the other should not see.",
			roleA, a.ContextA.BodyLength, roleB, a.ContextB.BodyLength, a.URL,
			significantBodyDelta*100,
		)
		severity = models.SeverityMedium
		confidence = models.ConfidenceLow
		impact = "One identity context may be receiving more data than intended."
		remediation = "Review the endpoint's data-filtering logic to ensure responses are scoped to the requesting identity."
		cwe = "CWE-200"
		owasp = "A01:2021 - Broken Access Control"

	case models.AnomalyRedirectDiffers:
		title = fmt.Sprintf("Redirect-based access control: %s vs %s on %s", roleA, roleB, a.URL)
		description = fmt.Sprintf(
			"Role %q was redirected to %q while role %q landed on %q. "+
				"Access control via redirect (rather than a 401/403) can be bypassed by clients that do not follow redirects.",
			roleA, a.ContextA.FinalURL, roleB, a.ContextB.FinalURL,
		)
		severity = models.SeverityMedium
		confidence = models.ConfidenceMedium
		impact = "Redirect-based access control can be bypassed by API clients or tools that ignore redirects."
		remediation = "Return a 401 or 403 for unauthenticated/unauthorized requests rather than relying solely on client-side redirects."
		cwe = "CWE-601"
		owasp = "A01:2021 - Broken Access Control"
	}

	observed := fmt.Sprintf(
		"role=%s status=%d body=%dB | role=%s status=%d body=%dB",
		roleA, a.ContextA.StatusCode, a.ContextA.BodyLength,
		roleB, a.ContextB.StatusCode, a.ContextB.BodyLength,
	)

	return models.Finding{
		ID:          fmt.Sprintf("authz-%s-%d", a.Kind, time.Now().UnixNano()),
		Title:       title,
		Description: description,
		Severity:    severity,
		Confidence:  confidence,
		Category:    models.CategoryAuthorization,
		CWE:         cwe,
		OWASP:       owasp,
		Target:      target,
		URL:         a.URL,
		Source:      models.SourceAuthz,
		DetectionMethod: fmt.Sprintf(
			"authorization comparison: %s (A) vs %s (B) — %s",
			roleA, roleB, a.Kind,
		),
		Evidence: models.Evidence{
			Observed:       observed,
			Location:       a.URL,
			RequestSummary: fmt.Sprintf("%s %s", a.Method, a.URL),
		},
		Impact:      impact,
		Remediation: remediation,
		References: []string{
			"https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
			"https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
		},
		FirstSeen: time.Now(),
	}
}

// --- helpers ---

func is2xx(code int) bool { return code >= 200 && code < 300 }
func is4xx(code int) bool { return code >= 400 && code < 500 }

func statusFamily(code int) int { return code / 100 }

func isSecurityRelevantStatusPair(a, b int) bool {
	// Flag when one side is successful (2xx) and the other is an
	// auth/authz denial (401/403) or a soft-denial 404.
	success := func(c int) bool { return c >= 200 && c < 300 }
	denial := func(c int) bool { return c == 401 || c == 403 || c == 404 }
	return (success(a) && denial(b)) || (denial(a) && success(b))
}

func isLoginLike(u string) bool {
	lower := strings.ToLower(u)
	for _, kw := range []string{"login", "signin", "sign-in", "auth", "sso", "account/login"} {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func normalizeURL(u string) string {
	return strings.TrimSuffix(strings.ToLower(u), "/")
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
