package authz

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// Scanner implements scanner.Scanner for authorization comparison testing.
// It requires two AuthContexts (A = baseline, B = challenger) and a list
// of endpoints to probe, which it takes from sc.Endpoints (populated by
// the Endpoints stage that runs before it in the pipeline).
type Scanner struct {
	client   *anpuhttp.Client
	contextB models.AuthContext
}

// New returns an authz.Scanner.  contextB is the challenger identity;
// the baseline (context A) is taken from sc.Auth at Run time.
func New(client *anpuhttp.Client, contextB models.AuthContext) *Scanner {
	return &Scanner{client: client, contextB: contextB}
}

func (s *Scanner) Name() string { return "authz-tester" }

// Available always returns true: with two identities the stage compares
// them; fully anonymous scans fall back to forced-browsing of sensitive
// endpoints instead of skipping.
func (s *Scanner) Available(_ context.Context) bool {
	return true
}

// Run probes every discovered endpoint under both identity contexts and
// produces findings for any authorization anomalies detected.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	contextA := sc.Auth
	contextB := s.contextB

	// No second identity: instead of skipping, probe sensitive endpoints
	// as anonymous — exposed admin consoles and APIs are the highest
	// value zero-config authorization signal.
	if !contextA.IsAuthenticated() && !contextB.IsAuthenticated() {
		return s.runAnonymousOnly(ctx, sc)
	}

	endpoints := sc.Endpoints
	if len(endpoints) == 0 {
		return scanner.StageResult{
			Warnings: []string{"authz-tester: no endpoints discovered; nothing to probe"},
		}, nil
	}

	var findings []models.Finding
	var warnings []string
	probed := 0

	for _, ep := range endpoints {
		// Skip assets — probing JS/CSS/images for authz issues is noise.
		if ep.Category == models.EndpointAsset {
			continue
		}

		select {
		case <-ctx.Done():
			warnings = append(warnings, "authz-tester: context cancelled, stopped early")
			return scanner.StageResult{Findings: findings, Warnings: warnings}, nil
		default:
		}

		probeA, errA := Probe(ctx, s.client, contextA, ep.URL)
		if errA != nil {
			warnings = append(warnings, fmt.Sprintf("authz-tester: probe A failed for %s: %v", ep.URL, errA))
			continue
		}

		probeB, errB := Probe(ctx, s.client, contextB, ep.URL)
		if errB != nil {
			warnings = append(warnings, fmt.Sprintf("authz-tester: probe B failed for %s: %v", ep.URL, errB))
			continue
		}

		probed++

		if anomaly := Compare(ep.URL, "GET", probeA, probeB); anomaly != nil {
			findings = append(findings, ToFinding(anomaly, sc.Target.Raw))
		}
	}

	if probed == 0 {
		warnings = append(warnings, "authz-tester: no non-asset endpoints were reachable for both contexts")
	}

	return scanner.StageResult{Findings: findings, Warnings: warnings}, nil
}

// sensitivePathFragments matches URL paths that almost always require
// authentication: admin consoles, internal tooling, and account APIs.
// A 200 here for an anonymous visitor is worth flagging.
var sensitivePathFragments = []string{
	"/admin", "/administrator", "/wp-admin", "/manager", "/console",
	"/dashboard", "/account", "/settings", "/profile", "/internal",
	"/actuator", "/env", "/config", "/debug", "/metrics",
	"/phpmyadmin", "/server-status", "/.git", "/api/admin",
}

// runAnonymousOnly is the zero-config fallback: GET each sensitive
// discovered endpoint once as anonymous and flag the ones that answer
// 200 with a real body instead of denying or redirecting to login.
func (s *Scanner) runAnonymousOnly(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	anon := models.AuthContext{}
	var findings []models.Finding
	var warnings []string
	probed := 0

	for _, ep := range sc.Endpoints {
		if ep.Category == models.EndpointAsset {
			continue
		}
		if ep.Category != models.EndpointAdminLike &&
			ep.Category != models.EndpointAuth &&
			ep.Category != models.EndpointAPI &&
			!isSensitivePath(ep.URL) {
			continue
		}

		select {
		case <-ctx.Done():
			warnings = append(warnings, "authz-tester: context cancelled, stopped early")
			return scanner.StageResult{Findings: findings, Warnings: warnings}, nil
		default:
		}

		probe, err := Probe(ctx, s.client, anon, ep.URL)
		if err != nil {
			continue
		}
		probed++

		// Denied, redirected to login, or empty — expected, not a finding.
		if probe.StatusCode != 200 || probe.BodyLength < minBodySizeForDiff {
			continue
		}
		if isLoginLike(probe.FinalURL) {
			continue
		}
		findings = append(findings, anonymousExposureFinding(ep.URL, probe, sc.Target.Raw))
	}

	if probed == 0 && len(findings) == 0 {
		warnings = append(warnings, "authz-tester: anonymous probe found no sensitive endpoints exposed (supply --authz-token / --authz-cookie / --authz-header for full comparison testing)")
	}

	return scanner.StageResult{Findings: findings, Warnings: warnings}, nil
}

// isSensitivePath reports whether a URL path looks like it should sit
// behind authentication.
func isSensitivePath(rawURL string) bool {
	lower := strings.ToLower(rawURL)
	for _, frag := range sensitivePathFragments {
		if strings.Contains(lower, frag) {
			return true
		}
	}
	return false
}

// anonymousExposureFinding records a sensitive endpoint that answered
// 200 to an unauthenticated GET.
func anonymousExposureFinding(url string, probe models.AuthzProbeResult, target string) models.Finding {
	return models.Finding{
		ID:    fmt.Sprintf("authz-anon-exposed-%d", time.Now().UnixNano()),
		Title: fmt.Sprintf("Sensitive endpoint reachable without authentication: %s", url),
		Description: fmt.Sprintf(
			"An unauthenticated GET to %s returned HTTP 200 with a %d-byte body instead of a 401/403 denial or login redirect. "+
				"Admin consoles, account areas, and internal APIs must enforce server-side authorization on every request.",
			url, probe.BodyLength,
		),
		Severity:        models.SeverityHigh,
		Confidence:      models.ConfidenceMedium,
		Category:        models.CategoryAuthorization,
		CWE:             "CWE-284",
		OWASP:           "A01:2021 - Broken Access Control",
		Target:          target,
		URL:             url,
		Source:          models.SourceAuthz,
		DetectionMethod: "anonymous forced-browsing: unauthenticated GET, no second identity configured",
		Evidence: models.Evidence{
			Observed:       fmt.Sprintf("role=anonymous status=%d body=%dB", probe.StatusCode, probe.BodyLength),
			Location:       url,
			RequestSummary: fmt.Sprintf("GET %s", url),
		},
		Impact:      "Unauthenticated visitors can reach functionality that is normally restricted to logged-in users or administrators.",
		Remediation: "Enforce server-side authorization checks on this endpoint; return 401/403 for anonymous requests. For deeper testing, supply --authz-token / --authz-cookie / --authz-header so ANPU can compare two identities.",
		References: []string{
			"https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
		},
		FirstSeen: time.Now(),
	}
}
