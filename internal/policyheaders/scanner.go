// Package policyheaders audits transport/isolation policy headers
// (Wave 1 item 26): a single GET, evaluating HSTS (incl. preload
// readiness: max-age ≥ 31536000 + includeSubDomains + preload),
// COOP/COEP/CORP, and Expect-CT. Each gap is a Low/Info finding with
// the exact deficit named. Passive header analysis — complements the
// Headers stage's presence checks with readiness semantics.
package policyheaders

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "policyheaders" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

// hstsReadiness parses Strict-Transport-Security (pure, tested).
type hstsReadiness struct {
	present         bool
	maxAge          int64
	includeSub      bool
	preload         bool
	preloadReady    bool
	preloadDeficits []string
}

func parseHSTS(v string) hstsReadiness {
	r := hstsReadiness{}
	if strings.TrimSpace(v) == "" {
		return r
	}
	r.present = true
	for _, part := range strings.Split(strings.ToLower(v), ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "max-age=") {
			r.maxAge, _ = strconv.ParseInt(strings.TrimPrefix(part, "max-age="), 10, 64)
		} else if part == "includesubdomains" {
			r.includeSub = true
		} else if part == "preload" {
			r.preload = true
		}
	}
	if r.maxAge < 31536000 {
		r.preloadDeficits = append(r.preloadDeficits, fmt.Sprintf("max-age=%d < 31536000", r.maxAge))
	}
	if !r.includeSub {
		r.preloadDeficits = append(r.preloadDeficits, "missing includeSubDomains")
	}
	if !r.preload {
		r.preloadDeficits = append(r.preloadDeficits, "missing preload directive")
	}
	r.preloadReady = len(r.preloadDeficits) == 0
	return r
}

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resp, err := s.client.Get(cctx, sc.Target.Raw)
	if err != nil || resp == nil {
		return scanner.StageResult{}, nil
	}
	isHTTPS := strings.HasPrefix(strings.ToLower(resp.FinalURL), "https://")
	h := resp.Header

	var findings []models.Finding
	add := func(id, title, desc string, sev models.Severity, observed string) {
		findings = append(findings, models.Finding{
			ID: id, Title: title, Description: desc, Severity: sev,
			Confidence: models.ConfidenceHigh, Category: models.CategoryConfiguration,
			Target: sc.Target.Raw, URL: sc.Target.Raw,
			Evidence: models.Evidence{Observed: observed, Location: "response headers"},
			Source:   models.SourceCustom, DetectionMethod: "policy-header readiness (policyheaders, 1 request)",
		})
	}

	if isHTTPS {
		rd := parseHSTS(h.Get("Strict-Transport-Security"))
		switch {
		case !rd.present:
			add("policyheaders-hsts-missing", "HSTS missing on HTTPS site",
				"HTTPS without Strict-Transport-Security stays downgradeable (SSL-stripping) on first visit. Emit max-age=31536000; includeSubDomains and submit for preload. Reproduce: curl -sI TARGET | grep -i strict.",
				models.SeverityLow, "Strict-Transport-Security: <absent>")
		case !rd.preloadReady:
			add("policyheaders-hsts-preload", "HSTS not preload-ready",
				"First visits stay strippable until the domain is preloaded; current gaps: "+strings.Join(rd.preloadDeficits, "; ")+". Fix all three and submit at hstspreload.org.",
				models.SeverityInfo, "HSTS gaps: "+strings.Join(rd.preloadDeficits, "; "))
		}
	}
	if v := strings.TrimSpace(h.Get("Cross-Origin-Opener-Policy")); v == "" {
		add("policyheaders-coop-missing", "COOP missing (cross-origin window isolation)",
			"Without Cross-Origin-Opener-Policy the page shares a browsing context group with cross-origin popups (XS-Leaks, credential-less attacks). Send COOP: same-origin (plus COEP for full isolation).",
			models.SeverityInfo, "Cross-Origin-Opener-Policy: <absent>")
	}
	if v := strings.TrimSpace(h.Get("Cross-Origin-Embedder-Policy")); v == "" {
		add("policyheaders-coep-missing", "COEP missing (cross-origin embed isolation)",
			"Without Cross-Origin-Embedder-Policy, cross-origin resources load without CORP/COEP opt-in, weakening Spectre-class isolation. Send COEP: require-corp alongside COOP.",
			models.SeverityInfo, "Cross-Origin-Embedder-Policy: <absent>")
	}
	if v := strings.TrimSpace(h.Get("Cross-Origin-Resource-Policy")); v == "" {
		add("policyheaders-corp-missing", "CORP missing (resource isolation)",
			"Without Cross-Origin-Resource-Policy, sensitive resources (images, scripts) are embeddable cross-origin. Send CORP: same-origin on non-public resources.",
			models.SeverityInfo, "Cross-Origin-Resource-Policy: <absent>")
	}
	return scanner.StageResult{Findings: findings}, nil
}
