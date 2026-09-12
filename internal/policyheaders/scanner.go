// Package policyheaders audits HSTS preload readiness (Wave 1 item 26):
// a single GET, evaluating max-age ≥ 31536000 + includeSubDomains +
// preload when Strict-Transport-Security is present. Bare presence gaps
// (missing HSTS/COOP/COEP/CORP) are owned by the Headers stage posture
// finding, which keeps the per-header checklist in one row — this stage
// only adds readiness semantics the checklist cannot express. Passive
// header analysis.
package policyheaders

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
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
		// Absent HSTS is owned by the Headers posture finding (Medium);
		// only present-but-not-ready earns a readiness row here.
		if rd.present && !rd.preloadReady {
			add("policyheaders-hsts-preload", "HSTS not preload-ready",
				"First visits stay strippable until the domain is preloaded; current gaps: "+strings.Join(rd.preloadDeficits, "; ")+". Fix all three and submit at hstspreload.org.",
				models.SeverityInfo, "HSTS gaps: "+strings.Join(rd.preloadDeficits, "; "))
		}
	}
	return scanner.StageResult{Findings: findings}, nil
}
