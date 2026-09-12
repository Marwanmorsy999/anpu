// Package clickjack checks clickjacking defenses natively (Wave 1 item
// 25): up to 3 same-host page GETs, evaluating X-Frame-Options and CSP
// frame-ancestors on each. Missing both headers is a Low finding;
// XFO ALLOWALL / ALLOW-FROM (legacy, inconsistently enforced) is a
// Low finding; SAMEORIGIN/DENY or a frame-ancestors directive is
// silent. Passive header analysis — no framing is attempted.
package clickjack

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// maxTargets bounds GETs per scan.
const maxTargets = 3

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "clickjack" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

// verdict classifies framing protection from headers (pure, tested).
func verdict(xfo, csp string) (protected bool, reason string) {
	if hasFrameAncestors(csp) {
		return true, "CSP frame-ancestors present"
	}
	switch strings.ToUpper(strings.TrimSpace(xfo)) {
	case "DENY", "SAMEORIGIN":
		return true, "X-Frame-Options " + strings.ToUpper(strings.TrimSpace(xfo))
	case "":
		return false, "no X-Frame-Options and no CSP frame-ancestors"
	default:
		return false, "X-Frame-Options " + strings.TrimSpace(xfo) + " is not consistently enforced"
	}
}

func hasFrameAncestors(csp string) bool {
	for _, dir := range strings.Split(strings.ToLower(csp), ";") {
		if strings.HasPrefix(strings.TrimSpace(dir), "frame-ancestors") {
			return true
		}
	}
	return false
}

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	targets := []string{sc.Target.Raw}
	for _, ep := range sc.Endpoints {
		if len(targets) >= maxTargets {
			break
		}
		if ep.Category != models.EndpointPage && ep.Category != models.EndpointUnknown {
			continue
		}
		u, err := url.Parse(ep.URL)
		if err != nil || !strings.EqualFold(u.Hostname(), sc.Target.Host) || ep.URL == sc.Target.Raw {
			continue
		}
		targets = append(targets, ep.URL)
	}

	var findings []models.Finding
	// When the Headers stage runs, its posture finding already reports
	// framing absence on the target page — re-reporting it here would be
	// a duplicate row. In that case only sub-pages with a WORSE verdict
	// than the target (protected default, exposed sub-page) earn a row.
	// With --only clickjack (Headers off) the legacy behavior stays.
	headersOn := sc.Config.Modules.Headers
	for _, target := range targets {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		resp, err := s.client.Get(cctx, target)
		cancel()
		if err != nil || resp == nil {
			continue
		}
		protected, reason := verdict(resp.Header.Get("X-Frame-Options"), resp.Header.Get("Content-Security-Policy"))
		if protected {
			continue
		}
		if headersOn && target == sc.Target.Raw {
			continue // posture checklist owns the target-page row
		}
		findings = append(findings, models.Finding{
			ID:              "clickjack-missing-framing",
			Title:           fmt.Sprintf("Clickjacking defense missing on %s", displayPath(target)),
			Description:     fmt.Sprintf("The page sends %s: it can be framed by any site for clickjacking (invisible overlay hijacking clicks). Send X-Frame-Options: SAMEORIGIN (or DENY) or a CSP frame-ancestors directive. Reproduce: curl -sI TARGET | grep -i -E 'x-frame-options|content-security-policy'.", reason),
			Severity:        models.SeverityLow,
			Confidence:      models.ConfidenceHigh,
			Category:        models.CategoryConfiguration,
			CWE:             "CWE-1021",
			Target:          sc.Target.Raw,
			URL:             target,
			Evidence:        models.Evidence{Observed: reason, Location: "response headers"},
			Source:          models.SourceCustom,
			DetectionMethod: "XFO + frame-ancestors analysis (clickjack, ≤3 requests)",
			Remediation:     "Add frame-ancestors 'self' (CSP) and X-Frame-Options: SAMEORIGIN.",
		})
		break // one page proves the site-wide default
	}
	return scanner.StageResult{Findings: findings}, nil
}

func displayPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	p := u.Path
	if p == "" {
		p = "/"
	}
	return p
}
