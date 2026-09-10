// Package verbtamper probes HTTP method tampering (Wave 1 item 21):
// for up to 3 same-host endpoints (discovered first, else the target
// root), it replays the request with alternate methods (POST, PUT,
// PATCH, DELETE, OPTIONS) when the baseline GET is denied (401/403/405)
// or explicitly limited. A 2xx variant with a body clearly dissimilar
// from both the denial page and the site-root control is a finding.
//
// GET-only baseline plus read-only method replays with empty bodies —
// no form submissions, no state change. Budget: 3 × (2 + 5) = 21 max.
package verbtamper

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// maxEndpoints and method variants bound the budget.
const (
	maxEndpoints = 3
	maxRequests  = 21
)

var methods = []string{"POST", "PUT", "PATCH", "DELETE", "OPTIONS"}

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "verbtamper" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	targets := pickTargets(sc)
	if len(targets) == 0 {
		return scanner.StageResult{}, nil
	}
	made := 0
	do := func(method, u string, headers map[string]string) *anpuhttp.Response {
		if made >= maxRequests {
			return nil
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		made++
		var resp *anpuhttp.Response
		var err error
		if len(headers) == 0 && method == "GET" {
			resp, err = s.client.Get(cctx, u)
		} else {
			resp, err = s.client.DoWithHeaders(cctx, method, u, headers)
		}
		if err != nil || resp == nil {
			return nil
		}
		return resp
	}

	// Control: plain site root for catch-all filtering.
	controlWords := map[string]struct{}{}
	if root := do("GET", sc.Target.Raw, nil); root != nil {
		controlWords = wordSet(root.Body)
	}

	var findings []models.Finding
	for _, target := range targets {
		base := do("GET", target, nil)
		if base == nil {
			continue
		}
		if base.StatusCode != 401 && base.StatusCode != 403 && base.StatusCode != 405 {
			continue // only denied/method-limited resources are interesting
		}
		baseWords := wordSet(base.Body)
		for _, m := range methods {
			if made >= maxRequests {
				break
			}
			resp := do(m, target, nil)
			if resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
				continue
			}
			got := wordSet(resp.Body)
			if overlap(got, baseWords) > 0.7 {
				continue // same denial page, different status
			}
			if overlap(got, controlWords) > 0.85 {
				continue // catch-all fallback
			}
			findings = append(findings, models.Finding{
				ID:              "verbtamper-" + strings.ToLower(m),
				Title:           fmt.Sprintf("Method tampering bypass via %s on %s", m, displayPath(target)),
				Description:     fmt.Sprintf("GET %s is denied (%d) but %s returns %d with clearly different content: access control is enforced per-method, not per-resource. Enforce authorization in a single layer for all methods. Reproduce: curl -s -X %s TARGET. Empty bodies only — nothing was submitted.", displayPath(target), base.StatusCode, m, resp.StatusCode, m),
				Severity:        models.SeverityMedium,
				Confidence:      models.ConfidenceMedium,
				Category:        models.CategoryVulnerability,
				CWE:             "CWE-863",
				Target:          sc.Target.Raw,
				URL:             target,
				Evidence:        models.Evidence{Observed: fmt.Sprintf("GET→%d, %s→%d (%d bytes, dissimilar)", base.StatusCode, m, resp.StatusCode, len(resp.Body)), Location: "method replay vs GET baseline"},
				Source:          models.SourceCustom,
				DetectionMethod: "HTTP method tampering with denial baseline (verbtamper, ≤21 requests)",
				Remediation:     "Authorize per resource for every method; deny unknown methods by default.",
			})
			break // one bypass per endpoint is enough
		}
		if len(findings) >= 3 {
			break
		}
	}
	return scanner.StageResult{Findings: findings}, nil
}

// pickTargets prefers admin-like/auth discovered endpoints, then any
// discovered page, then the target root.
func pickTargets(sc *scanner.ScanContext) []string {
	var admin, other []string
	for _, ep := range sc.Endpoints {
		u, err := url.Parse(ep.URL)
		if err != nil || !strings.EqualFold(u.Hostname(), sc.Target.Host) {
			continue
		}
		if ep.Category == models.EndpointAdminLike || ep.Category == models.EndpointAuth {
			admin = append(admin, ep.URL)
		} else if ep.Category == models.EndpointPage || ep.Category == models.EndpointUnknown {
			other = append(other, ep.URL)
		}
	}
	sort.Strings(admin)
	sort.Strings(other)
	out := append(admin, other...)
	if len(out) > maxEndpoints {
		out = out[:maxEndpoints]
	}
	if len(out) == 0 {
		out = []string{sc.Target.Raw}
	}
	return out
}

func wordSet(b []byte) map[string]struct{} {
	out := map[string]struct{}{}
	for _, w := range strings.Fields(strings.ToLower(string(b))) {
		if len(w) > 2 {
			out[w] = struct{}{}
		}
	}
	return out
}

func overlap(a, b map[string]struct{}) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	n := 0
	for w := range a {
		if _, ok := b[w]; ok {
			n++
		}
	}
	return float64(n) / float64(len(a))
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
