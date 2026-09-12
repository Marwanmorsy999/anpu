// Package cachedeception detects web cache deception (Wave 1 item 22):
// for up to 2 same-host page URLs it fetches the baseline, then
// deceptive variants (path + ".css", path + "/x.css", path + "%2e.css").
// A variant returning 200 with a body matching the private baseline —
// plus a cache HIT signal (X-Cache, CF-Cache-Status, Age, X-Cache-Hits)
// — is a Medium finding (poisoned cache serving the page as a static
// asset). Same body without cache evidence is an Info path-confusion
// note. GET-only, ≤8 requests, no state change.
package cachedeception

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// maxTargets and variants bound the budget: 2 × (1 + 3) = 8.
const (
	maxTargets  = 2
	maxRequests = 8
)

var deceptionSuffix = []string{".css", "/anpudecept.css", "%2e.css"}

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "cachedeception" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	targets := pickTargets(sc)
	made := 0
	get := func(u string) *anpuhttp.Response {
		if made >= maxRequests {
			return nil
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		made++
		resp, err := s.client.Get(cctx, u)
		if err != nil || resp == nil {
			return nil
		}
		return resp
	}

	var findings []models.Finding
	for _, target := range targets {
		base := get(target)
		if base == nil || base.StatusCode != 200 || len(base.Body) < 64 {
			continue
		}
		baseWords := wordSet(base.Body)
		for _, suf := range deceptionSuffix {
			if made >= maxRequests {
				break
			}
			variant := target + suf
			resp := get(variant)
			if resp == nil || resp.StatusCode != 200 || len(resp.Body) < 64 {
				continue
			}
			if overlap(wordSet(resp.Body), baseWords) < 0.8 {
				continue // different resource, not deception
			}
			hit, evidence := cacheHit(resp)
			sev := models.SeverityInfo
			title := fmt.Sprintf("Path confusion: %s serves page content", displayPath(variant))
			desc := fmt.Sprintf("GET %s returns 200 with the same content as %s: the edge treats a page URL as a static asset path. No cache-poison evidence was observed, but the confusion is the precondition for cache deception. Normalize/deny unknown extensions server-side. Reproduce: curl -s TARGET%s | diff - <(curl -s TARGET).", displayPath(variant), displayPath(target), suf)
			if hit {
				sev = models.SeverityMedium
				title = fmt.Sprintf("Web cache deception: %s cached as static asset (%s)", displayPath(variant), evidence)
				desc = fmt.Sprintf("GET %s returns 200 with page content AND a cache HIT signal (%s): the response is being stored under a static-asset cache key and may be served to other visitors, leaking the page. Add Cache-Control: no-store on dynamic pages and key the cache on Content-Type. Reproduce: curl -sI TARGET%s.", displayPath(variant), evidence, suf)
			}
			findings = append(findings, models.Finding{
				ID:              "cachedeception-hit",
				Title:           title,
				Description:     desc,
				Severity:        sev,
				Confidence:      models.ConfidenceMedium,
				Category:        models.CategoryVulnerability,
				CWE:             "CWE-444",
				Target:          sc.Target.Raw,
				URL:             variant,
				Evidence:        models.Evidence{Observed: fmt.Sprintf("variant 200 (%d bytes, %.0f%% overlap); cache: %s", len(resp.Body), overlap(wordSet(resp.Body), baseWords)*100, evidence), Location: "deceptive suffix vs baseline"},
				Source:          models.SourceCustom,
				DetectionMethod: "cache-deception suffix matrix (cachedeception, ≤8 requests)",
				Remediation:     "no-store on dynamic content; cache key must include Content-Type.",
			})
			break // one variant per target is enough
		}
		if len(findings) >= 2 {
			break
		}
	}
	return scanner.StageResult{Findings: findings}, nil
}

// cacheHit reports edge cache HIT signals (case-insensitive).
func cacheHit(resp *anpuhttp.Response) (bool, string) {
	h := resp.Header
	checks := []struct{ k, want string }{
		{"X-Cache", "hit"},
		{"X-Cache-Status", "hit"},
		{"CF-Cache-Status", "hit"},
		{"X-Drupal-Cache", "hit"},
		{"X-Varnish-Cache", "hit"},
		{"Akamai-Cache-Status", "hit"},
		{"X-Cache-Hits", ""}, // any numeric value
		{"Age", ""},          // any Age means it came from cache
	}
	for _, c := range checks {
		v := strings.ToLower(strings.TrimSpace(h.Get(c.k)))
		if v == "" {
			continue
		}
		if c.want == "" || strings.Contains(v, c.want) {
			return true, c.k + ": " + h.Get(c.k)
		}
	}
	return false, "no HIT headers"
}

func pickTargets(sc *scanner.ScanContext) []string {
	out := []string{sc.Target.Raw}
	for _, ep := range sc.Endpoints {
		if len(out) >= maxTargets {
			break
		}
		if ep.Category != models.EndpointPage && ep.Category != models.EndpointUnknown {
			continue
		}
		u, err := url.Parse(ep.URL)
		if err != nil || !strings.EqualFold(u.Hostname(), sc.Target.Host) {
			continue
		}
		if ep.URL == sc.Target.Raw {
			continue
		}
		out = append(out, ep.URL)
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
