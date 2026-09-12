// Package gfclassify tags discovered URLs with GF-style vulnerability
// patterns (Wave 1 item 50): fully offline classification of
// sc.Endpoints by parameter name into xss/sqli/ssrf/redirect/lfi/rce/
// ssti/idor buckets. Zero requests. Buckets with hits become one Info
// finding each (cap 4) naming example parameters — prioritization intel
// for the Active stage, which consumes the same endpoint list.
package gfclassify

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"context"

	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// buckets maps GF pattern → param-name fragments (lowercase).
func buckets() map[string][]string {
	return map[string][]string{
		"xss":      {"q", "query", "search", "keyword", "name", "message", "comment", "text", "title", "input"},
		"sqli":     {"id", "user_id", "uid", "pid", "cid", "cat", "category", "product", "item", "order_id"},
		"ssrf":     {"url", "uri", "link", "src", "dest", "redirect_uri", "feed", "image_url", "webhook", "callback_url"},
		"redirect": {"next", "redirect", "return", "continue", "dest", "target", "r", "u", "ref", "callback"},
		"lfi":      {"file", "page", "path", "include", "template", "doc", "folder", "load", "pg", "view"},
		"rce":      {"cmd", "exec", "command", "run", "shell", "ping", "host", "ip"},
		"ssti":     {"template", "name", "message", "greeting", "hello", "preview"},
		"idor":     {"id", "user_id", "account_id", "order_id", "invoice", "doc_id"},
	}
}

// Scanner implements scanner.Scanner.
type Scanner struct{}

// New builds a Scanner.
func New() *Scanner { return &Scanner{} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "gfclassify" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

// classify buckets param names (pure, tested).
func classify(params []string) map[string][]string {
	b := buckets()
	hits := map[string][]string{}
	seen := map[string]map[string]bool{}
	for _, p := range params {
		lp := strings.ToLower(p)
		for bucket, frags := range b {
			for _, f := range frags {
				if lp == f || strings.HasSuffix(lp, "_"+f) || strings.HasPrefix(lp, f+"_") {
					if seen[bucket] == nil {
						seen[bucket] = map[string]bool{}
					}
					if !seen[bucket][p] {
						seen[bucket][p] = true
						hits[bucket] = append(hits[bucket], p)
					}
					break
				}
			}
		}
	}
	return hits
}

// Run implements scanner.Scanner.
func (s *Scanner) Run(_ context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	var params []string
	seen := map[string]bool{}
	for _, ep := range sc.Endpoints {
		u, err := url.Parse(ep.URL)
		if err != nil {
			continue
		}
		for k := range u.Query() {
			if !seen[k] {
				seen[k] = true
				params = append(params, k)
			}
		}
	}
	if len(params) == 0 {
		return scanner.StageResult{}, nil
	}
	hits := classify(params)
	if len(hits) == 0 {
		return scanner.StageResult{}, nil
	}
	names := make([]string, 0, len(hits))
	for n := range hits {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) > 4 {
		names = names[:4]
	}
	var findings []models.Finding
	for _, n := range names {
		pp := hits[n]
		sort.Strings(pp)
		shown := pp
		if len(shown) > 8 {
			shown = shown[:8]
		}
		findings = append(findings, models.Finding{
			ID: "gfclassify-" + n, Title: fmt.Sprintf("GF pattern %q: %d parameter(s) (%s)", n, len(pp), strings.Join(shown, ", ")),
			Description: fmt.Sprintf("Discovered parameters match the GF %q pattern class: prioritize them for %s testing in follow-up work. Offline classification — zero requests. Reproduce: list endpoint query names and match the GF pattern lists.", n, n),
			Severity:    models.SeverityInfo, Confidence: models.ConfidenceHigh, Category: models.CategoryExposure,
			Target:   sc.Target.Raw,
			Evidence: models.Evidence{Observed: fmt.Sprintf("%s: %s", n, strings.Join(shown, ", ")), Location: "endpoint parameter names"},
			Source:   models.SourceEndpoints, DetectionMethod: "GF-pattern URL classifier (gfclassify, offline)",
		})
	}
	return scanner.StageResult{Findings: findings}, nil
}
