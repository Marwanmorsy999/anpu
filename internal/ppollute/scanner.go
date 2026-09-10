// Package ppollute finds client-side prototype pollution shape (Wave
// next, item 5): homepage plus up to 5 same-host JS assets are scanned
// statically for dangerous merge sinks (jQuery.extend deep, lodash
// merge/defaultsDeep, custom deepMerge/deepExtend/recursive assign)
// fed by attacker-controlled sources (location.hash/search,
// postMessage data, JSON-parsed fragments) without a key blocklist
// (__proto__/constructor/prototype). Static analysis only — nothing
// executes, nothing is posted. ≤6 requests.
package ppollute

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// maxAssets bounds JS asset fetches (1 homepage + 5 assets = 6 requests).
const maxAssets = 5

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "ppollute" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

var (
	scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"']+)["']`)
	sinkRe      = regexp.MustCompile(`(?i)(\$\.extend\s*\(\s*true|_\.(merge|defaultsDeep|assignIn|extend)\s*\(|deepMerge\s*\(|deepExtend\s*\(|mergeDeep\s*\(|recursiveAssign\s*\()`)
	sourceRe    = regexp.MustCompile(`(?i)(location\.hash|location\.search|URLSearchParams|e\.data|event\.data|JSON\.parse\s*\(\s*(location|document\.location))`)
	guardRe     = regexp.MustCompile(`(?i)(__proto__|constructor\s*===|prototype\s*===|isPrototypeOf|blocklist|denylist|sanitizeKey|safeKey)`)
)

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	made := 0
	get := func(u string) string {
		if made >= 1+maxAssets {
			return ""
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		made++
		resp, err := s.client.Get(cctx, u)
		if err != nil || resp == nil {
			return ""
		}
		if len(resp.Body) > 1024*1024 {
			return string(resp.Body[:1024*1024])
		}
		return string(resp.Body)
	}

	home := get(sc.Target.Raw)
	if home == "" {
		return scanner.StageResult{}, nil
	}
	base, err := url.Parse(sc.Target.Raw)
	if err != nil {
		return scanner.StageResult{}, nil
	}
	bodies := map[string]string{"[inline]": home}
	for _, m := range scriptSrcRe.FindAllStringSubmatch(home, -1) {
		if len(bodies) > maxAssets {
			break
		}
		ref, err := url.Parse(strings.TrimSpace(m[1]))
		if err != nil {
			continue
		}
		abs := base.ResolveReference(ref)
		if abs.Scheme != "http" && abs.Scheme != "https" {
			continue
		}
		if !strings.EqualFold(abs.Hostname(), sc.Target.Host) {
			continue
		}
		abs.Fragment = ""
		if _, ok := bodies[abs.String()]; ok {
			continue
		}
		if body := get(abs.String()); body != "" {
			bodies[abs.String()] = body
		}
	}

	type hit struct{ where, kind string }
	var hits []hit
	for where, body := range bodies {
		if !sinkRe.MatchString(body) || !sourceRe.MatchString(body) || guardRe.MatchString(body) {
			continue
		}
		hits = append(hits, hit{where, "deep-merge sink fed by URL/message input without key blocklist"})
	}
	if len(hits) == 0 {
		return scanner.StageResult{}, nil
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].where < hits[j].where })
	if len(hits) > 4 {
		hits = hits[:4]
	}
	var findings []models.Finding
	for i, h := range hits {
		findings = append(findings, models.Finding{
			ID: fmt.Sprintf("ppollute-shape-%d", i+1), Title: "Prototype-pollution shape: " + h.kind,
			Description: fmt.Sprintf("Static analysis of %s found %s. Confirm manually with an inert __proto__ probe in a test browser; never ship a merge of untrusted objects. Reproduce: fetch the script and grep deep-merge calls fed by location.*. No code was executed.", h.where, h.kind),
			Severity:    models.SeverityLow, Confidence: models.ConfidenceMedium, Category: models.CategoryVulnerability,
			CWE: "CWE-1321", Target: sc.Target.Raw, URL: h.where,
			Evidence: models.Evidence{Observed: h.kind, Location: "static JS analysis"},
			Source:   models.SourceEndpoints, DetectionMethod: "merge-sink/source static analysis (ppollute, ≤6 requests)",
			Remediation: "Block __proto__/constructor/prototype keys; use safe merge libs.",
		})
	}
	return scanner.StageResult{Findings: findings}, nil
}
