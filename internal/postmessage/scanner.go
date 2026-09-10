// Package postmessage finds risky postMessage handlers and DOM sinks
// (Wave 1 item 18): 1 homepage GET plus up to 5 same-host JS assets,
// static regex analysis only. A file containing both a message listener
// (with e.data use) and a dangerous sink — without an origin check —
// is a Low finding. No code is executed and nothing is posted.
//
// Echo-guard: vendor/minified bundles are still analyzed (deterministic),
// but a file with an explicit origin allowlist check is silent.
package postmessage

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
func (s *Scanner) Name() string { return "postmessage" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

var (
	scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"']+)["']`)
	listenerRe  = regexp.MustCompile(`(?i)addEventListener\s*\(\s*["']message["']`)
	dataUseRe   = regexp.MustCompile(`(?i)\b(e|event)\s*\.\s*data\b`)
	sinkRe      = regexp.MustCompile(`(?i)(innerHTML|outerHTML|document\.write|eval\s*\(|location\s*=|location\.href\s*=|\.html\s*\()`)
	originChkRe = regexp.MustCompile(`(?i)(origin\s*===?\s*["']https?://|["']https?://[^"']+["']\s*===?\s*.*origin|allowedOrigins|trustedOrigins|e\.origin\b)`)
	postCallRe  = regexp.MustCompile(`(?i)\.postMessage\s*\([^,]+,\s*["']\*["']`)
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
	seen := map[string]bool{}
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
			continue // same-host only
		}
		abs.Fragment = ""
		if seen[abs.String()] {
			continue
		}
		seen[abs.String()] = true
		if body := get(abs.String()); body != "" {
			bodies[abs.String()] = body
		}
	}

	type hit struct{ where, kind string }
	var hits []hit
	for where, body := range bodies {
		// Risky receiver: listener + e.data + sink, no origin check.
		if listenerRe.MatchString(body) && dataUseRe.MatchString(body) && sinkRe.MatchString(body) && !originChkRe.MatchString(body) {
			hits = append(hits, hit{where, "message listener feeds e.data into a DOM sink without an origin check"})
			continue
		}
		// Wildcard sender is worth one note per scan at most.
		if postCallRe.MatchString(body) {
			hits = append(hits, hit{where, "postMessage with wildcard targetOrigin '*'"})
		}
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
			ID:              fmt.Sprintf("postmessage-risky-%d", i+1),
			Title:           "Risky postMessage handler: " + h.kind,
			Description:     fmt.Sprintf("Static analysis of %s found %s. Any framed page could deliver data into the sink (stored/persistent XSS primitive). Enforce event.origin === expected-origin before touching e.data. Reproduce: fetch the script and grep for addEventListener('message') + innerHTML/eval. No code was executed.", h.where, h.kind),
			Severity:        models.SeverityLow,
			Confidence:      models.ConfidenceMedium,
			Category:        models.CategoryVulnerability,
			CWE:             "CWE-940",
			Target:          sc.Target.Raw,
			URL:             h.where,
			Evidence:        models.Evidence{Observed: h.kind, Location: "static JS analysis"},
			Source:          models.SourceEndpoints,
			DetectionMethod: "postMessage/sink static analysis (postmessage, ≤6 requests)",
			Remediation:     "Check event.origin against an allowlist; avoid sinks on e.data.",
		})
	}
	return scanner.StageResult{Findings: findings}, nil
}
