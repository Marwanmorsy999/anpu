package active

import (
	"context"
	"fmt"
	"sort"
	"strings"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/params"
	"github.com/anpu-project/anpu/internal/route"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// Scanner is the pipeline stage for Phase 4 safe active testing.
// It extracts input vectors from discovered endpoints, runs every
// registered rule against every vector, and emits findings.
type Scanner struct {
	client   *anpuhttp.Client
	registry *Registry
}

// New returns an active.Scanner with the default rule registry.
func New(client *anpuhttp.Client) *Scanner {
	return &Scanner{
		client:   client,
		registry: DefaultRegistry(),
	}
}

func (s *Scanner) Name() string                     { return "active-tester" }
func (s *Scanner) Available(_ context.Context) bool { return true }

// Run iterates over all discovered endpoints, extracts input vectors,
// and runs every rule against every vector within its declared budget.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	if len(sc.Endpoints) == 0 {
		return scanner.StageResult{
			Warnings: []string{"active-tester: no endpoints discovered; nothing to probe"},
		}, nil
	}

	var findings []models.Finding
	var warnings []string
	totalVectors := 0
	totalProbes := 0

	// Route sampling: when the target exposes many endpoints with the
	// same shape, sample 3–5 per group to bound volume while preserving
	// coverage (Grade F 9.0 needs max + volume, not exhaustive spam).
	endpoints := sc.Endpoints
	if len(endpoints) > 10 {
		sampled := route.Sample(endpoints)
		if len(sampled) < len(endpoints) {
			warnings = append(warnings, fmt.Sprintf("active-tester: sampled %d endpoints down to %d via route classifier (3–5 per shape)", len(endpoints), len(sampled)))
		}
		endpoints = sampled
	}

	// Soft-404 detector (mirrors dirs.go:122,176) for gating low-value
	// endpoints. Fail-open: nil detector means no filtering.
	soft404 := newSoft404Detector(ctx, s.client.WithAuth(sc.Auth.RequestHeaders()), sc.Target.Raw)

	// pageOracle probes paramless pages for cache poisoning. The
	// vector loop below cannot reach them (no injectable locations),
	// but cached marketing pages are prime poisoning targets.
	pageOracle := &cachePoisonRule{}

	for _, ep := range endpoints {
		// Skip static assets — low value for active testing.
		if ep.Category == models.EndpointAsset {
			continue
		}

		select {
		case <-ctx.Done():
			warnings = append(warnings, "active-tester: context cancelled, stopped early")
			return scanner.StageResult{Findings: findings, Warnings: warnings}, nil
		default:
		}

		// Gate: status!=200 || CT!~html/json || soft404>0.85 → skip low-value endpoints.
		if shouldSkipEndpoint(ctx, s.client.WithAuth(sc.Auth.RequestHeaders()), soft404, ep) {
			continue
		}

		vectors := ExtractVectors(ep)
		vectors = append(vectors, apiVectorsFor(ep)...)
		// Priority order: classified (attacker-interesting) parameter
		// names first, so interrupted or budgeted scans keep the
		// highest-value probes. Stable sort preserves discovery order
		// within each class.
		sort.SliceStable(vectors, func(i, j int) bool {
			return len(params.Classify(vectors[i].Name)) > len(params.Classify(vectors[j].Name))
		})
		// WebSocket vectors are adversarial WS targets (jsintel).
		if strings.HasPrefix(strings.ToLower(ep.URL), "ws://") || strings.HasPrefix(strings.ToLower(ep.URL), "wss://") {
			vectors = append(vectors, models.InputVector{URL: ep.URL, Kind: models.VectorWebSocket, Name: ep.URL})
		}
		if len(vectors) == 0 {
			// No injectable locations: only the page-level cache
			// oracle can do anything here. Skipped when authed
			// (personalized, not shared cache).
			if ep.Category == models.EndpointPage && !sc.Auth.IsAuthenticated() {
				totalVectors++
				result, err := pageOracle.Test(ctx, s.client.WithAuth(sc.Auth.RequestHeaders()), models.InputVector{
					URL:  ep.URL,
					Kind: models.VectorQueryParam,
				})
				totalProbes += result.RequestsMade
				if err != nil {
					warnings = append(warnings, fmt.Sprintf(
						"active-tester: rule %s on %s: %v",
						pageOracle.ID(), ep.URL, err,
					))
				} else if result.Found {
					findings = append(findings, pageOracle.ToFinding(result, sc.Target.Raw))
				}
			}
			continue
		}

		totalVectors += len(vectors)

		for _, vec := range vectors {
			for _, rule := range s.registry.Rules() {
				// Adversarial hazardous probes require explicit opt-in --adversarial --confirm-authorized.
				if isAdversarialRule(rule.ID()) && !IsAdversarialEnabled() {
					continue
				}
				// Skip cache oracle when authed (personalized responses).
				if sc.Auth.IsAuthenticated() && rule.ID() == "cache-poisoning-oracle" {
					continue
				}
				select {
				case <-ctx.Done():
					return scanner.StageResult{Findings: findings, Warnings: warnings}, nil
				default:
				}

				result, err := rule.Test(ctx, s.client.WithAuth(sc.Auth.RequestHeaders()), vec)
				totalProbes += result.RequestsMade
				if err != nil {
					warnings = append(warnings, fmt.Sprintf(
						"active-tester: rule %s on %s[%s]: %v",
						rule.ID(), ep.URL, vec.Name, err,
					))
					continue
				}
				if result.Found {
					findings = append(findings, rule.ToFinding(result, sc.Target.Raw))
				}
			}
		}
	}

	// --- XML body pass (Phase 12: XXE detection) ---
	// ExtractXMLVectors identifies POST/PUT endpoints that accept XML.
	// The xxeRule handles VectorXMLBody; all other rules no-op via their guard.
	xmlVectors := ExtractXMLVectors(endpoints)
	for _, vec := range xmlVectors {
		select {
		case <-ctx.Done():
			warnings = append(warnings, "active-tester: context cancelled during XML pass")
			return scanner.StageResult{Findings: findings, Warnings: warnings}, nil
		default:
		}

		totalVectors++

		for _, rule := range s.registry.Rules() {
			if isAdversarialRule(rule.ID()) && !IsAdversarialEnabled() {
				continue
			}
			select {
			case <-ctx.Done():
				return scanner.StageResult{Findings: findings, Warnings: warnings}, nil
			default:
			}

			result, err := rule.Test(ctx, s.client.WithAuth(sc.Auth.RequestHeaders()), vec)
			totalProbes += result.RequestsMade
			if err != nil {
				warnings = append(warnings, fmt.Sprintf(
					"active-tester: rule %s on XML vector %s: %v",
					rule.ID(), vec.URL, err,
				))
				continue
			}
			if result.Found {
				findings = append(findings, rule.ToFinding(result, sc.Target.Raw))
			}
		}
	}

	if sc.Verbose {
		warnings = append(warnings, fmt.Sprintf(
			"active-tester: tested %d vectors across %d endpoints (%d HTTP probes)",
			totalVectors, len(endpoints), totalProbes,
		))
	}

	// Platform-artifact filter: managed edges answer Host-header and
	// cache probes in expected ways. Demoted items become warnings so
	// the decision is visible; unknown stacks fail open (no filtering).
	filtered, platWarnings := platformFilter(findings, sc.Technologies)
	findings = filtered
	warnings = append(warnings, platWarnings...)

	// Sibling merge: the same differential firing on many same-shape
	// URLs (blog slugs, paginated routes) is one issue, not N. Group by
	// detection method + parameter + CWE and fold sibling URLs into a
	// single finding so volume can't inflate the grade.
	findings = mergeSiblingFindings(findings)

	return scanner.StageResult{Findings: findings, Warnings: warnings}, nil
}

// mergeSiblingFindings folds findings that share detection method,
// parameter, and CWE but differ only by URL into the first finding,
// listing the sibling URLs in evidence. Groups of one pass through.
func mergeSiblingFindings(in []models.Finding) []models.Finding {
	groups := map[string][]int{}
	order := []string{}
	for i, f := range in {
		if f.Parameter == "" {
			continue
		}
		key := f.DetectionMethod + "\x00" + f.Parameter + "\x00" + f.CWE + "\x00" + string(f.Severity)
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], i)
	}
	mergedIdx := map[int]bool{}
	for _, key := range order {
		idx := groups[key]
		if len(idx) < 2 {
			continue
		}
		// Confirm the URLs actually differ (guard against grouping
		// distinct params that share a name).
		urls := []string{}
		seen := map[string]bool{}
		for _, j := range idx {
			if u := in[j].URL; u != "" && !seen[u] {
				seen[u] = true
				urls = append(urls, u)
			}
		}
		if len(urls) < 2 {
			continue
		}
		keep := idx[0]
		listed := urls
		extra := ""
		if len(listed) > 5 {
			extra = fmt.Sprintf(" (+%d more)", len(listed)-5)
			listed = listed[:5]
		}
		in[keep].Evidence.Observed += fmt.Sprintf("\nAlso observed at %d sibling URL(s): %s%s", len(urls)-1, strings.Join(listed[1:], ", "), extra)
		for _, j := range idx[1:] {
			mergedIdx[j] = true
		}
	}
	if len(mergedIdx) == 0 {
		return in
	}
	out := make([]models.Finding, 0, len(in)-len(mergedIdx))
	for i, f := range in {
		if !mergedIdx[i] {
			out = append(out, f)
		}
	}
	return out
}

// shouldSkipEndpoint implements the active gate: skip endpoints that
// are not 200, not html/json, or are soft-404 >0.85. Fail-open on
// network errors so transient failures don't hide real surface.
func shouldSkipEndpoint(ctx context.Context, client *anpuhttp.Client, det *soft404Detector, ep models.Endpoint) bool {
	// WebSocket endpoints are not HTTP — never gate them as soft-404.
	if strings.HasPrefix(strings.ToLower(ep.URL), "ws://") || strings.HasPrefix(strings.ToLower(ep.URL), "wss://") {
		return false
	}
	// Quick probe of the endpoint itself (no injection).
	resp, err := client.Get(ctx, ep.URL)
	if err != nil || resp == nil {
		return false // fail-open
	}
	if resp.StatusCode != 200 {
		return true
	}
	ct := resp.Header.Get("Content-Type")
	if !isHTMLorJSON(ct) {
		return true
	}
	if det != nil && det.soft404Score(resp) > 0.85 {
		return true
	}
	if det != nil && det.isSoft404(resp) {
		return true
	}
	return false
}
