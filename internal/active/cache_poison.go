package active

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

// cachePoisonRule detects web cache poisoning via the classic unkeyed-
// input oracle (PortSwigger Param Miner technique), with a confirmation
// step and an inert canary:
//
//  1. Baseline the page. Skipped when Vary covers the probe header
//     (keyed, not unkeyed), when Set-Cookie is present, or when an
//     authed context is active (personalized responses, not shared cache).
//     Pages that forbid caching (no-store/private) are also skipped.
//  2. Replay with unkeyed headers (X-Forwarded-Host and friends). A
//     reflected canary in a cacheable response is a candidate.
//  3. Re-request clean: if the first canary persists, the cache key
//     excludes our input and poisoning is CONFIRMED.
//
// Inert-canary persistence proof is intended practice: the confirmation
// re-request stores only a random harmless string, proving cache-key
// exclusion without polluting with attack content. Mutations are never
// sent: pages only, GET only. At most maxCachePages pages per scan;
// state lives on the rule instance (one per scan via DefaultRegistry).
type cachePoisonRule struct {
	mu     sync.Mutex
	probed map[string]bool
	pages  int
}

func (r *cachePoisonRule) ID() models.ActiveRuleID    { return "cache-poisoning-oracle" }
func (r *cachePoisonRule) Name() string               { return "Web Cache Poisoning Oracle" }
func (r *cachePoisonRule) Safety() models.SafetyLevel { return models.SafetyLowImpact }
func (r *cachePoisonRule) RequestBudget() int         { return 8 }

// maxCachePages bounds the oracle to a handful of pages per scan:
// poisoning checks are per-page, not per-vector.
const maxCachePages = 10

// unkeyedHeaders are inputs CDNs commonly exclude from cache keys.
var unkeyedHeaders = []string{
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
	"X-Forwarded-Scheme",
	"X-Original-URL",
}

// cacheCanary returns a DNS/host-safe random token.
// Ghost mode uses CacheCanary() from canary.go (no `anpu` substring).
func cacheCanary() string {
	if GhostEnabled {
		return CacheCanary()
	}
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return cacheCanaryFallback()
	}
	return "anpucache" + hex.EncodeToString(b)
}

func (r *cachePoisonRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}
	if v.Kind != models.VectorQueryParam && v.Kind != models.VectorPathSegment {
		return result, nil
	}
	page := stripQuery(v.URL)

	r.mu.Lock()
	if r.probed == nil {
		r.probed = map[string]bool{}
	}
	if r.probed[page] || r.pages >= maxCachePages {
		r.mu.Unlock()
		return result, nil
	}
	r.probed[page] = true
	r.pages++
	r.mu.Unlock()

	get := func(url string, headers map[string]string) (*anpuhttp.Response, bool) {
		var resp *anpuhttp.Response
		var err error
		if len(headers) == 0 {
			resp, err = client.Get(ctx, url)
		} else {
			resp, err = client.DoWithHeaders(ctx, "GET", url, headers)
		}
		result.RequestsMade++
		if err != nil || resp == nil {
			return nil, false
		}
		return resp, true
	}

	// --- Baseline: must look cacheable, else this is not our bug class ---
	base, ok := get(page, nil)
	if !ok || base.StatusCode != 200 {
		return result, nil
	}
	// Skip when Set-Cookie present (personalized, not shared cache).
	if base.Header != nil && base.Header.Get("Set-Cookie") != "" {
		return result, nil
	}
	if !looksCacheable(base) {
		return result, nil
	}

	// --- Probe unkeyed inputs for reflection ---
	canary := cacheCanary()
	for _, h := range unkeyedHeaders {
		if result.RequestsMade >= r.RequestBudget()-1 {
			break // keep one request of headroom for confirmation
		}
		// Skip when Vary covers the probe header (keyed, not unkeyed).
		if varyCovers(base, h) {
			continue
		}
		resp, ok := get(page, map[string]string{h: canary})
		if !ok {
			continue
		}
		if !reflectedCanary(resp, canary) {
			continue
		}
		// Reflected in a cacheable response: candidate. Confirm by
		// re-requesting clean — persistence proves cache-key exclusion.
		clean, ok := get(page, nil)
		if !ok {
			return poisonCandidate(result, v, h, canary), nil
		}
		if strings.Contains(string(clean.Body), canary) {
			result.Found = true
			result.Payload = h + ": " + canary
			result.Evidence = fmt.Sprintf(
				"CONFIRMED cache poisoning on %s: canary %q sent via unkeyed header %s persisted into a subsequent clean response. "+
					"The cache key excludes %s, so stored attacker content would serve to other visitors.",
				page, canary, h, h,
			)
			return result, nil
		}
		return poisonCandidate(result, v, h, canary), nil
	}
	return result, nil
}

// poisonCandidate builds the Medium-confidence result for reflection
// in a cacheable response without persistence proof.
func poisonCandidate(result models.ActiveRuleResult, v models.InputVector, header, canary string) models.ActiveRuleResult {
	result.Found = true
	result.Payload = header + ": " + canary
	result.Evidence = fmt.Sprintf(
		"Cache poisoning candidate on %s: canary %q sent via %s was reflected in a cacheable response, "+
			"but a clean re-request did not retain it (per-header cache key or short TTL). Review cache-key configuration.",
		stripQuery(v.URL), canary, header,
	)
	return result
}

// stripQuery returns the URL without query string or fragment.
func stripQuery(raw string) string {
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		return raw[:i]
	}
	return raw
}

// reflectedCanary reports whether the canary appears in the body or a
// redirect Location (hostile-host redirects are the classic primitive).
func reflectedCanary(resp *anpuhttp.Response, canary string) bool {
	if strings.Contains(string(resp.Body), canary) {
		return true
	}
	if resp.Header != nil && strings.Contains(resp.Header.Get("Location"), canary) {
		return true
	}
	return false
}

// varyCovers reports whether the baseline Vary header covers the probe
// header (or *), meaning the probe input is part of the cache key.
func varyCovers(base *anpuhttp.Response, probeHeader string) bool {
	if base == nil || base.Header == nil {
		return false
	}
	vary := base.Header.Get("Vary")
	if vary == "" {
		// Also check comma-joined values case-insensitively.
		vals := base.Header.Values("Vary")
		if len(vals) == 0 {
			return false
		}
		vary = strings.Join(vals, ",")
	}
	for _, part := range strings.Split(vary, ",") {
		p := strings.ToLower(strings.TrimSpace(part))
		if p == "*" || p == strings.ToLower(probeHeader) {
			return true
		}
	}
	return false
}

// looksCacheable reports whether a baseline response could plausibly be
// served from cache: explicit no-store/private disqualify (unless HIT
// markers prove caching), Set-Cookie always disqualifies (skip),
// positive Age/HIT markers or cache-friendly directives qualify.
func looksCacheable(resp *anpuhttp.Response) bool {
	h := resp.Header
	cc := ""
	if h != nil {
		cc = strings.ToLower(h.Get("Cache-Control"))
	}
	if h != nil && h.Get("Set-Cookie") != "" {
		return false
	}
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") || strings.Contains(cc, "no-cache") {
		return hasHitMarker(h)
	}
	if hasHitMarker(h) {
		return true
	}
	return strings.Contains(cc, "public") || strings.Contains(cc, "s-maxage") || strings.Contains(cc, "max-age")
}

// hasHitMarker reports positive cache-hit evidence (Age or HIT markers).
func hasHitMarker(h http.Header) bool {
	if len(h) == 0 {
		return false
	}
	if h.Get("Age") != "" {
		return true
	}
	for _, hdr := range []string{"X-Cache", "CF-Cache-Status", "X-Cache-Status", "X-App-Cache"} {
		v := strings.ToUpper(h.Get(hdr))
		if strings.Contains(v, "HIT") {
			return true
		}
	}
	return false
}

func (r *cachePoisonRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	severity := models.SeverityMedium
	confidence := models.ConfidenceMedium
	title := "Web cache poisoning candidate (unkeyed input reflected)"
	if strings.HasPrefix(res.Evidence, "CONFIRMED") {
		severity = models.SeverityHigh
		confidence = models.ConfidenceHigh
		title = "Web cache poisoning confirmed (unkeyed input persists in cache)"
	}
	return models.Finding{
		ID:    fmt.Sprintf("active-cache-poison-%d", time.Now().UnixNano()),
		Title: fmt.Sprintf("%s at %s", title, stripQuery(res.Vector.URL)),
		Description: fmt.Sprintf(
			"An input that caches commonly exclude from cache keys was reflected into a cacheable response at %s. "+
				"When the cache key excludes attacker input, poisoned responses (stored XSS, open redirects, defacement) serve to other visitors. %s",
			stripQuery(res.Vector.URL), res.Evidence,
		),
		Severity:        severity,
		Confidence:      confidence,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-444",
		OWASP:           "A04:2021 - Insecure Design",
		Target:          target,
		URL:             stripQuery(res.Vector.URL),
		Parameter:       res.Vector.Name,
		Source:          models.SourceActive,
		DetectionMethod: "cache-poisoning oracle: unkeyed-header canary reflected in cacheable response, clean re-request confirms persistence",
		Evidence: models.Evidence{
			Observed:       res.Evidence,
			Location:       stripQuery(res.Vector.URL),
			RequestSummary: fmt.Sprintf("GET %s (unkeyed header %s)", stripQuery(res.Vector.URL), res.Payload),
		},
		Impact:      "Stored attack content served from shared cache to other visitors: session theft via stored XSS, credential harvesting via poisoned redirects, site defacement.",
		Remediation: "Include all reflected inputs in the cache key (or strip them at the edge), disable caching of dynamic responses, and normalize Host/forwarded headers before cache lookup.",
		References: []string{
			"https://portswigger.net/web-security/web-cache-poisoning",
		},
		FirstSeen: time.Now(),
	}
}
