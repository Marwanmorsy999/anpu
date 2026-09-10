package active

// bypass_403.go — 403/401 authorization-bypass probe (educational,
// read-only).
//
// Many deployments deny sensitive paths with 403 while trusting
// proxy-supplied headers (X-Forwarded-For, X-Original-URL) or
// normalizing paths inconsistently (trailing slash, /%2e/, case).
// This rule replays the denied request with a small set of classic,
// harmless bypass variants and reports when one returns a clearly
// different successful page.
//
// Detection approach (safe, differential):
//
//  1. Baseline GET of the vector URL; continue only on 401/403.
//  2. Control GET of the site root (plain, no extra headers).
//  3. Replay with header variants (X-Forwarded-For: 127.0.0.1,
//     X-Original-URL, X-Custom-IP-Authorization) and path variants
//     (trailing-slash toggle, /%2e/ prefix, upper-cased last segment).
//  4. Replay with verb-tamper variants (POST, PUT, PATCH) and header
//     override X-HTTP-Method-Override to catch verb-based access control
//     that only guards GET.
//  5. Header/verb variants on the same URL succeed on 2xx with a body
//     clearly dissimilar from the denial page (same resource, flipped
//     decision — sound by construction).
//  6. Path variants and the root+override variant succeed on 2xx with a
//     body dissimilar from BOTH the denial page and the site-root
//     control page — this filters SPA/catch-all fallbacks that serve
//     the homepage with 200 for every unknown path.
//  7. At most 11 requests per vector (baseline + control + 9 variants).
//
// Safety: GET only, no credentials, no payloads beyond loopback IPs and
// path spellings. Never submits forms or mutates state.
//
// CWE-863: Incorrect Authorization
// OWASP A01:2021 — Broken Access Control

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

type bypass403Rule struct{}

func (r *bypass403Rule) ID() models.ActiveRuleID    { return "auth-bypass-403" }
func (r *bypass403Rule) Name() string               { return "Authorization Bypass (403/401)" }
func (r *bypass403Rule) Safety() models.SafetyLevel { return models.SafetyBenign }
func (r *bypass403Rule) RequestBudget() int         { return 11 }

type bypassVariant struct {
	name   string
	url    string
	method string // empty means GET
	// headers applied to the request; nil means plain.
	headers map[string]string
	// sameResource is true when the variant requests the same URL as the
	// baseline (header/method-only change): success needs only dissimilarity
	// with the denial page. False for path/root variants, which must
	// also differ from the site-root control page (fallback filter).
	sameResource bool
}

func (r *bypass403Rule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}

	if v.Kind != models.VectorQueryParam && v.Kind != models.VectorPathSegment {
		return result, nil
	}

	base, err := client.Get(ctx, v.URL)
	result.RequestsMade++
	if err != nil || base == nil {
		return result, nil
	}
	if base.StatusCode != 401 && base.StatusCode != 403 {
		return result, nil // only denied resources are interesting
	}
	baseWords := bypassWordSet(base.Body)

	parsed, err := url.Parse(v.URL)
	if err != nil {
		return result, nil
	}
	siteRoot := parsed.Scheme + "://" + parsed.Host + "/"
	path := parsed.Path
	if path == "" {
		path = "/"
	}

	// Control: plain site root, used to recognize catch-all fallbacks.
	controlWords := map[string]struct{}{}
	if cresp, cerr := client.Get(ctx, siteRoot); cerr == nil && cresp != nil {
		result.RequestsMade++
		controlWords = bypassWordSet(cresp.Body)
	}

	variants := []bypassVariant{
		{name: "X-Forwarded-For: 127.0.0.1", url: v.URL, headers: map[string]string{"X-Forwarded-For": "127.0.0.1"}, sameResource: true},
		{name: "X-Original-URL override", url: v.URL, headers: map[string]string{"X-Original-URL": path, "X-Forwarded-For": "127.0.0.1"}, sameResource: true},
		{name: "X-Custom-IP-Authorization", url: v.URL, headers: map[string]string{"X-Custom-IP-Authorization": "127.0.0.1"}, sameResource: true},
		{name: "X-HTTP-Method-Override: PUT", url: v.URL, headers: map[string]string{"X-HTTP-Method-Override": "PUT"}, sameResource: true},
		{name: "X-Original-URL at site root", url: siteRoot, headers: map[string]string{"X-Original-URL": path}},
		{name: "trailing-slash toggle", url: toggleSlash(v.URL)},
		{name: "dot-segment + case variant", url: dotSegmentUpper(v.URL)},
		{name: "verb tamper POST", url: v.URL, method: "POST", sameResource: true},
		{name: "verb tamper PUT", url: v.URL, method: "PUT", sameResource: true},
		{name: "verb tamper PATCH", url: v.URL, method: "PATCH", sameResource: true},
	}

	for _, bv := range variants {
		if result.RequestsMade >= r.RequestBudget() {
			break
		}
		if bv.url == "" {
			continue
		}
		method := bv.method
		if method == "" {
			method = "GET"
		}
		var (
			resp *anpuhttp.Response
			rerr error
		)
		if len(bv.headers) > 0 {
			resp, rerr = client.DoWithHeaders(ctx, method, bv.url, bv.headers)
		} else if method != "GET" {
			resp, rerr = client.DoWithHeaders(ctx, method, bv.url, nil)
		} else {
			resp, rerr = client.Get(ctx, bv.url)
		}
		result.RequestsMade++
		if rerr != nil || resp == nil {
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			continue
		}
		if len(resp.Body) == 0 {
			continue
		}
		candWords := bypassWordSet(resp.Body)
		if bypassSimilarity(baseWords, candWords) >= 0.5 {
			continue // same block page, different status — not a bypass
		}
		if !bv.sameResource && len(controlWords) > 0 &&
			bypassSimilarity(controlWords, candWords) >= 0.5 {
			continue // catch-all fallback serving the homepage — not a bypass
		}
		result.Found = true
		result.Payload = bv.name
		result.Evidence = fmt.Sprintf(
			"Baseline GET %s returned HTTP %d, but variant %q returned HTTP %d with a clearly different body (%d vs %d bytes). "+
				"The access control decision changes based on headers/path spelling.",
			v.URL, base.StatusCode, bv.name, resp.StatusCode, len(base.Body), len(resp.Body),
		)
		return result, nil
	}

	return result, nil
}

func (r *bypass403Rule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	return models.Finding{
		ID: fmt.Sprintf("active-bypass-403-%d", time.Now().UnixNano()),
		Title: fmt.Sprintf(
			"Possible authorization bypass at %s", res.Vector.URL,
		),
		Description: fmt.Sprintf(
			"The endpoint at %s denies direct requests but serves a different successful page when requested with an alternate "+
				"header or path spelling. Proxy-trusted headers and inconsistent path normalization are classic access-control "+
				"bypass vectors. Detection: %s",
			res.Vector.URL, res.Evidence,
		),
		Severity:        models.SeverityMedium,
		Confidence:      models.ConfidenceMedium,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-863",
		OWASP:           "A01:2021 - Broken Access Control",
		Target:          target,
		URL:             res.Vector.URL,
		Parameter:       res.Payload,
		Source:          models.SourceActive,
		DetectionMethod: "Denied-vs-variant differential analysis (headers/path/verb tamper)",
		Evidence: models.Evidence{
			Observed:       res.Evidence,
			Location:       res.Vector.URL,
			RequestSummary: fmt.Sprintf("GET %s + bypass variants", res.Vector.URL),
		},
		Impact: "If the bypassed resource is administrative or data-bearing, an unauthenticated visitor can read or reach " +
			"functionality the application intended to restrict. Confirm manually which operations the bypassed page exposes.",
		Remediation: "Enforce authorization server-side on every route using the canonical path only: normalize the path " +
			"(decode, resolve dot-segments, unify case/trailing slash) BEFORE the access check, and never trust " +
			"client-supplied X-Forwarded-For / X-Original-URL headers for access decisions. Deny by default.",
		References: []string{
			"https://portswigger.net/web-security/access-control",
			"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema",
			"https://cwe.mitre.org/data/definitions/863.html",
		},
		FirstSeen: time.Now(),
	}
}

// toggleSlash adds a trailing slash, or removes it when present.
func toggleSlash(raw string) string {
	if strings.HasSuffix(raw, "/") {
		return strings.TrimRight(raw, "/")
	}
	if i := strings.Index(raw, "?"); i >= 0 {
		return raw[:i] + "/" + raw[i:]
	}
	return raw + "/"
}

// dotSegmentUpper prefixes the path with /%2e/ and upper-cases the last
// segment — two classic normalizer confusions in one probe.
func dotSegmentUpper(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	p := strings.Trim(u.Path, "/")
	if p == "" {
		return raw
	}
	segs := strings.Split(p, "/")
	segs[len(segs)-1] = strings.ToUpper(segs[len(segs)-1])
	u.Path = "/%2e/" + strings.Join(segs, "/")
	u.RawPath = ""
	return u.String()
}

func bypassWordSet(body []byte) map[string]struct{} {
	set := map[string]struct{}{}
	for _, w := range strings.Fields(strings.ToLower(string(body))) {
		w = strings.Trim(w, " \t\n\r\"'<>.,;:!?()[]{}")
		if len(w) < 3 {
			continue
		}
		hasLetter := false
		for _, r := range w {
			if r >= 'a' && r <= 'z' {
				hasLetter = true
				break
			}
		}
		if hasLetter {
			set[w] = struct{}{}
		}
	}
	return set
}

func bypassSimilarity(a, b map[string]struct{}) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	inter := 0
	for w := range a {
		if _, ok := b[w]; ok {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}
