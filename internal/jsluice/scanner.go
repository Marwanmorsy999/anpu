// Package jsluice is ANPU's native port of BishopFox jsluice's URL
// extraction (upstream is archived and no longer builds on modern Go,
// with no Windows asset — so the technique is ported, not wrapped).
//
// Like jsluice, this stage harvests URL-shaped strings from shipped
// JavaScript and joins relative references against the asset's own
// location (browser-style resolution), plus a compact secret-regex
// pack over the same bodies. Same zero-extra-request contract as the
// secrets/jsintel pipeline: the only traffic is fetching the homepage
// and up to 8 same-host JS assets (≤9 requests) — discovered URLs are
// returned as endpoints for later stages to probe, never fetched here.
//
// Overlap note: secrets (jsintel routes) and jssecrets (40+ secret
// pack) cover adjacent ground. This port is greedier than jsintel's
// context-anchored patterns (it harvests every quoted URL-shaped
// string, including bare config-object URLs jsintel misses), and its
// secret findings reuse jssecrets' title/URL/CWE shape so true
// duplicates collapse in dedup instead of double-reporting.
package jsluice

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

// maxAssets bounds JS asset fetches (homepage + 8), maxEndpoints caps
// emitted endpoints, maxFindings caps secret findings.
const (
	maxAssets    = 8
	maxEndpoints = 40
	maxFindings  = 6
)

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "jsluice" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

var scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"']+)["']`)

// quotedRe harvests quoted/backtick string literals (jsluice's raw
// material); classification happens in extractURLs.
var quotedRe = regexp.MustCompile("['\"`]([^'\"`]{2,300})['\"`]")

// skippedExt are asset-ish suffixes that are never route endpoints.
var skippedExt = []string{
	".js", ".jsx", ".ts", ".tsx", ".map", ".css", ".scss",
	".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
	".woff", ".woff2", ".ttf", ".eot", ".otf",
	".mp4", ".webm", ".mp3", ".wav", ".pdf",
}

// skippedScheme are non-fetchable/misc schemes.
func skippedScheme(s string) bool {
	for _, p := range []string{
		"data:", "javascript:", "mailto:", "tel:", "blob:",
		"vbscript:", "about:", "chrome:", "file:",
	} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// hasSkippedExt reports an asset-like path suffix (query/fragment
// stripped before the check).
func hasSkippedExt(p string) bool {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	lower := strings.ToLower(p)
	for _, ext := range skippedExt {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// joinAssetURL resolves a harvested reference the way a browser (and
// jsluice) resolves it against the asset it was found in: absolute
// URLs pass through a same-host gate, protocol-relative URLs inherit
// the target scheme, root-absolute paths join on the target, and bare
// relative references resolve against the asset's directory.
// Anything cross-host, non-http(s), or escaping above the root ("..")
// resolves to "" (out of scope, never probed from here).
func joinAssetURL(ref, assetURL, targetRaw string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || skippedScheme(strings.ToLower(ref)) {
		return ""
	}
	// Never probe template slots, fragments, or query-only refs.
	if strings.Contains(ref, "${") || strings.HasPrefix(ref, "#") || strings.HasPrefix(ref, "?") {
		return ""
	}
	if strings.ContainsAny(ref, " \t\r\n<>\"'\\") {
		return ""
	}
	if strings.Contains(ref, "..") {
		return ""
	}
	target, err := url.Parse(targetRaw)
	if err != nil || target.Host == "" {
		return ""
	}
	scheme := target.Scheme
	if scheme != "http" && scheme != "https" {
		scheme = "https"
	}
	// Absolute URL: same-host only.
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		u, err := url.Parse(ref)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return ""
		}
		if !strings.EqualFold(u.Host, target.Host) {
			return ""
		}
		u.Fragment = ""
		return u.String()
	}
	// Protocol-relative: inherit the target scheme, same-host only.
	if strings.HasPrefix(ref, "//") {
		u, err := url.Parse(scheme + ":" + ref)
		if err != nil || !strings.EqualFold(u.Host, target.Host) {
			return ""
		}
		u.Fragment = ""
		return u.String()
	}
	// Root-absolute: asset extensions are includes, not routes.
	if strings.HasPrefix(ref, "/") {
		if hasSkippedExt(ref) {
			return ""
		}
		u := *target
		u.Fragment = ""
		if i := strings.Index(ref, "?"); i >= 0 {
			u.Path, u.RawQuery = ref[:i], ref[i+1:]
		} else {
			u.Path, u.RawQuery = ref, ""
		}
		if u.Path == "" {
			return ""
		}
		return u.String()
	}
	// Bare relative: must look link-like (a path or dotted name),
	// then resolve against the asset's directory.
	if !strings.ContainsAny(ref, "/.") || len(ref) < 3 {
		return ""
	}
	if hasSkippedExt(ref) {
		return ""
	}
	assetBase, err := url.Parse(assetURL)
	if err != nil || assetBase.Host == "" {
		return ""
	}
	dir := assetBase.Path
	if i := strings.LastIndex(dir, "/"); i >= 0 {
		dir = dir[:i+1]
	} else {
		dir = "/"
	}
	joined := dir + ref
	u := *target
	u.Fragment = ""
	// Keep the asset's host (same-host gate: the asset itself was
	// already gated at fetch time).
	u.Host = assetBase.Host
	if i := strings.Index(joined, "?"); i >= 0 {
		u.Path, u.RawQuery = joined[:i], joined[i+1:]
	} else {
		u.Path, u.RawQuery = joined, ""
	}
	if u.Path == "" {
		return ""
	}
	return u.String()
}

// extractURLs harvests every quoted URL-shaped string from a JS body
// and resolves it via joinAssetURL. Pure function over bytes (no
// requests) — capped and deterministically ordered.
func extractURLs(body, assetURL, targetRaw string, cap int) []models.Endpoint {
	seen := map[string]bool{}
	var out []models.Endpoint
	for _, m := range quotedRe.FindAllStringSubmatch(body, -1) {
		if len(m) < 2 || len(out) >= cap {
			break
		}
		raw := strings.TrimSpace(m[1])
		if raw == "" {
			continue
		}
		// URL-shaped only: absolute, protocol-relative, rooted, or a
		// relative ref containing a path separator. Dotted-only
		// strings (`.split(`, `Math.trunc(` in minified bundles) are
		// code fragments, not links — requiring `/` keeps them out.
		if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") &&
			!strings.HasPrefix(raw, "//") && !strings.HasPrefix(raw, "/") &&
			!strings.Contains(raw, "/") {
			continue
		}
		resolved := joinAssetURL(raw, assetURL, targetRaw)
		if resolved == "" || seen[resolved] {
			continue
		}
		seen[resolved] = true
		out = append(out, models.Endpoint{
			URL:      resolved,
			Category: models.EndpointAPI,
			Sources:  []string{"jsluice"},
		})
	}
	return out
}

type secretPattern struct {
	name string
	re   *regexp.Regexp
	sev  models.Severity
}

// secretPack is the compact jsluice-style secret set. Titles reuse
// jssecrets' "Embedded secret in JavaScript: <kind>" shape so
// identical hits merge in dedup instead of double-reporting.
func secretPack() []secretPattern {
	rx := regexp.MustCompile
	return []secretPattern{
		{"aws-access-key", rx(`\bAKIA[0-9A-Z]{16}\b`), models.SeverityHigh},
		{"google-api-key", rx(`\bAIza[0-9A-Za-z_\-]{35}\b`), models.SeverityHigh},
		{"github-token", rx(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`), models.SeverityHigh},
		{"gitlab-token", rx(`\bglpat-[A-Za-z0-9_\-]{20,}\b`), models.SeverityHigh},
		{"slack-token", rx(`\bxox[baprs]-[A-Za-z0-9\-]{10,}\b`), models.SeverityHigh},
		{"slack-webhook", rx(`https://hooks\.slack\.com/services/[A-Za-z0-9/]+`), models.SeverityHigh},
		{"stripe-live", rx(`\bsk_live_[A-Za-z0-9]{10,}\b`), models.SeverityHigh},
		{"private-key", rx(`-----BEGIN [A-Z ]*PRIVATE KEY-----`), models.SeverityHigh},
		{"twilio-sid", rx(`\bAC[0-9a-fA-F]{32}\b`), models.SeverityMedium},
		{"sendgrid-key", rx(`\bSG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b`), models.SeverityHigh},
		{"firebase-url", rx(`https://[a-z0-9\-]+\.firebaseio\.com`), models.SeverityMedium},
		{"mailgun-key", rx(`\bkey-[0-9a-f]{32}\b`), models.SeverityHigh},
		{"basic-auth-url", rx(`https?://[A-Za-z0-9_\-]+:[A-Za-z0-9_\-]+@[A-Za-z0-9.\-]+`), models.SeverityHigh},
		{"bearer-literal", rx(`(?i)bearer\s+[A-Za-z0-9_\-.]{24,}`), models.SeverityMedium},
	}
}

// secretHit is one masked secret observation. Pure function over
// bytes: matchSecrets scans body and returns distinct kind+sample
// hits in deterministic order.
type secretHit struct {
	where string
	kind  string
	sev   models.Severity
}

func matchSecrets(body, where string) []secretHit {
	seen := map[string]bool{}
	var hits []secretHit
	for _, p := range secretPack() {
		for _, m := range p.re.FindAllString(body, -1) {
			key := p.name + "|" + maskSecret(m)
			if seen[key] {
				continue
			}
			seen[key] = true
			hits = append(hits, secretHit{where: where, kind: p.name + ": " + maskSecret(m), sev: p.sev})
		}
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].where == hits[j].where {
			return hits[i].kind < hits[j].kind
		}
		return hits[i].where < hits[j].where
	})
	return hits
}

// maskSecret keeps a short prefix for triage and hides the rest.
func maskSecret(v string) string {
	v = strings.TrimSpace(v)
	if len(v) <= 8 {
		return "***"
	}
	return v[:4] + "***" + v[len(v)-3:]
}

// Run implements scanner.Scanner: homepage + up to 8 same-host JS
// assets, static harvest only (≤9 requests).
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
	bodies := map[string]string{}
	for _, m := range scriptSrcRe.FindAllStringSubmatch(home, -1) {
		if len(bodies) >= maxAssets {
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
	bodies[sc.Target.Raw+"#inline"] = home

	var endpoints []models.Endpoint
	var hits []secretHit
	seenEP := map[string]bool{}
	for where, body := range bodies {
		for _, ep := range extractURLs(body, where, sc.Target.Raw, maxEndpoints-len(endpoints)) {
			if seenEP[ep.URL] {
				continue
			}
			seenEP[ep.URL] = true
			endpoints = append(endpoints, ep)
		}
		hits = append(hits, matchSecrets(body, where)...)
	}
	sort.Slice(endpoints, func(i, j int) bool { return endpoints[i].URL < endpoints[j].URL })
	if len(endpoints) > maxEndpoints {
		endpoints = endpoints[:maxEndpoints]
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].where == hits[j].where {
			return hits[i].kind < hits[j].kind
		}
		return hits[i].where < hits[j].where
	})
	if len(hits) > maxFindings {
		hits = hits[:maxFindings]
	}
	var findings []models.Finding
	for i, h := range hits {
		kind := h.kind
		if j := strings.Index(kind, ":"); j > 0 {
			kind = kind[:j]
		}
		findings = append(findings, models.Finding{
			ID:              fmt.Sprintf("jsluice-%d", i+1),
			Title:           "Embedded secret in JavaScript: " + kind,
			Description:     "A shipped JavaScript file contains a secret-shaped string (" + h.kind + "). Anything in client JS is public — move the secret server-side and rotate it; validity was NOT tested (keyless). Values are masked below.",
			Severity:        h.sev,
			Confidence:      models.ConfidenceMedium,
			Category:        models.CategoryExposure,
			CWE:             "CWE-798",
			Target:          sc.Target.Raw,
			URL:             h.where,
			Evidence:        models.Evidence{Observed: h.kind, Location: "shipped JavaScript (value masked)"},
			Source:          models.SourceCustom,
			DetectionMethod: "JS URL + secret harvest (jsluice native port, ≤9 requests)",
			Remediation:     "Remove the secret from client code; rotate it.",
		})
	}
	return scanner.StageResult{Findings: findings, Endpoints: endpoints}, nil
}
