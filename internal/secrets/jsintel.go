package secrets

// jsintel.go — JavaScript intelligence: hidden routes, DOM-XSS sinks.
//
// Beyond secret regexes, shipped JS bundles reveal attack surface:
// client-side routes, API paths, and dangerous sinks. This file feeds
// three outputs from already-fetched asset bodies (no extra requests):
//
//  1. Routes → returned as Endpoints so the pipeline (Active, AuthZ,
//     Dirs follow-ups) probes them like any discovered URL.
//  2. Sinks  → one informational finding per asset listing distinct
//     DOM-XSS sink families (innerHTML, eval, document.write, ...).
//  3. Secrets handled by rules in secrets.go (extended pack there).

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/anpu-project/anpu/pkg/models"
)

// jsRoutePatterns extracts candidate paths/URLs from JS source:
// quoted absolute paths, fetch/axios/XHR calls, router pushes, and
// template-literal URLs.
var jsRoutePatterns = []*regexp.Regexp{
	// fetch("/api/x"), axios.get('/y'), $.ajax({url: "/z"})
	regexp.MustCompile(`(?i)(?:fetch|axios\.(?:get|post|put|patch|delete|request)|\$\.(?:get|post|ajax)|XMLHttpRequest)\s*\(\s*["'\x60]([^"'\x60]{2,200})["'\x60]`),
	// url: "/path" inside ajax/fetch option objects
	regexp.MustCompile(`(?i)\burl\s*:\s*["'\x60]([^"'\x60]{2,200})["'\x60]`),
	// router.push("/x"), navigate('/y'), history.push("/z")
	regexp.MustCompile(`(?i)(?:router\.push|navigate|history\.push|redirect\s*\(\s*)["'\x60]([^"'\x60]{2,200})["'\x60]`),
	// generic quoted absolute paths (LinkFinder-style core)
	regexp.MustCompile(`["'\x60](/[A-Za-z0-9_\-\.~/%{}]{1,160})["'\x60]`),
}

// wsRoutePattern extracts WebSocket endpoints (ws://, wss://) for adversarial
// WebSocket vector generation. These are returned as VectorWebSocket candidates.
var wsRoutePattern = regexp.MustCompile(`(?i)["'\x60]\s*(wss?://[^"'\x60\s]{5,200})["'\x60]`)

// jsAssetExt are skipped: binary-ish or style assets, never routes.
func jsRouteSkipped(path string) bool {
	lower := strings.ToLower(path)
	// Strip query/fragment for the extension check.
	if i := strings.IndexAny(lower, "?#"); i >= 0 {
		lower = lower[:i]
	}
	for _, ext := range []string{
		".js", ".jsx", ".ts", ".tsx", ".map", ".css", ".scss",
		".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
		".woff", ".woff2", ".ttf", ".eot", ".otf",
		".mp4", ".webm", ".mp3", ".wav", ".pdf",
	} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// extractJSRoutes resolves candidate routes found in a JS body against
// the scan target. Only same-host http(s) URLs are returned, capped.
// Relative references resolve against the asset's own directory (correct
// for bundled dynamic import() chunks); template ${...} segments are
// stripped and the static remainder kept when still a clean path.
func extractJSRoutes(body, assetURL, targetRaw string, cap int) []models.Endpoint {
	target, err := url.Parse(targetRaw)
	if err != nil || target.Host == "" {
		return nil
	}
	assetBase, _ := url.Parse(assetURL)
	seen := map[string]bool{}
	var out []models.Endpoint
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "data:") || strings.HasPrefix(raw, "javascript:") {
			return
		}
		// Strip ${...} template slots; keep the static remainder only
		// when it is still a meaningful path (e.g. /api/users/${id}
		// implies the /api/users/ collection). Bare prefixes like
		// /api/ stay skipped — too generic to probe.
		if strings.Contains(raw, "${") {
			raw = templateSlotPattern.ReplaceAllString(raw, "")
			if strings.ContainsAny(raw, "{}()<>\"'\\") || !strings.HasPrefix(raw, "/") || len(raw) < 8 {
				return
			}
		}
		var resolved string
		switch {
		case strings.HasPrefix(raw, "ws://") || strings.HasPrefix(raw, "wss://"):
			u, err := url.Parse(raw)
			if err != nil || !strings.EqualFold(u.Host, target.Host) {
				return // cross-origin WS hosts out of scope
			}
			u.Fragment = ""
			resolved = u.String()
		case strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://"):
			u, err := url.Parse(raw)
			if err != nil || !strings.EqualFold(u.Host, target.Host) {
				return // cross-origin API hosts are out of scope for probing
			}
			u.Fragment = ""
			resolved = u.String()
		case strings.HasPrefix(raw, "/"):
			if jsRouteSkipped(raw) {
				return
			}
			u := *target
			u.Fragment = ""
			if i := strings.Index(raw, "?"); i >= 0 {
				u.Path, u.RawQuery = raw[:i], raw[i+1:]
			} else {
				u.Path, u.RawQuery = raw, ""
			}
			resolved = u.String()
		default:
			// Bare relative reference: resolve against the asset's
			// directory (webpack/vite chunks live next to the bundle).
			if assetBase == nil || assetBase.Host == "" || strings.ContainsAny(raw, " <>\"'\\") {
				return
			}
			if strings.Contains(raw, "..") {
				return // refuse directory escapes above the root
			}
			dir := assetBase.Path
			if i := strings.LastIndex(dir, "/"); i >= 0 {
				dir = dir[:i+1]
			} else {
				dir = "/"
			}
			rel := dir + raw
			if jsRouteSkipped(rel) {
				return
			}
			u := *target
			u.Fragment = ""
			if i := strings.Index(rel, "?"); i >= 0 {
				u.Path, u.RawQuery = path.Clean(rel[:i]), rel[i+1:]
			} else {
				u.Path, u.RawQuery = path.Clean(rel), ""
			}
			resolved = u.String()
		}
		if seen[resolved] {
			return
		}
		seen[resolved] = true
		out = append(out, models.Endpoint{
			URL:      resolved,
			Category: models.EndpointAPI,
			Sources:  []string{"javascript"},
		})
	}
outer:
	for _, re := range jsRoutePatterns {
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			if len(m) < 2 {
				continue
			}
			add(m[1])
			if len(out) >= cap {
				break outer
			}
		}
	}
	// WebSocket endpoints (ws://, wss://) are adversarial WS vectors.
	for _, m := range wsRoutePattern.FindAllStringSubmatch(body, -1) {
		if len(m) < 2 {
			continue
		}
		add(m[1])
		if len(out) >= cap {
			break
		}
	}
	return out
}

// templateSlotPattern matches ${...} template-literal slots.
var templateSlotPattern = regexp.MustCompile(`\$\{[^{}]*\}`)

// chunkPattern matches webpack/vite chunk filenames referenced in
// bundles: 1234.ab12cd34.chunk.js, chunk-ABC.js, assets/x.hash.js,
// vite assets/index-[hash].js.
var chunkPattern = []*regexp.Regexp{
	regexp.MustCompile(`["'\x60]([A-Za-z0-9_.\-/]*chunk[A-Za-z0-9_.\-/]*\.js)["'\x60]`),
	regexp.MustCompile(`["'\x60](\d+\.[0-9a-f]{6,40}\.js)["'\x60]`),
	regexp.MustCompile(`["'\x60]((?:assets/)?index-[A-Za-z0-9_\-]{6,40}\.js)["'\x60]`),
}

// extractJSChunks returns same-host chunk URLs referenced by a bundle
// so the stage can fetch them for their own routes and secrets.
func extractJSChunks(body, assetURL, targetRaw string, cap int) []string {
	target, err := url.Parse(targetRaw)
	if err != nil || target.Host == "" {
		return nil
	}
	assetBase, _ := url.Parse(assetURL)
	seen := map[string]bool{}
	var out []string
	add := func(raw string) {
		if len(out) >= cap || strings.ContainsAny(raw, "${}<>\"'\\ ") {
			return
		}
		var resolved string
		switch {
		case strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://"):
			u, err := url.Parse(raw)
			if err != nil || !strings.EqualFold(u.Host, target.Host) {
				return
			}
			resolved = u.String()
		case strings.HasPrefix(raw, "/"):
			resolved = strings.TrimSuffix(targetRaw, "/") + raw
		default:
			if assetBase == nil || assetBase.Host == "" {
				return
			}
			if strings.Contains(raw, "..") {
				return
			}
			dir := assetBase.Path
			if i := strings.LastIndex(dir, "/"); i >= 0 {
				dir = dir[:i+1]
			} else {
				dir = "/"
			}
			clean := path.Clean("/" + dir + raw)
			if target.Scheme != "" {
				resolved = target.Scheme + "://" + assetBase.Host + clean
			} else {
				resolved = "https://" + assetBase.Host + clean
			}
		}
		if seen[resolved] {
			return
		}
		seen[resolved] = true
		out = append(out, resolved)
	}
	for _, re := range chunkPattern {
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			if len(m) >= 2 {
				add(m[1])
			}
		}
	}
	return out
}

// sourceMapPattern extracts //# sourceMappingURL= references.
var sourceMapPattern = regexp.MustCompile(`(?m)^[^\S\n]*//[#@]\s*sourceMappingURL=(\S+)\s*$`)

// sourceMapURL resolves a bundle's sourceMappingURL against the asset
// location. Returns "" for data: URLs, cross-host maps, or absence.
func sourceMapURL(body, assetURL, targetRaw string) string {
	m := sourceMapPattern.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	ref := strings.TrimSpace(m[1])
	if ref == "" || strings.HasPrefix(ref, "data:") {
		return ""
	}
	target, err := url.Parse(targetRaw)
	if err != nil || target.Host == "" {
		return ""
	}
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		u, err := url.Parse(ref)
		if err != nil || !strings.EqualFold(u.Host, target.Host) {
			return ""
		}
		return u.String()
	}
	assetBase, _ := url.Parse(assetURL)
	base := target
	if assetBase != nil && assetBase.Host != "" {
		base = assetBase
	}
	dir := base.Path
	if i := strings.LastIndex(dir, "/"); i >= 0 {
		dir = dir[:i+1]
	} else {
		dir = "/"
	}
	name := ref
	if strings.HasPrefix(name, "/") {
		dir = ""
	}
	if strings.Contains(dir+name, "..") {
		return ""
	}
	scheme := target.Scheme
	if scheme == "" {
		scheme = "https"
	}
	host := target.Host
	if assetBase != nil && assetBase.Host != "" {
		host = assetBase.Host
	}
	return scheme + "://" + host + dir + name
}

// emailPattern matches plausible email addresses in page text.
var emailPattern = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,24}\b`)

// extractEmails harvests unique addresses for recon (password-spray and
// account-takeover scoping), skipping asset filenames and long junk.
func extractEmails(body string, cap int) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range emailPattern.FindAllString(body, -1) {
		lower := strings.ToLower(m)
		if seen[lower] || len(m) > 254 {
			continue
		}
		domain := lower[strings.LastIndex(lower, "@")+1:]
		skip := false
		for _, ext := range []string{".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif", ".js", ".css", ".map", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp4", ".pdf", ".webmanifest"} {
			if strings.HasSuffix(domain, ext) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		seen[lower] = true
		out = append(out, m)
		if len(out) >= cap {
			break
		}
	}
	return out
}

// domSinks maps sink family → detection patterns. Presence is intel
// (a sink is only exploitable with attacker-controlled data flow), so
// findings stay informational.
var domSinks = []struct {
	family  string
	pattern *regexp.Regexp
}{
	{"innerHTML assignment", regexp.MustCompile(`(?i)\.innerHTML\s*(\+)?=`)},
	{"outerHTML assignment", regexp.MustCompile(`(?i)\.outerHTML\s*(\+)?=`)},
	{"document.write", regexp.MustCompile(`(?i)\bdocument\.writ(?:e|eln)\s*\(`)},
	{"eval", regexp.MustCompile(`(?i)(^|[^.\w])eval\s*\(`)},
	{"Function constructor", regexp.MustCompile(`(?i)\bnew\s+Function\s*\(`)},
	{"setTimeout/setInterval string", regexp.MustCompile(`(?i)\bset(?:Timeout|Interval)\s*\(\s*["'\x60]`)},
	{"insertAdjacentHTML", regexp.MustCompile(`(?i)\.insertAdjacentHTML\s*\(`)},
	{"location sink", regexp.MustCompile(`(?i)\blocation\s*\.\s*(?:href|replace|assign)\s*\(?=`)},
	{"jQuery .html()", regexp.MustCompile(`\$\([^)]*\)\.(?:html|append|prepend|before|after)\s*\(`)},
	{"postMessage", regexp.MustCompile(`(?i)\bpostMessage\s*\(`)},
}

// detectDOMSinks returns the distinct sink families present in body.
func detectDOMSinks(body string) []string {
	var found []string
	for _, s := range domSinks {
		if s.pattern.MatchString(body) {
			found = append(found, s.family)
		}
	}
	sort.Strings(found)
	return found
}

// domSinkFinding builds the per-asset sinks finding.
func domSinkFinding(targetRaw, assetURL string, sinks []string) models.Finding {
	return models.Finding{
		ID:    "secrets-dom-sinks-" + slugHost(assetURL),
		Title: fmt.Sprintf("DOM XSS sink(s) in client-side asset (%d familie(s))", len(sinks)),
		Description: "The shipped JavaScript contains DOM sinks that execute strings as code or HTML " +
			"(" + strings.Join(sinks, ", ") + "). A sink is exploitable only when attacker-controlled data " +
			"reaches it; this finding is attack-surface intel for manual review, not proof of XSS.",
		Severity:   models.SeverityLow,
		Confidence: models.ConfidenceMedium,
		Category:   models.CategoryExposure,
		CWE:        "CWE-79",
		Target:     targetRaw,
		URL:        assetURL,
		Evidence: models.Evidence{
			Observed:       "sink families: " + strings.Join(sinks, ", "),
			RequestSummary: "GET " + assetURL,
			Location:       "client-delivered asset",
		},
		Source:          models.SourceCustom,
		DetectionMethod: "static sink-pattern scan of discovered JS",
		Impact:          "If user-controlled data flows into one of these sinks, stored or reflected DOM XSS is possible.",
		Remediation:     "Prefer textContent over innerHTML, avoid eval/Function constructor, and audit data flows into the listed sinks during code review.",
		FirstSeen:       time.Now(),
	}
}
