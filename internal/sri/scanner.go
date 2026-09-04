// Package sri implements the Phase 12C Subresource Integrity (SRI) passive check.
//
// # What it detects
//
// External scripts (<script src="https://cdn.example.com/lib.js">) and
// stylesheets (<link rel="stylesheet" href="https://fonts.googleapis.com/...">)
// loaded from cross-origin hosts without a cryptographic integrity= attribute
// give third-party CDNs full script execution (or style-injection) capability
// over the page.  If the CDN is compromised or the URL is hijacked, the
// attacker can run arbitrary code in every visitor's browser.
//
// The integrity= attribute (W3C Subresource Integrity) pins the resource to a
// specific hash.  Browsers reject the resource if the hash does not match,
// preventing supply-chain attacks.
//
// # Strategy
//
// For each discovered HTML page endpoint the scanner:
//  1. Fetches the page (one GET per page).
//  2. Parses <script src="..."> and <link rel="stylesheet" href="..."> tags.
//  3. Filters to cross-origin URLs only — same-origin assets are controlled
//     by the site owner and do not benefit from SRI.
//  4. Reports one finding per asset URL that lacks integrity=.
//     Findings are deduplicated by asset URL across all pages to avoid noise.
//
// # CWE / OWASP
//
// CWE-829: Inclusion of Functionality from Untrusted Control Sphere
// OWASP A06:2021 — Vulnerable and Outdated Components
//
// # Severity / Confidence
//
// Severity: Low — a compromised CDN is a realistic but not imminent threat.
// Confidence: High — the missing attribute is directly observable.
package sri

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// scriptTagPattern matches an entire <script ...> opening tag, including
// multi-line attribute lists, capturing the src attribute value in group 1.
// (?s) makes . match newlines so attributes on separate lines are included.
var scriptTagPattern = regexp.MustCompile(
	`(?is)<script(\s[^>]*)?>`,
)

// scriptSrcAttr extracts the src= attribute value from a tag string.
var scriptSrcAttr = regexp.MustCompile(`(?i)\bsrc\s*=\s*["']([^"'>\s]+)["']`)

// linkTagPattern matches an entire <link ...> opening tag including newlines.
var linkTagPattern = regexp.MustCompile(`(?is)<link(\s[^>]*)?>`)

// linkRelStylesheet checks whether a tag contains rel="stylesheet".
var linkRelStylesheet = regexp.MustCompile(`(?i)\brel\s*=\s*["']stylesheet["']`)

// linkHrefAttr extracts the href= attribute value from a tag string.
var linkHrefAttr = regexp.MustCompile(`(?i)\bhref\s*=\s*["']([^"'>\s]+)["']`)

// integrityAttrPattern checks whether an integrity= attribute is present
// anywhere in a tag string.
var integrityAttrPattern = regexp.MustCompile(`(?i)\bintegrity\s*=\s*["']`)

// Scanner is the pipeline stage for SRI checking.
type Scanner struct {
	client *anpuhttp.Client
}

// New returns an sri.Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

func (s *Scanner) Name() string                     { return "sri-scanner" }
func (s *Scanner) Available(_ context.Context) bool { return true }

// Run fetches each HTML page endpoint and reports cross-origin assets missing
// the integrity= attribute.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	var findings []models.Finding
	var warnings []string

	// seenAsset deduplicates findings by asset URL — one finding per unique
	// missing-SRI asset regardless of how many pages reference it.
	seenAsset := map[string]bool{}

	// targetHost is the host (scheme+host) of the scan target, used to
	// distinguish same-origin from cross-origin asset URLs.
	targetHost := hostOf(sc.Target.Raw)

	for _, ep := range sc.Endpoints {
		// Only check HTML pages — assets and API endpoints don't embed sub-resources.
		if ep.Category != models.EndpointPage && ep.Category != models.EndpointUnknown {
			continue
		}

		select {
		case <-ctx.Done():
			warnings = append(warnings, "sri-scanner: context cancelled, stopped early")
			return scanner.StageResult{Findings: findings, Warnings: warnings}, nil
		default:
		}

		resp, err := s.client.WithAuth(sc.Auth.RequestHeaders()).Get(ctx, ep.URL)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("sri-scanner: GET %s: %v", ep.URL, err))
			continue
		}

		ct := strings.ToLower(resp.Header.Get("Content-Type"))
		if !strings.Contains(ct, "text/html") && !strings.Contains(ct, "application/xhtml") && ct != "" {
			continue // skip non-HTML responses
		}

		body := string(resp.Body)
		missing := extractMissingIntegrity(body, targetHost)

		for _, asset := range missing {
			if seenAsset[asset.URL] {
				continue
			}
			seenAsset[asset.URL] = true

			findings = append(findings, models.Finding{
				ID: fmt.Sprintf("sri-missing-integrity-%d", time.Now().UnixNano()),
				Title: fmt.Sprintf(
					"Cross-origin %s loaded without Subresource Integrity: %s",
					asset.Kind, asset.URL,
				),
				Description: fmt.Sprintf(
					"The page at %s loads a cross-origin %s from %s without an integrity= attribute. "+
						"Without SRI, a compromised or hijacked CDN can serve a modified version of this resource "+
						"that executes arbitrary code (for scripts) or exfiltrates data (for stylesheets) "+
						"in every visitor's browser.",
					ep.URL, asset.Kind, asset.URL,
				),
				Severity:        models.SeverityLow,
				Confidence:      models.ConfidenceHigh,
				Category:        models.CategoryVulnerability,
				CWE:             "CWE-829",
				OWASP:           "A06:2021 - Vulnerable and Outdated Components",
				Target:          sc.Target.Raw,
				URL:             ep.URL,
				Parameter:       asset.URL,
				Source:          models.SourceSRI,
				DetectionMethod: fmt.Sprintf("Fetched page HTML; found cross-origin <%s> tag without integrity= attribute", asset.Tag),
				Evidence: models.Evidence{
					Observed: fmt.Sprintf(
						"<%s> referencing cross-origin URL %s lacks integrity= attribute (found on page %s)",
						asset.Tag, asset.URL, ep.URL,
					),
					Location:       ep.URL,
					RequestSummary: fmt.Sprintf("GET %s", ep.URL),
				},
				Impact: "If the CDN serving this resource is compromised (or the URL taken over after a CDN account deletion), " +
					"an attacker can replace the resource with malicious code that runs with full origin privileges in every visitor's browser.",
				Remediation: fmt.Sprintf(
					"Generate the SRI hash for %s using: "+
						"`openssl dgst -sha384 -binary <file> | openssl base64 -A` "+
						"or https://www.srihash.org/ and add integrity=\"sha384-<hash>\" crossorigin=\"anonymous\" to the tag.",
					asset.URL,
				),
				References: []string{
					"https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
					"https://www.w3.org/TR/SRI/",
					"https://cwe.mitre.org/data/definitions/829.html",
				},
				FirstSeen: time.Now(),
			})
		}
	}

	return scanner.StageResult{Findings: findings, Warnings: warnings}, nil
}

// assetRef holds an extracted cross-origin asset reference.
type assetRef struct {
	URL  string // the full asset URL
	Kind string // "script" or "stylesheet"
	Tag  string // the full matched tag text (for evidence)
}

// extractMissingIntegrity parses body and returns all cross-origin script/
// stylesheet references that lack an integrity= attribute.
func extractMissingIntegrity(body, targetHost string) []assetRef {
	var out []assetRef

	// --- <script ...> tags ---
	for _, m := range scriptTagPattern.FindAllStringSubmatch(body, -1) {
		tag := m[0] // full opening tag including all attributes
		srcMatch := scriptSrcAttr.FindStringSubmatch(tag)
		if len(srcMatch) < 2 {
			continue // no src — inline script
		}
		assetURL := srcMatch[1]
		if !isCrossOrigin(assetURL, targetHost) {
			continue
		}
		if integrityAttrPattern.MatchString(tag) {
			continue // integrity= present — safe
		}
		out = append(out, assetRef{URL: assetURL, Kind: "script", Tag: "script"})
	}

	// --- <link ...> tags ---
	for _, m := range linkTagPattern.FindAllStringSubmatch(body, -1) {
		tag := m[0]
		if !linkRelStylesheet.MatchString(tag) {
			continue // not a stylesheet link
		}
		hrefMatch := linkHrefAttr.FindStringSubmatch(tag)
		if len(hrefMatch) < 2 {
			continue
		}
		assetURL := hrefMatch[1]
		if !isCrossOrigin(assetURL, targetHost) {
			continue
		}
		if integrityAttrPattern.MatchString(tag) {
			continue
		}
		out = append(out, assetRef{URL: assetURL, Kind: "stylesheet", Tag: "link"})
	}

	return out
}

// isCrossOrigin returns true when assetURL is an absolute URL pointing to a
// host different from targetHost.  Relative URLs and data: URIs are always
// same-origin and return false.
func isCrossOrigin(assetURL, targetHost string) bool {
	lower := strings.ToLower(assetURL)
	// Only absolute http(s) URLs can be cross-origin.
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return false
	}
	assetHost := hostOf(assetURL)
	return assetHost != targetHost
}

// hostOf extracts the lowercase scheme+host from a URL string.
// Returns an empty string when the URL is unparseable.
func hostOf(rawURL string) string {
	// Trim to just scheme://host — avoid importing net/url for this hot path.
	lower := strings.ToLower(rawURL)
	for _, prefix := range []string{"https://", "http://"} {
		if strings.HasPrefix(lower, prefix) {
			rest := rawURL[len(prefix):]
			// Host ends at the first slash, question mark, or hash.
			end := strings.IndexAny(rest, "/?#")
			if end < 0 {
				return strings.ToLower(prefix + rest)
			}
			return strings.ToLower(prefix + rest[:end])
		}
	}
	return ""
}
