// Package fpmatch is ANPU's shared false-positive matching primitive
// (Phase 2). dirs.go is the reference implementation (dual baselines +
// root/app-shell suppression with true Jaccard similarity); the helpers
// here canonicalize that logic so active soft-404, backup/exposed
// scanners, and origin-IP checks all apply the same math instead of
// drifting into per-engine variants (asymmetric overlap, prefix match,
// dead control buckets).
//
// Everything here is pure stdlib over response bodies — no network, no
// fixtures required beyond byte slices — so it stays cheap to unit test.
package fpmatch

import (
	"crypto/sha256"
	"regexp"
	"strings"
)

// Similarity thresholds shared by all engines.
const (
	// CatchAllDetect is the A-vs-B baseline agreement that declares a
	// catch-all router serving one template for every path.
	CatchAllDetect = 0.80
	// ShellMatch suppresses a probe that looks like a known template
	// (soft-404 baseline or application shell).
	ShellMatch = 0.85
	// OriginMatch is the looser bar for origin-IP confirmation (edge vs
	// direct-IP bodies differ by CDN-injected scripts, so exact-shell
	// matching would miss real bypasses).
	OriginMatch = 0.55
)

var wordRe = regexp.MustCompile(`[a-z]{3,}`)

// highEntropyRe matches long random-looking tokens (nonces, hashes,
// integrity values, per-request IDs). Stripping them lets two renders of
// the same template match even when embedded secrets rotate.
var highEntropyRe = regexp.MustCompile(`[A-Za-z0-9+/=_-]{16,}`)

// NormalizeBody removes high-entropy tokens so template comparison is
// stable across renders. Bodies are capped to keep regex work bounded.
func NormalizeBody(body []byte) []byte {
	const cap = 100 << 10
	if len(body) > cap {
		body = body[:cap]
	}
	return highEntropyRe.ReplaceAll(body, nil)
}

// WordSet tokenizes a body into a lowercase word set (3+ letters).
func WordSet(body []byte) map[string]struct{} {
	const cap = 100 << 10
	if len(body) > cap {
		body = body[:cap]
	}
	words := wordRe.FindAllString(strings.ToLower(string(NormalizeBody(body))), -1)
	set := make(map[string]struct{}, len(words))
	for _, w := range words {
		set[w] = struct{}{}
	}
	return set
}

// NormHash hashes the normalized body for exact template matching.
func NormHash(body []byte) [32]byte {
	return sha256.Sum256(NormalizeBody(body))
}

// Similarity is true Jaccard similarity |A∩B|/|A∪B| over word sets.
// Empty sets score 0 (never a match).
func Similarity(a, b map[string]struct{}) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	small, large := a, b
	if len(small) > len(large) {
		small, large = large, small
	}
	inter := 0
	for w := range small {
		if _, ok := large[w]; ok {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

// Template is one known page shape (soft-404 baseline or app shell).
type Template struct {
	Hash  [32]byte
	Words map[string]struct{}
	Has   bool
}

// NewTemplate snapshots a body as a comparable template.
func NewTemplate(body []byte) Template {
	if len(body) == 0 {
		return Template{}
	}
	return Template{Hash: NormHash(body), Words: WordSet(body), Has: true}
}

// MatchesTemplate reports whether probe looks like any known template:
// exact normalized hash, or word similarity at/above threshold.
func MatchesTemplate(probeBody []byte, threshold float64, templates ...Template) bool {
	ph := NormHash(probeBody)
	pw := WordSet(probeBody)
	for _, t := range templates {
		if !t.Has {
			continue
		}
		if ph == t.Hash {
			return true
		}
		if len(t.Words) > 0 && Similarity(pw, t.Words) >= threshold {
			return true
		}
	}
	return false
}

// ScoreTemplate returns the best similarity of probe against templates
// (1.0 on exact hash match, else max Jaccard, else 0).
func ScoreTemplate(probeBody []byte, templates ...Template) float64 {
	ph := NormHash(probeBody)
	pw := WordSet(probeBody)
	best := 0.0
	for _, t := range templates {
		if !t.Has {
			continue
		}
		if ph == t.Hash {
			return 1.0
		}
		if s := Similarity(pw, t.Words); s > best {
			best = s
		}
	}
	return best
}

// WAFBodyMarkers are vendor-specific block-page fragments (lowercase).
// Deliberately specific: generic words like "captcha" or "blocked"
// appear on legitimate pages and must never veto a finding alone.
var WAFBodyMarkers = []string{
	"attention required", "cf-ray", "cf-chl", "__cf_bm", "just a moment",
	"verify you are human", "awselb", "x-amzn-waf", "aws-waf",
	"akamaighost", "reference #", "incapsula", "incap_ses", "x-iinfo",
	"x-sucuri-id", "access denied - sucuri", "sucuri webproxy",
	"x-fastly-request-id", "the requested url was rejected", "x-waf-event",
	"fortiwaf", "fortigate", "fortinet", "x-barracuda", "barracuda",
	"mod_security", "modsecurity", "not acceptable", "imperva",
	"cloudflare ray id", "security policy violation",
}

// IsWAFBlockPage reports whether body looks like a WAF/vendor block
// page rather than application content. Only the first 32KB is scanned.
func IsWAFBlockPage(body []byte) bool {
	const scanCap = 32 << 10
	if len(body) > scanCap {
		body = body[:scanCap]
	}
	lb := strings.ToLower(string(body))
	for _, m := range WAFBodyMarkers {
		if strings.Contains(lb, m) {
			return true
		}
	}
	return false
}

// Denial classes for non-2xx sensitive-path responses.
const (
	// DenialWAF means vendor markers identified the response as WAF
	// noise — not evidence about the path.
	DenialWAF = "waf-block"
	// DenialApp means a bare 401/403/406 with no WAF markers — a
	// present-but-protected candidate worth manual review (reported as
	// a warning, never as an exposure finding).
	DenialApp = "app-denied"
	// DenialOther covers everything else (404s, 5xx, ...).
	DenialOther = "other"
)

// ClassifyDenial separates WAF noise from real access-control signals
// on sensitive paths.
func ClassifyDenial(status int, body []byte) string {
	if IsWAFBlockPage(body) {
		return DenialWAF
	}
	if status == 401 || status == 403 || status == 406 {
		return DenialApp
	}
	return DenialOther
}

// CDNNameFragments match CDN/WAF-edge provider names (lowercase
// substrings). Used for port-scan caveats and origin-hunting hints —
// over-matching here only adds a cautionary note, never a finding.
var CDNNameFragments = []string{
	"cloudflare", "cloudfront", "akamai", "fastly", "vercel",
	"sucuri", "incapsula", "imperva", "azureedge", "azurefd",
	"frontdoor", "cloudarmor", "bunnycdn", "bunny", "keycdn",
	"cdn77", "stackpath", "edgecast", "limelight", "leaseweb",
	"g-core", "gcore", "cachefly", "jsdelivr", "alicdn",
	"cloudinary", "imgix", "netlify", "edgio", "quantil",
}

// IsCDNName reports whether a fingerprinted technology name (or CNAME
// target) belongs to a CDN/edge provider.
func IsCDNName(name string) bool {
	ln := strings.ToLower(name)
	for _, f := range CDNNameFragments {
		if strings.Contains(ln, f) {
			return true
		}
	}
	return false
}
