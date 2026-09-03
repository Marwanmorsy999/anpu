// Package technology performs passive technology fingerprinting from
// HTTP headers, cookie names, and HTML/JS content — the same kind of
// signals a browser's "view source" would reveal. It never claims an
// exact version without direct evidence for that version string.
package technology

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// Detector implements scanner.Scanner for technology fingerprinting.
type Detector struct {
	client *anpuhttp.Client
}

func New(client *anpuhttp.Client) *Detector { return &Detector{client: client} }

func (d *Detector) Name() string { return "technology" }

func (d *Detector) Available(ctx context.Context) bool { return true }

func (d *Detector) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	resp, err := d.client.Get(ctx, sc.Target.Raw)
	if err != nil {
		return scanner.StageResult{}, fmt.Errorf("fetching target for technology detection: %w", err)
	}

	body := string(resp.Body)
	var techs []models.Technology

	techs = append(techs, detectFromHeader(resp.Header, "Server", serverSignatures)...)
	techs = append(techs, detectFromHeader(resp.Header, "X-Powered-By", poweredBySignatures)...)
	techs = append(techs, detectFromCookies(resp.Header)...)
	techs = append(techs, detectFromBody(body)...)
	techs = append(techs, detectCDN(resp.Header)...)

	techs = dedupTechnologies(techs)

	return scanner.StageResult{Technologies: techs}, nil
}

type signature struct {
	Name     string
	Category string
	Pattern  *regexp.Regexp // optional: extracts version as first capture group
}

var serverSignatures = []signature{
	{"nginx", "web-server", regexp.MustCompile(`(?i)nginx/?([\d.]+)?`)},
	{"Apache", "web-server", regexp.MustCompile(`(?i)apache/?([\d.]+)?`)},
	{"Microsoft-IIS", "web-server", regexp.MustCompile(`(?i)microsoft-iis/?([\d.]+)?`)},
	{"cloudflare", "cdn", regexp.MustCompile(`(?i)cloudflare`)},
	{"LiteSpeed", "web-server", regexp.MustCompile(`(?i)litespeed`)},
	{"Caddy", "web-server", regexp.MustCompile(`(?i)caddy`)},
}

var poweredBySignatures = []signature{
	{"PHP", "backend", regexp.MustCompile(`(?i)php/?([\d.]+)?`)},
	{"ASP.NET", "backend", regexp.MustCompile(`(?i)asp\.net`)},
	{"Express", "backend", regexp.MustCompile(`(?i)express`)},
	{"Next.js", "framework", regexp.MustCompile(`(?i)next\.js`)},
}

func detectFromHeader(h http.Header, headerName string, sigs []signature) []models.Technology {
	v := h.Get(headerName)
	if v == "" {
		return nil
	}
	var out []models.Technology
	for _, sig := range sigs {
		m := sig.Pattern.FindStringSubmatch(v)
		if m == nil {
			continue
		}
		version := ""
		if len(m) > 1 {
			version = m[1]
		}
		out = append(out, models.Technology{
			Name:       sig.Name,
			Category:   sig.Category,
			Version:    version,
			Confidence: 0.8,
			Evidence: models.Evidence{
				Observed: fmt.Sprintf("%s: %s", headerName, v),
				Location: "HTTP response header",
			},
		})
	}
	return out
}

// cookieSignatures maps well-known cookie name prefixes/exact-names to
// the technology that typically sets them.
var cookieSignatures = map[string]signature{
	"phpsessid":           {"PHP", "backend", nil},
	"asp.net_sessionid":   {"ASP.NET", "backend", nil},
	"laravel_session":     {"Laravel", "framework", nil},
	"connect.sid":         {"Express (connect/express-session)", "framework", nil},
	"csrftoken":           {"Django", "framework", nil},
	"django_language":     {"Django", "framework", nil},
	"_rails_session":      {"Ruby on Rails", "framework", nil},
	"wordpress_logged_in": {"WordPress", "cms", nil},
	"wp-settings":         {"WordPress", "cms", nil},
	"ci_session":          {"CodeIgniter", "framework", nil},
	"jsessionid":          {"Java (Servlet container)", "backend", nil},
}

func detectFromCookies(h http.Header) []models.Technology {
	var out []models.Technology
	var dummy http.Response
	dummy.Header = h
	for _, c := range dummy.Cookies() {
		sig, ok := cookieSignatures[strings.ToLower(c.Name)]
		if !ok {
			continue
		}
		out = append(out, models.Technology{
			Name:       sig.Name,
			Category:   sig.Category,
			Confidence: 0.6,
			Evidence: models.Evidence{
				Observed: fmt.Sprintf("cookie name: %s", c.Name),
				Location: "Set-Cookie response header",
			},
		})
	}
	return out
}

// bodySignature matches HTML/JS body content. VersionAt, if > 0, is the
// capture-group index in Pattern that holds the version string.
type bodySignature struct {
	Name      string
	Category  string
	Pattern   *regexp.Regexp
	VersionAt int // 0 = no version capture
}

// bodySignatures match against raw HTML/JS body content. Kept conservative
// and specific to reduce false positives.
//
// VersionAt points to the capture group that holds the version string when
// it can be extracted directly from the matched token.
var bodySignatures = []bodySignature{
	// WordPress — wp-content/wp-includes path presence; version via generator tag
	{"WordPress", "cms",
		regexp.MustCompile(`(?i)wp-content/|wp-includes/`), 0},
	// React — no reliable inline version
	{"React", "js-framework",
		regexp.MustCompile(`(?i)data-reactroot|react-dom|__REACT_DEVTOOLS`), 0},
	// Vue.js
	{"Vue.js", "js-framework",
		regexp.MustCompile(`(?i)data-v-app|__vue__|vue\.js`), 0},
	// Angular writes ng-version="17.3.1" on the root element
	{"Angular", "js-framework",
		regexp.MustCompile(`(?i)ng-version="([\d.]+)"`), 1},
	// Next.js
	{"Next.js", "framework",
		regexp.MustCompile(`(?i)__NEXT_DATA__|/_next/static/`), 0},
	// jQuery — inline banner /*! jQuery v3.6.0 */ or script src filename
	{"jQuery", "js-library",
		regexp.MustCompile(`(?i)(?:jQuery(?:\s+JavaScript Library)?\s+v([\d.]+)|jquery[/\-]([\d.]+)(?:\.min)?\.js)`), 1},
	// Bootstrap — inline banner /*! Bootstrap v5.3.0 */ or filename
	{"Bootstrap", "css-framework",
		regexp.MustCompile(`(?i)(?:Bootstrap\s+v([\d.]+)|bootstrap[/\-]([\d.]+)(?:\.min)?(?:\.css|\.js))`), 1},
	// lodash — inline banner /*! lodash v4.17.21 */
	{"lodash", "js-library",
		regexp.MustCompile(`(?i)lodash(?:\s+v|-)([\d.]+)`), 1},
	// moment.js — inline banner //! moment.js 2.29.4
	{"moment", "js-library",
		regexp.MustCompile(`(?i)moment\.js\s+([\d.]+)`), 1},
	{"Shopify", "cms",
		regexp.MustCompile(`(?i)cdn\.shopify\.com|Shopify\.theme`), 0},
	{"Drupal", "cms",
		regexp.MustCompile(`(?i)Drupal\.settings|/sites/default/files/`), 0},
	{"Tailwind CSS", "css-framework",
		regexp.MustCompile(`(?i)tailwind`), 0},
	{"Google Tag Manager", "analytics",
		regexp.MustCompile(`(?i)googletagmanager\.com/gtm\.js`), 0},
	{"Google Analytics", "analytics",
		regexp.MustCompile(`(?i)google-analytics\.com/analytics\.js|gtag\('config'`), 0},
}

// generatorPattern matches <meta name="generator" content="Name Version">
// in either attribute order.
var generatorPattern = regexp.MustCompile(
	`(?i)<meta[^>]+name=["'']?generator["'']?[^>]+content=["'']([^"']+)["'']|` +
		`<meta[^>]+content=["'']([^"']+)["''][^>]+name=["'']?generator["'']?`,
)

// knownGenerators maps generator tag prefixes to Technology fields.
var knownGenerators = []struct {
	prefix   string
	name     string
	category string
}{
	{"wordpress", "WordPress", "cms"},
	{"joomla!", "Joomla", "cms"},
	{"drupal", "Drupal", "cms"},
	{"typo3", "TYPO3", "cms"},
	{"mediawiki", "MediaWiki", "cms"},
	{"ghost", "Ghost", "cms"},
	{"gatsby", "Gatsby", "framework"},
	{"hugo", "Hugo", "framework"},
	{"jekyll", "Jekyll", "framework"},
	{"wix", "Wix", "cms"},
	{"squarespace", "Squarespace", "cms"},
}

// detectFromBody scans the page body for technology fingerprints and, where
// possible, extracts the exact version from inline banners or attribute values.
func detectFromBody(body string) []models.Technology {
	if len(body) > 2_000_000 {
		body = body[:2_000_000]
	}
	var out []models.Technology

	for _, sig := range bodySignatures {
		m := sig.Pattern.FindStringSubmatch(body)
		if m == nil {
			continue
		}
		version := ""
		if sig.VersionAt > 0 {
			for i := sig.VersionAt; i < len(m); i++ {
				if m[i] != "" {
					version = m[i]
					break
				}
			}
		}
		out = append(out, models.Technology{
			Name:       sig.Name,
			Category:   sig.Category,
			Version:    version,
			Confidence: 0.65,
			Evidence: models.Evidence{
				Observed: fmt.Sprintf("matched pattern in page content: %q", truncate(m[0], 80)),
				Location: "HTML/JavaScript response body",
			},
		})
	}

	out = append(out, detectFromGenerator(body)...)
	return out
}

// detectFromGenerator extracts technology and version from <meta name="generator">.
// Many CMSes and frameworks emit this tag with an exact version.
func detectFromGenerator(body string) []models.Technology {
	matches := generatorPattern.FindAllStringSubmatch(body, -1)
	var out []models.Technology
	for _, m := range matches {
		content := m[1]
		if content == "" {
			content = m[2]
		}
		content = strings.TrimSpace(content)
		if content == "" {
			continue
		}
		lower := strings.ToLower(content)
		for _, kg := range knownGenerators {
			if !strings.HasPrefix(lower, kg.prefix) {
				continue
			}
			// Version is everything after the product name, stripped of leading spaces/v.
			version := strings.TrimLeft(content[len(kg.prefix):], " vV")
			out = append(out, models.Technology{
				Name:       kg.name,
				Category:   kg.category,
				Version:    version,
				Confidence: 0.85,
				Evidence: models.Evidence{
					Observed: fmt.Sprintf("meta[name=generator]: %q", truncate(content, 80)),
					Location: "HTML meta tag",
				},
			})
			break
		}
	}
	return out
}

func detectCDN(h http.Header) []models.Technology {
	var out []models.Technology
	if h.Get("CF-Ray") != "" || h.Get("CF-Cache-Status") != "" {
		out = append(out, models.Technology{
			Name: "Cloudflare", Category: "cdn", Confidence: 0.9,
			Evidence: models.Evidence{Observed: "CF-Ray/CF-Cache-Status header present", Location: "HTTP response header"},
		})
	}
	if strings.Contains(strings.ToLower(h.Get("Server")), "cloudfront") || h.Get("X-Amz-Cf-Id") != "" {
		out = append(out, models.Technology{
			Name: "Amazon CloudFront", Category: "cdn", Confidence: 0.9,
			Evidence: models.Evidence{Observed: "X-Amz-Cf-Id header present", Location: "HTTP response header"},
		})
	}
	if h.Get("X-Vercel-Id") != "" {
		out = append(out, models.Technology{
			Name: "Vercel", Category: "hosting", Confidence: 0.9,
			Evidence: models.Evidence{Observed: "X-Vercel-Id header present", Location: "HTTP response header"},
		})
	}
	return out
}

func dedupTechnologies(in []models.Technology) []models.Technology {
	seen := map[string]bool{}
	var out []models.Technology
	for _, t := range in {
		key := t.Name + "|" + t.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, t)
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
