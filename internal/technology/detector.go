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

// bodySignatures match against raw HTML/JS body content. Kept
// conservative and specific to reduce false positives.
var bodySignatures = []struct {
	Name     string
	Category string
	Needle   *regexp.Regexp
}{
	{"WordPress", "cms", regexp.MustCompile(`(?i)wp-content/|wp-includes/|generator" content="WordPress`)},
	{"React", "js-framework", regexp.MustCompile(`(?i)data-reactroot|react-dom|__REACT_DEVTOOLS`)},
	{"Vue.js", "js-framework", regexp.MustCompile(`(?i)data-v-app|__vue__|vue\.js`)},
	{"Angular", "js-framework", regexp.MustCompile(`(?i)ng-version=|angular\.js`)},
	{"Next.js", "framework", regexp.MustCompile(`(?i)__NEXT_DATA__|/_next/static/`)},
	{"jQuery", "js-library", regexp.MustCompile(`(?i)jquery(-|\.)([\d.]+)?(\.min)?\.js`)},
	{"Shopify", "cms", regexp.MustCompile(`(?i)cdn\.shopify\.com|Shopify\.theme`)},
	{"Drupal", "cms", regexp.MustCompile(`(?i)Drupal\.settings|/sites/default/files/`)},
	{"Bootstrap", "css-framework", regexp.MustCompile(`(?i)bootstrap(\.min)?\.css|bootstrap(\.min)?\.js`)},
	{"Tailwind CSS", "css-framework", regexp.MustCompile(`(?i)tailwind`)},
	{"Google Tag Manager", "analytics", regexp.MustCompile(`(?i)googletagmanager\.com/gtm\.js`)},
	{"Google Analytics", "analytics", regexp.MustCompile(`(?i)google-analytics\.com/analytics\.js|gtag\('config'`)},
}

func detectFromBody(body string) []models.Technology {
	if len(body) > 2_000_000 {
		body = body[:2_000_000]
	}
	var out []models.Technology
	for _, sig := range bodySignatures {
		loc := sig.Needle.FindString(body)
		if loc == "" {
			continue
		}
		out = append(out, models.Technology{
			Name:       sig.Name,
			Category:   sig.Category,
			Confidence: 0.65,
			Evidence: models.Evidence{
				Observed: fmt.Sprintf("matched pattern in page content: %q", truncate(loc, 80)),
				Location: "HTML/JavaScript response body",
			},
		})
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
