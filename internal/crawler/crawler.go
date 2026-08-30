// Package crawler provides bounded, same-host web crawling for ANPU's
// attack-surface discovery stage. It intentionally performs only GET
// requests through ANPU's shared HTTP client and never submits forms.
package crawler

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

// Limits are deliberately conservative. The safe profile is a single-page
// discovery pass; standard and deep progressively expand coverage while
// remaining bounded so a public site cannot cause an unbounded crawl.
type Limits struct {
	MaxPages int
	MaxDepth int
}

func LimitsForProfile(profile models.Profile) Limits {
	switch profile {
	case models.ProfileDeep:
		return Limits{MaxPages: 100, MaxDepth: 4}
	case models.ProfileStandard:
		return Limits{MaxPages: 25, MaxDepth: 2}
	default:
		return Limits{MaxPages: 1, MaxDepth: 0}
	}
}

// Crawler performs bounded same-host discovery.
type Crawler struct {
	client *anpuhttp.Client
	limits Limits
}

func New(client *anpuhttp.Client, limits Limits) *Crawler {
	if limits.MaxPages < 1 {
		limits.MaxPages = 1
	}
	if limits.MaxDepth < 0 {
		limits.MaxDepth = 0
	}
	return &Crawler{client: client, limits: limits}
}

type page struct {
	url   string
	depth int
}

var (
	hrefPattern   = regexp.MustCompile(`(?is)<a\s+[^>]*href\s*=\s*["']([^"']+)["']`)
	formPattern   = regexp.MustCompile(`(?is)<form\s+[^>]*action\s*=\s*["']([^"']*)["'][^>]*>`)
	formMethodPat = regexp.MustCompile(`(?is)\bmethod\s*=\s*["'](get|post|put|patch|delete)["']`)
	scriptSrcPat  = regexp.MustCompile(`(?is)<script\s+[^>]*src\s*=\s*["']([^"']+)["']`)
	jsPathPattern = regexp.MustCompile(`(?i)["']((?:/|\.{0,2}/)[a-zA-Z0-9_./?&=:%{}-]+)["']`)
)

// Discover returns normalized endpoints and non-fatal warnings. It starts
// from startURL, follows only same-host HTTP(S) links, and queues only URLs
// that look like documents rather than obvious static assets.
func (c *Crawler) Discover(ctx context.Context, startURL string) ([]models.Endpoint, []string, error) {
	base, err := url.Parse(startURL)
	if err != nil || base.Hostname() == "" {
		return nil, nil, fmt.Errorf("invalid crawl start URL %q", startURL)
	}

	start, ok := normalizeURL(base, startURL)
	if !ok {
		return nil, nil, fmt.Errorf("crawl start URL %q is outside the allowed scheme/scope", startURL)
	}

	queue := []page{{url: start, depth: 0}}
	queued := map[string]bool{start: true}
	visited := map[string]bool{}
	collected := map[string]*models.Endpoint{}
	var warnings []string
	limitHit := false

	for len(queue) > 0 && len(visited) < c.limits.MaxPages {
		select {
		case <-ctx.Done():
			return materialize(collected), warnings, ctx.Err()
		default:
		}

		current := queue[0]
		queue = queue[1:]
		if visited[current.url] {
			continue
		}
		visited[current.url] = true

		resp, err := c.client.Get(ctx, current.url)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("crawler: %s: %v", current.url, err))
			continue
		}

		finalURL, finalOK := normalizeURL(base, resp.FinalURL)
		if finalOK {
			if _, exists := collected[finalURL]; !exists {
				collected[finalURL] = &models.Endpoint{
					URL:      finalURL,
					Category: categorize(finalURL),
					Sources:  []string{"crawler"},
				}
			}
		}

		if !isHTML(resp.Header.Get("Content-Type")) {
			continue
		}

		links := extractLinks(resp.Body)
		for _, link := range links {
			resolved, ok := normalizeURL(base, resolve(base, link.raw, current.url))
			if !ok {
				continue
			}

			addEndpoint(collected, resolved, link.source, link.method)
			if current.depth >= c.limits.MaxDepth || !shouldCrawl(resolved) || queued[resolved] || visited[resolved] {
				continue
			}
			if len(visited)+len(queue) >= c.limits.MaxPages {
				limitHit = true
				continue
			}
			queued[resolved] = true
			queue = append(queue, page{url: resolved, depth: current.depth + 1})
		}
	}

	if len(visited) >= c.limits.MaxPages && (len(queue) > 0 || limitHit) {
		warnings = append(warnings, fmt.Sprintf("crawler: page limit reached (%d)", c.limits.MaxPages))
	}
	return materialize(collected), warnings, nil
}

type link struct {
	raw    string
	source string
	method string
}

func extractLinks(body []byte) []link {
	text := string(body)
	seen := map[string]bool{}
	var out []link
	add := func(raw, source, method string) {
		raw = strings.TrimSpace(raw)
		key := source + "|" + raw + "|" + method
		if raw == "" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, link{raw: raw, source: source, method: method})
	}

	for _, m := range hrefPattern.FindAllStringSubmatch(text, -1) {
		add(m[1], "html-link", "")
	}
	for _, m := range formPattern.FindAllStringSubmatch(text, -1) {
		method := "GET"
		if mm := formMethodPat.FindStringSubmatch(m[0]); len(mm) > 1 {
			method = strings.ToUpper(mm[1])
		}
		add(m[1], "html-form", method)
	}
	for _, m := range scriptSrcPat.FindAllStringSubmatch(text, -1) {
		add(m[1], "javascript", "")
	}
	for _, m := range jsPathPattern.FindAllStringSubmatch(text, -1) {
		add(m[1], "javascript-reference", "")
	}
	return out
}

func resolve(base *url.URL, raw, current string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return current
	}
	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "javascript:") ||
		strings.HasPrefix(lower, "mailto:") ||
		strings.HasPrefix(lower, "tel:") ||
		strings.HasPrefix(lower, "data:") {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return base.ResolveReference(u).String()
}

func normalizeURL(base *url.URL, raw string) (string, bool) {
	if strings.TrimSpace(raw) == "" {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	if !strings.EqualFold(u.Hostname(), base.Hostname()) {
		return "", false
	}
	u.Fragment = ""
	return strings.TrimSuffix(u.String(), "/"), true
}

func shouldCrawl(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	path := strings.ToLower(u.Path)
	for _, ext := range []string{".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map", ".webp", ".mp4", ".pdf", ".zip", ".tar", ".gz"} {
		if strings.HasSuffix(path, ext) {
			return false
		}
	}
	return true
}

func isHTML(contentType string) bool {
	contentType = strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	return contentType == "" || contentType == "text/html" || contentType == "application/xhtml+xml"
}

func categorize(rawURL string) models.EndpointCategory {
	u, err := url.Parse(rawURL)
	path := strings.ToLower(rawURL)
	if err == nil {
		path = strings.ToLower(u.Path)
	}
	switch {
	case strings.Contains(path, "/wp-admin") || strings.Contains(path, "/admin") ||
		strings.Contains(path, "/dashboard") || strings.Contains(path, "/manage") || strings.Contains(path, "/cpanel"):
		return models.EndpointAdminLike
	case strings.Contains(path, "/api/") || strings.HasPrefix(path, "/api") ||
		strings.Contains(path, "/graphql") || strings.Contains(path, "/rest/"):
		return models.EndpointAPI
	case strings.Contains(path, "/login") || strings.Contains(path, "/signin") ||
		strings.Contains(path, "/signup") || strings.Contains(path, "/register") ||
		strings.Contains(path, "/auth") || strings.Contains(path, "/sso") || strings.Contains(path, "/logout"):
		return models.EndpointAuth
	case isAssetPath(path):
		return models.EndpointAsset
	case looksLikePage(path):
		return models.EndpointPage
	default:
		return models.EndpointUnknown
	}
}

func isAssetPath(path string) bool {
	for _, ext := range []string{".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".ico", ".map", ".webp", ".mp4", ".pdf"} {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return strings.Contains(path, "/static/") || strings.Contains(path, "/assets/")
}

func looksLikePage(path string) bool {
	if path == "" {
		return true
	}
	for _, ext := range []string{".html", ".htm", ".php", ".asp", ".aspx", ".jsp", "/"} {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	last := path
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		last = path[idx+1:]
	}
	return !strings.Contains(last, ".")
}

func addEndpoint(collected map[string]*models.Endpoint, raw, source, method string) {
	if ep, ok := collected[raw]; ok {
		if !contains(ep.Sources, source) {
			ep.Sources = append(ep.Sources, source)
		}
		if ep.Method == "" && method != "" {
			ep.Method = method
		}
		return
	}
	collected[raw] = &models.Endpoint{
		URL:      raw,
		Method:   method,
		Category: categorize(raw),
		Sources:  []string{source},
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func materialize(collected map[string]*models.Endpoint) []models.Endpoint {
	out := make([]models.Endpoint, 0, len(collected))
	for _, ep := range collected {
		out = append(out, *ep)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}
