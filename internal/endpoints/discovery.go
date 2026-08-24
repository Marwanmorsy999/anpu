// Package endpoints discovers, normalizes, and categorizes endpoints
// from HTML links, forms, and JavaScript file references. It performs
// no authentication attempts, form submission, or brute-forcing — it
// only parses content already returned by a normal GET request.
package endpoints

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// Discovery implements scanner.Scanner for endpoint discovery.
type Discovery struct {
	client *anpuhttp.Client
}

func New(client *anpuhttp.Client) *Discovery { return &Discovery{client: client} }

func (d *Discovery) Name() string { return "endpoints" }

func (d *Discovery) Available(ctx context.Context) bool { return true }

var (
	hrefPattern   = regexp.MustCompile(`(?i)<a\s+[^>]*href=["']([^"'#][^"']*)["']`)
	formPattern   = regexp.MustCompile(`(?i)<form\s+[^>]*action=["']([^"']*)["'][^>]*>`)
	formMethodPat = regexp.MustCompile(`(?i)method=["'](get|post)["']`)
	scriptSrcPat  = regexp.MustCompile(`(?i)<script\s+[^>]*src=["']([^"']*)["']`)
	jsApiLikePat  = regexp.MustCompile(`(?i)["'](/api/[a-zA-Z0-9_/\-{}]+)["']`)
)

func (d *Discovery) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	resp, err := d.client.Get(ctx, sc.Target.Raw)
	if err != nil {
		return scanner.StageResult{}, fmt.Errorf("fetching target for endpoint discovery: %w", err)
	}
	body := string(resp.Body)
	base, err := url.Parse(resp.FinalURL)
	if err != nil {
		base, _ = url.Parse(sc.Target.Raw)
	}

	collected := map[string]*models.Endpoint{}

	addEndpoint := func(raw, source string, methodHint string) {
		norm, ok := normalizeURL(base, raw)
		if !ok {
			return
		}
		if ep, exists := collected[norm]; exists {
			ep.Sources = appendUnique(ep.Sources, source)
			if methodHint != "" && ep.Method == "" {
				ep.Method = methodHint
			}
			return
		}
		collected[norm] = &models.Endpoint{
			URL:      norm,
			Method:   methodHint,
			Category: categorize(norm),
			Sources:  []string{source},
		}
	}

	for _, m := range hrefPattern.FindAllStringSubmatch(body, -1) {
		addEndpoint(m[1], "html-link", "")
	}
	for _, m := range formPattern.FindAllString(body, -1) {
		actionMatch := formPattern.FindStringSubmatch(m)
		if len(actionMatch) < 2 {
			continue
		}
		method := "GET"
		if mm := formMethodPat.FindStringSubmatch(m); len(mm) > 1 {
			method = strings.ToUpper(mm[1])
		}
		action := actionMatch[1]
		if action == "" {
			action = base.String() // empty action submits to current page
		}
		addEndpoint(action, "html-form", method)
	}
	for _, m := range scriptSrcPat.FindAllStringSubmatch(body, -1) {
		addEndpoint(m[1], "javascript", "")
	}
	for _, m := range jsApiLikePat.FindAllStringSubmatch(body, -1) {
		addEndpoint(m[1], "javascript-api-reference", "")
	}

	endpoints := make([]models.Endpoint, 0, len(collected))
	for _, ep := range collected {
		endpoints = append(endpoints, *ep)
	}
	sort.Slice(endpoints, func(i, j int) bool { return endpoints[i].URL < endpoints[j].URL })

	var findings []models.Finding
	adminLike := 0
	for _, ep := range endpoints {
		if ep.Category == models.EndpointAdminLike {
			adminLike++
		}
	}
	if adminLike > 0 {
		findings = append(findings, models.Finding{
			ID:              "endpoints-admin-like-discovered",
			Title:           fmt.Sprintf("%d administrative-looking endpoint(s) discovered", adminLike),
			Description:     "One or more discovered endpoints have paths that suggest administrative or privileged functionality. This is informational — it does not by itself mean the endpoint is unprotected — but it narrows the attack surface worth manually reviewing for proper authentication/authorization.",
			Severity:        models.SeverityInfo,
			Confidence:      models.ConfidenceLow,
			Category:        models.CategoryEndpoint,
			Target:          sc.Target.Raw,
			Evidence:        models.Evidence{Observed: fmt.Sprintf("%d admin-like endpoint(s) found via passive discovery", adminLike), Location: "HTML/JavaScript content"},
			Source:          models.SourceEndpoints,
			DetectionMethod: "passive HTML/JS link and form extraction",
			Remediation:     "Confirm each administrative endpoint enforces authentication and authorization server-side, independent of whether the URL is publicly discoverable.",
		})
	}

	return scanner.StageResult{Findings: findings, Endpoints: endpoints}, nil
}

func normalizeURL(base *url.URL, raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "javascript:") || strings.HasPrefix(raw, "mailto:") ||
		strings.HasPrefix(raw, "tel:") || strings.HasPrefix(raw, "data:") {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	resolved := base.ResolveReference(u)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return "", false
	}
	// Only keep same-host endpoints — third-party links aren't part of
	// this target's attack surface.
	if resolved.Hostname() != base.Hostname() {
		return "", false
	}
	resolved.Fragment = ""
	s := resolved.String()
	s = strings.TrimSuffix(s, "/")
	return s, true
}

func categorize(rawURL string) models.EndpointCategory {
	u, err := url.Parse(rawURL)
	path := rawURL
	if err == nil {
		path = u.Path
	}
	lower := strings.ToLower(path)

	switch {
	case strings.Contains(lower, "/wp-admin") || strings.Contains(lower, "/admin") ||
		strings.Contains(lower, "/dashboard") || strings.Contains(lower, "/manage") ||
		strings.Contains(lower, "/cpanel"):
		return models.EndpointAdminLike
	case strings.Contains(lower, "/api/") || strings.HasPrefix(lower, "/api") ||
		strings.Contains(lower, "/graphql") || strings.Contains(lower, "/rest/"):
		return models.EndpointAPI
	case strings.Contains(lower, "/login") || strings.Contains(lower, "/signin") ||
		strings.Contains(lower, "/signup") || strings.Contains(lower, "/register") ||
		strings.Contains(lower, "/auth") || strings.Contains(lower, "/sso") ||
		strings.Contains(lower, "/logout"):
		return models.EndpointAuth
	case isAssetPath(lower):
		return models.EndpointAsset
	case looksLikePage(lower):
		return models.EndpointPage
	default:
		return models.EndpointUnknown
	}
}

var assetExtensions = []string{".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".ico", ".map", ".webp", ".mp4", ".pdf"}

func isAssetPath(lowerPath string) bool {
	for _, ext := range assetExtensions {
		if strings.HasSuffix(lowerPath, ext) {
			return true
		}
	}
	return strings.Contains(lowerPath, "/static/") || strings.Contains(lowerPath, "/assets/")
}

var pageExtensions = []string{".html", ".htm", ".php", ".asp", ".aspx", ".jsp", "/"}

func looksLikePage(lowerPath string) bool {
	if lowerPath == "" {
		return true
	}
	for _, ext := range pageExtensions {
		if strings.HasSuffix(lowerPath, ext) {
			return true
		}
	}
	// No file extension at all commonly indicates a page route in
	// SPA/MVC frameworks.
	last := lowerPath
	if idx := strings.LastIndex(lowerPath, "/"); idx >= 0 {
		last = lowerPath[idx+1:]
	}
	return !strings.Contains(last, ".")
}

func appendUnique(list []string, v string) []string {
	for _, existing := range list {
		if existing == v {
			return list
		}
	}
	return append(list, v)
}
