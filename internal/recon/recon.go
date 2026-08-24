// Package recon performs passive/low-impact reconnaissance: DNS lookups,
// HTTP(S) reachability and redirect-chain observation, and fetching of
// well-known, publicly-intended files (robots.txt, sitemap.xml). It
// performs no destructive or intrusive actions — only requests a client
// browser or crawler would ordinarily make.
package recon

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// Recon implements scanner.Scanner for the recon pipeline stage.
type Recon struct {
	client *anpuhttp.Client
}

func New(client *anpuhttp.Client) *Recon { return &Recon{client: client} }

func (r *Recon) Name() string { return "recon" }

func (r *Recon) Available(ctx context.Context) bool { return true }

func (r *Recon) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	var findings []models.Finding
	var endpoints []models.Endpoint
	var warnings []string

	// DNS resolution info (informational finding, useful evidence for a
	// human reviewer; not a vulnerability by itself).
	if ips, err := net.DefaultResolver.LookupIPAddr(ctx, sc.Target.Host); err == nil && len(ips) > 0 {
		var addrs []string
		for _, ip := range ips {
			addrs = append(addrs, ip.String())
		}
		findings = append(findings, models.Finding{
			ID:              "recon-dns-resolution",
			Title:           "DNS resolution",
			Description:     fmt.Sprintf("The target hostname resolved to %d address(es).", len(addrs)),
			Severity:        models.SeverityInfo,
			Confidence:      models.ConfidenceHigh,
			Category:        models.CategoryExposure,
			Target:          sc.Target.Raw,
			Evidence:        models.Evidence{Observed: strings.Join(addrs, ", "), Location: "DNS A/AAAA lookup"},
			Source:          models.SourceRecon,
			DetectionMethod: "DNS lookup",
		})
	} else if err != nil {
		warnings = append(warnings, fmt.Sprintf("DNS resolution failed: %v", err))
	}

	// robots.txt
	robotsFindings, robotsEndpoints := r.fetchRobots(ctx, sc)
	findings = append(findings, robotsFindings...)
	endpoints = append(endpoints, robotsEndpoints...)

	// sitemap.xml
	sitemapEndpoints := r.fetchSitemap(ctx, sc)
	endpoints = append(endpoints, sitemapEndpoints...)

	// Redirect chain observation on the target itself.
	resp, err := r.client.Get(ctx, sc.Target.Raw)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("initial request to target failed: %v", err))
		return scanner.StageResult{Findings: findings, Endpoints: endpoints, Warnings: warnings}, nil
	}
	if resp.FinalURL != "" && resp.FinalURL != sc.Target.Raw {
		findings = append(findings, models.Finding{
			ID:              "recon-redirect-observed",
			Title:           "Target redirects to a different URL",
			Description:     fmt.Sprintf("A request to the target was redirected to %s before returning a final response.", resp.FinalURL),
			Severity:        models.SeverityInfo,
			Confidence:      models.ConfidenceHigh,
			Category:        models.CategoryExposure,
			Target:          sc.Target.Raw,
			URL:             resp.FinalURL,
			Evidence:        models.Evidence{Observed: fmt.Sprintf("final URL: %s (status %d)", resp.FinalURL, resp.StatusCode), Location: "HTTP redirect chain"},
			Source:          models.SourceRecon,
			DetectionMethod: "HTTP request following redirects",
		})
	}

	// Source map detection: look for `//# sourceMappingURL=` in the
	// initial HTML response's inline scripts, and in the response body
	// generally — a common accidental exposure of original source.
	if loc := sourceMapPattern.FindString(string(resp.Body)); loc != "" {
		findings = append(findings, models.Finding{
			ID:              "recon-sourcemap-reference",
			Title:           "JavaScript source map reference found",
			Description:     "The page content references a JavaScript source map. If the referenced .map file is publicly accessible, it can expose original (unminified/uncompiled) source code, including comments and internal file paths.",
			Severity:        models.SeverityLow,
			Confidence:      models.ConfidenceMedium,
			Category:        models.CategoryExposure,
			CWE:             "CWE-540",
			Target:          sc.Target.Raw,
			URL:             resp.FinalURL,
			Evidence:        models.Evidence{Observed: truncate(loc, 200), Location: "HTML/JavaScript response body"},
			Source:          models.SourceRecon,
			DetectionMethod: "response body pattern match",
			Impact:          "If the .map file is deployed to production and publicly reachable, an attacker could reconstruct original source, including comments, variable names, and internal logic.",
			Remediation:     "Avoid deploying source maps to production, or restrict access to them (e.g. behind authentication or excluded from the public build).",
		})
	}

	return scanner.StageResult{Findings: findings, Endpoints: endpoints, Warnings: warnings}, nil
}

var sourceMapPattern = regexp.MustCompile(`//#\s*sourceMappingURL=\S+`)

func (r *Recon) fetchRobots(ctx context.Context, sc *scanner.ScanContext) ([]models.Finding, []models.Endpoint) {
	robotsURL := joinURL(sc.Target.Raw, "/robots.txt")
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	resp, err := r.client.Get(ctx, robotsURL)
	if err != nil || resp.StatusCode != 200 {
		return nil, nil
	}

	body := string(resp.Body)
	var endpoints []models.Endpoint
	var disallowedPaths []string

	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "disallow:") {
			path := strings.TrimSpace(line[len("disallow:"):])
			if path != "" {
				disallowedPaths = append(disallowedPaths, path)
				endpoints = append(endpoints, models.Endpoint{
					URL:      joinURL(sc.Target.Raw, path),
					Category: categorizePath(path),
					Sources:  []string{"robots.txt"},
				})
			}
		} else if strings.HasPrefix(lower, "sitemap:") {
			sm := strings.TrimSpace(line[len("sitemap:"):])
			if sm != "" {
				endpoints = append(endpoints, models.Endpoint{URL: sm, Category: models.EndpointPage, Sources: []string{"robots.txt"}})
			}
		}
	}

	var findings []models.Finding
	findings = append(findings, models.Finding{
		ID:              "recon-robots-txt-found",
		Title:           "robots.txt found",
		Description:     fmt.Sprintf("robots.txt was found and lists %d Disallow rule(s). These paths are excluded from well-behaved crawlers but are not access-controlled — they are visible to anyone who requests robots.txt.", len(disallowedPaths)),
		Severity:        models.SeverityInfo,
		Confidence:      models.ConfidenceHigh,
		Category:        models.CategoryExposure,
		Target:          sc.Target.Raw,
		URL:             robotsURL,
		Evidence:        models.Evidence{Observed: fmt.Sprintf("%d Disallow rule(s) found", len(disallowedPaths)), Location: "robots.txt"},
		Source:          models.SourceRecon,
		DetectionMethod: "fetch of /robots.txt",
	})

	// Flag disallowed paths that look sensitive (admin-like) as a
	// low-severity information-exposure note, since robots.txt often
	// inadvertently maps out administrative areas.
	for _, p := range disallowedPaths {
		if categorizePath(p) == models.EndpointAdminLike {
			findings = append(findings, models.Finding{
				ID:              "recon-robots-admin-path-" + safeSlug(p),
				Title:           "robots.txt references an administrative-looking path",
				Description:     fmt.Sprintf("robots.txt disallows crawling of %q, which appears to be an administrative or sensitive path. This does not restrict access — it only asks crawlers not to index it — so the path itself is still reachable if not otherwise protected.", p),
				Severity:        models.SeverityInfo,
				Confidence:      models.ConfidenceLow,
				Category:        models.CategoryExposure,
				Target:          sc.Target.Raw,
				URL:             joinURL(sc.Target.Raw, p),
				Evidence:        models.Evidence{Observed: fmt.Sprintf("Disallow: %s", p), Location: "robots.txt"},
				Source:          models.SourceRecon,
				DetectionMethod: "robots.txt parsing",
				Impact:          "robots.txt is not an access control mechanism; anyone can request it and see the referenced path.",
				Remediation:     "Ensure administrative/sensitive paths are protected by authentication, not merely omitted from robots.txt.",
			})
		}
	}

	return findings, endpoints
}

func (r *Recon) fetchSitemap(ctx context.Context, sc *scanner.ScanContext) []models.Endpoint {
	sitemapURL := joinURL(sc.Target.Raw, "/sitemap.xml")
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	resp, err := r.client.Get(ctx, sitemapURL)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}

	locs := sitemapLocPattern.FindAllStringSubmatch(string(resp.Body), -1)
	var endpoints []models.Endpoint
	for _, m := range locs {
		if len(m) < 2 {
			continue
		}
		endpoints = append(endpoints, models.Endpoint{
			URL:      strings.TrimSpace(m[1]),
			Category: models.EndpointPage,
			Sources:  []string{"sitemap.xml"},
		})
	}
	return endpoints
}

var sitemapLocPattern = regexp.MustCompile(`<loc>\s*([^<\s]+)\s*</loc>`)

func categorizePath(p string) models.EndpointCategory {
	lower := strings.ToLower(p)
	switch {
	case strings.Contains(lower, "admin") || strings.Contains(lower, "wp-admin") ||
		strings.Contains(lower, "manage") || strings.Contains(lower, "dashboard") ||
		strings.Contains(lower, "cpanel"):
		return models.EndpointAdminLike
	case strings.Contains(lower, "/api/") || strings.HasPrefix(lower, "/api"):
		return models.EndpointAPI
	case strings.Contains(lower, "login") || strings.Contains(lower, "signin") ||
		strings.Contains(lower, "auth") || strings.Contains(lower, "sso"):
		return models.EndpointAuth
	default:
		return models.EndpointUnknown
	}
}

func joinURL(base, path string) string {
	base = strings.TrimRight(base, "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path
}

func safeSlug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
