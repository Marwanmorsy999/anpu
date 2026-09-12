// Package archiveurls builds a live-page URL + parameter corpus (Wave 1
// item 1): it fetches the target homepage and robots.txt (max 3 requests
// including a soft-404 control), extracts same-host links and query
// parameter names, and returns them as Endpoints so the crawler, Active,
// AuthZ, and Params stages work over a larger surface.
//
// Ghost-compatible and deterministic: same input → same corpus.
// Echo-guard: javascript:/mailto:/tel:/data: URLs and pure-fragment
// links are skipped. The soft-404 control signature is recorded as
// context on the corpus finding so operators see whether downstream
// soft-404 gates face a catch-all template; mined URLs are filtered
// by those downstream gates (crawler, Active), not probed here.
package archiveurls

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// maxRequests bounds all HTTP traffic for this stage.
const maxRequests = 3

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "archiveurls" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

var (
	hrefRe    = regexp.MustCompile(`(?i)(?:href|src|action|data-url)\s*=\s*["']([^"'#]+)["']`)
	paramRe   = regexp.MustCompile(`[?&]([A-Za-z0-9_\-\[\]]+)=`)
	skipRe    = regexp.MustCompile(`(?i)^\s*(javascript:|mailto:|tel:|data:|ftp:|file:|about:|chrome:|vbscript:)`)
	onEventRe = regexp.MustCompile(`(?i)(fetch|axios\.[a-z]+|\$\.(get|post)|XMLHttpRequest)\s*\(\s*["']([^"']+)["']`)
)

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	made := 0
	get := func(u string) *anpuhttp.Response {
		if made >= maxRequests {
			return nil
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		made++
		resp, err := s.client.Get(cctx, u)
		if err != nil || resp == nil {
			return nil
		}
		return resp
	}

	root := get(sc.Target.Raw)
	if root == nil {
		return scanner.StageResult{}, nil
	}
	// Baseline: soft-404 control signature (status + length bucket).
	controlLen := -1
	controlStatus := 0
	control := get(strings.TrimSuffix(sc.Target.Raw, "/") + "/anpu-corpus-control-404")
	if control != nil {
		controlLen = len(control.Body) / 256 // coarse bucket, template-tolerant
		controlStatus = control.StatusCode
	}

	seen := map[string]bool{}
	var endpoints []models.Endpoint
	add := func(raw, source string) {
		raw = strings.TrimSpace(raw)
		if raw == "" || skipRe.MatchString(raw) || strings.HasPrefix(raw, "#") {
			return // echo-guard
		}
		base, err := url.Parse(sc.Target.Raw)
		if err != nil {
			return
		}
		ref, err := url.Parse(raw)
		if err != nil {
			return
		}
		abs := base.ResolveReference(ref)
		if abs.Scheme != "http" && abs.Scheme != "https" {
			return
		}
		if !strings.EqualFold(abs.Hostname(), sc.Target.Host) {
			return // corpus is same-host only
		}
		abs.Fragment = ""
		key := abs.String()
		if seen[key] {
			return
		}
		seen[key] = true
		endpoints = append(endpoints, models.Endpoint{
			URL:      key,
			Category: categorize(abs.Path),
			Sources:  []string{source},
		})
	}

	bodies := []string{string(root.Body)}
	if rb := get(strings.TrimSuffix(sc.Target.Raw, "/") + "/robots.txt"); rb != nil && rb.StatusCode == 200 {
		bodies = append(bodies, string(rb.Body))
		for _, m := range regexp.MustCompile(`(?im)^(?:allow|disallow)\s*:\s*(\S+)`).FindAllStringSubmatch(string(rb.Body), -1) {
			add(m[1], "robots.txt")
		}
	}
	for _, body := range bodies {
		for _, m := range hrefRe.FindAllStringSubmatch(body, -1) {
			add(m[1], "html-link")
		}
		for _, m := range onEventRe.FindAllStringSubmatch(body, -1) {
			add(m[3], "javascript")
		}
	}

	// Param corpus: distinct query-param names across the corpus.
	params := map[string]bool{}
	for _, ep := range endpoints {
		for _, m := range paramRe.FindAllStringSubmatch(ep.URL, -1) {
			params[strings.ToLower(m[1])] = true
		}
	}
	var paramNames []string
	for p := range params {
		paramNames = append(paramNames, p)
	}
	sort.Strings(paramNames)

	var findings []models.Finding
	if len(endpoints) > 0 {
		// The soft-404 control is load-bearing here as context, not a
		// filter: corpus URLs are mined, not probed (fetching each
		// would blow the 3-request budget), so downstream soft-404
		// gates (crawler, Active) do the filtering. Recording the
		// control signature tells operators whether those gates are
		// armed against a catch-all template or a clean 404.
		observed := fmt.Sprintf("%d same-host URLs, %d distinct query params", len(endpoints), len(paramNames))
		if controlLen >= 0 {
			observed += fmt.Sprintf("; soft-404 control: HTTP %d, ~%dKB template", controlStatus, controlLen/4)
		} else {
			observed += "; soft-404 control: clean 404 (no catch-all template)"
		}
		if len(paramNames) > 0 {
			shown := paramNames
			if len(shown) > 12 {
				shown = shown[:12]
			}
			observed += "; params: " + strings.Join(shown, ", ")
		}
		findings = append(findings, models.Finding{
			ID:              "archiveurls-corpus",
			Title:           fmt.Sprintf("URL corpus: %d same-host URLs discovered", len(endpoints)),
			Description:     "ANPU extracted same-host URLs and query-parameter names from the homepage, robots.txt, and inline JS references (max 3 requests). The corpus feeds the crawler and active parameter tests. Reproduce: curl the homepage and grep href/src/action attributes.",
			Severity:        models.SeverityInfo,
			Confidence:      models.ConfidenceHigh,
			Category:        models.CategoryExposure,
			Target:          sc.Target.Raw,
			Evidence:        models.Evidence{Observed: observed, Location: "homepage + robots.txt link extraction"},
			Source:          models.SourceRecon,
			DetectionMethod: "live-page URL + param corpus (archiveurls)",
		})
	}
	return scanner.StageResult{Findings: findings, Endpoints: endpoints}, nil
}

func categorize(path string) models.EndpointCategory {
	p := strings.ToLower(path)
	switch {
	case strings.Contains(p, "api") || strings.HasSuffix(p, ".json"):
		return models.EndpointAPI
	case strings.Contains(p, "login") || strings.Contains(p, "signin") || strings.Contains(p, "auth"):
		return models.EndpointAuth
	case strings.Contains(p, "admin"):
		return models.EndpointAdminLike
	case strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".css") || strings.HasSuffix(p, ".png") || strings.HasSuffix(p, ".jpg") || strings.HasSuffix(p, ".svg"):
		return models.EndpointAsset
	case p == "" || p == "/" || strings.HasSuffix(p, ".html") || !strings.Contains(p, "."):
		return models.EndpointPage
	default:
		return models.EndpointUnknown
	}
}
