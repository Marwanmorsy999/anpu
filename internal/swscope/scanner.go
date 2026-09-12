// Package swscope analyzes service-worker registration risk (Wave
// next, item 6): homepage scan for navigator.serviceWorker.register
// calls plus bounded probes of conventional script paths. Findings:
// registration with root scope from a non-root script lacking the
// Service-Worker-Allowed header (Low), and cross-origin importScripts
// supply-chain surface (Info). Static + header analysis only — workers
// are never installed or messaged. ≤6 requests.
package swscope

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

// maxRequests bounds all HTTP traffic.
const maxRequests = 6

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "swscope" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

var (
	registerRe = regexp.MustCompile(`(?i)navigator\.serviceWorker\s*\.\s*register\s*\(\s*["']([^"']+)["']\s*(,\s*\{([^}]*)\})?`)
	importRe   = regexp.MustCompile(`(?i)importScripts\s*\(\s*([^)]+)\)`)
	scopeRe    = regexp.MustCompile(`(?i)scope\s*:\s*["']([^"']+)["']`)
	urlLikeRe  = regexp.MustCompile(`https?://[^"'()\s,]+`)
)

var conventionalSW = []string{"/sw.js", "/service-worker.js", "/serviceworker.js"}

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

	base, err := url.Parse(sc.Target.Raw)
	if err != nil {
		return scanner.StageResult{}, nil
	}
	resolve := func(raw string) string {
		ref, err := url.Parse(strings.TrimSpace(raw))
		if err != nil {
			return ""
		}
		abs := base.ResolveReference(ref)
		if abs.Scheme != "http" && abs.Scheme != "https" {
			return ""
		}
		if !strings.EqualFold(abs.Hostname(), sc.Target.Host) {
			return ""
		}
		abs.Fragment = ""
		return abs.String()
	}

	home := get(sc.Target.Raw)
	if home == nil {
		return scanner.StageResult{}, nil
	}
	scripts := map[string]string{} // script URL → declared scope ("" if none)
	for _, m := range registerRe.FindAllStringSubmatch(string(home.Body), -1) {
		if u := resolve(m[1]); u != "" {
			scope := ""
			if len(m) > 3 {
				if sm := scopeRe.FindStringSubmatch(m[3]); sm != nil {
					scope = sm[1]
				}
			}
			scripts[u] = scope
		}
	}
	// Conventional paths as fallback candidates.
	for _, p := range conventionalSW {
		if len(scripts) >= 4 || made >= maxRequests {
			break
		}
		u := strings.TrimSuffix(sc.Target.Raw, "/") + p
		if resp := get(u); resp != nil && resp.StatusCode == 200 && len(resp.Body) > 32 {
			// Echo-guard: only worker-shaped bodies (catch-all HTML
			// fallbacks must not register as workers).
			bl := strings.ToLower(string(resp.Body))
			if !strings.Contains(bl, "addeventlistener") && !strings.Contains(bl, "importscripts") && !strings.Contains(bl, "self.") {
				continue
			}
			if _, ok := scripts[u]; !ok {
				scripts[u] = ""
			}
		}
	}

	var findings []models.Finding
	var names []string
	for u := range scripts {
		names = append(names, u)
	}
	sort.Strings(names)
	for _, u := range names {
		if made >= maxRequests {
			break
		}
		resp := get(u)
		if resp == nil || resp.StatusCode != 200 {
			continue
		}
		body := string(resp.Body)
		// Root scope from a nested script without the allow header.
		if scripts[u] == "/" {
			su, _ := url.Parse(u)
			if su != nil && su.Path != "/" && su.Path != "" && resp.Header.Get("Service-Worker-Allowed") == "" {
				findings = append(findings, mkFinding(sc, "swscope-broad-scope",
					"Service worker claims root scope without Service-Worker-Allowed",
					fmt.Sprintf("The worker at %s declares scope '/' but the response lacks Service-Worker-Allowed (browsers then clamp scope — unless a proxy strips the rules). Keep worker scope tight and the allow header explicit. Reproduce: curl -sI %s.", displayPath(u), u),
					models.SeverityLow, "scope '/' without Service-Worker-Allowed", u))
			}
		}
		// Cross-origin importScripts supply chain.
		var foreign []string
		for _, m := range importRe.FindAllStringSubmatch(body, -1) {
			for _, cand := range urlLikeRe.FindAllString(m[1], -1) {
				cu, err := url.Parse(cand)
				if err != nil || !strings.EqualFold(cu.Hostname(), sc.Target.Host) {
					if cu != nil && cu.Hostname() != "" {
						foreign = append(foreign, cu.Hostname())
					}
				}
			}
		}
		if len(foreign) > 0 {
			sort.Strings(foreign)
			findings = append(findings, mkFinding(sc, "swscope-foreign-import",
				"Service worker imports cross-origin scripts",
				fmt.Sprintf("The worker at %s importScripts() from %s: a persistent, high-privilege context trusting third parties. Vendor or integrity-pin worker code. Reproduce: fetch the worker and grep importScripts.", displayPath(u), strings.Join(foreign, ", ")),
				models.SeverityInfo, "foreign importScripts: "+strings.Join(foreign, ", "), u))
		}
		if len(findings) >= 4 {
			break
		}
	}
	return scanner.StageResult{Findings: findings}, nil
}

func mkFinding(sc *scanner.ScanContext, id, title, desc string, sev models.Severity, observed, u string) models.Finding {
	return models.Finding{
		ID: id, Title: title, Description: desc,
		Severity: sev, Confidence: models.ConfidenceMedium, Category: models.CategoryExposure,
		Target: sc.Target.Raw, URL: u,
		Evidence: models.Evidence{Observed: observed, Location: "service worker analysis"},
		Source:   models.SourceEndpoints, DetectionMethod: "SW registration/scope analysis (swscope, ≤6 requests)",
		Remediation: "Least-privilege worker scope; pin worker supply chain.",
	}
}

func displayPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	p := u.Path
	if p == "" {
		p = "/"
	}
	return p
}
