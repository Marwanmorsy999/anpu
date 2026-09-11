// Package originip hunts origin-IP exposure signals (Wave 1 item 10)
// without any third-party API: CNAME chain (CDN keyword match), apex A
// records, and — when the host sits behind a CDN name — a bounded
// direct-IP probe (max 3 requests total) comparing the direct-IP page
// title against the homepage baseline. A byte-similar direct-IP page
// means the origin serves traffic past the CDN/WAF: High value, Low
// severity (exposure), needs manual confirm.
//
// No APIs, no brute force, no Host-header poisoning: the direct probe
// uses GetWithHost for the target's own hostname only.
package originip

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/anpu-project/anpu/internal/fpmatch"
	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// maxRequests bounds all HTTP traffic for this stage.
const maxRequests = 3

// cdnMarkers match CNAME targets of common CDN/WAF providers.
var cdnMarkers = []string{
	"cloudflare", "akamai", "fastly", "cloudfront", "azureedge",
	"azurefd", "frontdoor", "cloudarmor", "googlehosted", "googlesyndication",
	"incapsula", "imperva", "sucuri", "stackpath", "keycdn", "bunnycdn",
	"bunny", "cdn77", "jsdelivr", "edgecast", "limelight", "leaseweb",
	"ovh", "g-core", "gcore", "cachefly", "alicdn", "vercel", "netlify",
}

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
	// lookup hooks for hermetic tests.
	lookupCNAME func(host string) (string, error)
	lookupIP    func(host string) ([]net.IP, error)
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner {
	return &Scanner{client: client, lookupCNAME: net.LookupCNAME, lookupIP: net.LookupIP}
}

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "originip" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	host := strings.ToLower(strings.TrimSuffix(sc.Target.Host, "."))
	if host == "" || net.ParseIP(host) != nil || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return scanner.StageResult{}, nil
	}
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

	var signals []string
	behindCDN := false
	if cname, err := s.lookupCNAME(host); err == nil && cname != "" {
		cname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cname), "."))
		if !strings.EqualFold(cname, host) && !strings.EqualFold(cname, host+".") {
			signals = append(signals, "CNAME "+host+" → "+cname)
			if cdnName(cname) != "" {
				behindCDN = true
				signals = append(signals, "CDN/WAF hint: "+cdnName(cname))
			}
		}
	}
	ips, _ := s.lookupIP(host)
	if len(ips) > 0 {
		var v4 []string
		for _, ip := range ips {
			if ip.To4() != nil {
				v4 = append(v4, ip.String())
			}
		}
		if len(v4) > 0 {
			shown := v4
			if len(shown) > 4 {
				shown = shown[:4]
			}
			signals = append(signals, "A "+strings.Join(shown, ", "))
		}
	}

	var findings []models.Finding
	if behindCDN && len(ips) > 0 {
		// Baseline: homepage title + body words; probe: direct-IP with
		// Host override. Title equality alone is weak for SPA shells
		// (same <title> on edge + origin), so confirmation also
		// requires body word similarity (Phase 2).
		var baseline string
		var baselineWords map[string]struct{}
		if root := get(sc.Target.Raw); root != nil {
			baseline = normTitle(extractTitle(string(root.Body)))
			baselineWords = fpmatch.WordSet(root.Body)
		}
		for _, ip := range ips {
			if ip.To4() == nil || made >= maxRequests {
				continue
			}
			scheme := sc.Target.URL.Scheme
			if scheme == "" {
				scheme = "https"
			}
			direct := fmt.Sprintf("%s://%s/", scheme, ip.String())
			cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			made++
			presp, perr := s.client.GetWithHost(cctx, direct, host, nil)
			cancel()
			if perr != nil || presp == nil {
				continue
			}
			ptitle := normTitle(extractTitle(string(presp.Body)))
			// Baseline-subtract + echo-guard: empty titles and
			// default-server pages never count. Beyond title equality,
			// the direct-IP body must share vocabulary with the
			// homepage (Jaccard ≥ OriginMatch) — a coincidental title
			// on unrelated content is not an origin bypass.
			bodySim := fpmatch.Similarity(baselineWords, fpmatch.WordSet(presp.Body))
			if ptitle != "" && baseline != "" && strings.EqualFold(ptitle, baseline) && !defaultPageTitle(ptitle) && bodySim >= fpmatch.OriginMatch {
				findings = append(findings, models.Finding{
					ID:              "originip-direct-exposure",
					Title:           fmt.Sprintf("Origin reachable directly at %s (bypasses CDN/WAF)", ip.String()),
					Description:     fmt.Sprintf("Fetching http(s)://%s/ with the target Host header returns the same page title %q as the homepage (body similarity %.2f), so the origin serves traffic past the CDN/WAF. Firewall the origin to the CDN ranges and rotate the address. Reproduce: curl -k --resolve %s:443:%s https://%s/ | grep -i <title>.", ip.String(), ptitle, bodySim, host, ip.String(), host),
					Severity:        models.SeverityLow,
					Confidence:      models.ConfidenceMedium,
					Category:        models.CategoryExposure,
					Target:          sc.Target.Raw,
					URL:             direct,
					Evidence:        models.Evidence{Observed: fmt.Sprintf("direct-IP title %q == homepage title (body similarity %.2f); signals: %s", ptitle, bodySim, strings.Join(signals, "; ")), Location: "direct-IP probe vs homepage baseline"},
					Source:          models.SourceRecon,
					DetectionMethod: "CNAME/CDN + direct-IP title and body comparison (originip, ≤3 requests)",
					Remediation:     "Restrict origin ingress to CDN/WAF egress ranges; rotate the origin IP.",
				})
				break // one confirmation is enough
			}
		}
	}
	if len(findings) == 0 && len(signals) > 0 {
		findings = append(findings, models.Finding{
			ID:              "originip-signals",
			Title:           "Origin intelligence signals collected",
			Description:     "Passive DNS signals (CNAME chain, apex A records) for origin-hunting review. No direct exposure confirmed. Reproduce: nslookup -type=CNAME host; nslookup host.",
			Severity:        models.SeverityInfo,
			Confidence:      models.ConfidenceHigh,
			Category:        models.CategoryExposure,
			Target:          sc.Target.Raw,
			Evidence:        models.Evidence{Observed: strings.Join(signals, "; "), Location: "DNS CNAME/A"},
			Source:          models.SourceRecon,
			DetectionMethod: "CNAME/DNS origin signals (originip, 0 target requests)",
		})
	}
	return scanner.StageResult{Findings: findings}, nil
}

func cdnName(cname string) string {
	l := strings.ToLower(cname)
	for _, m := range cdnMarkers {
		if strings.Contains(l, m) {
			return m
		}
	}
	return ""
}

func extractTitle(body string) string {
	m := titleRe.FindStringSubmatch(body)
	if len(m) != 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

func normTitle(t string) string {
	return strings.Join(strings.Fields(strings.ToLower(t)), " ")
}

func defaultPageTitle(t string) bool {
	for _, d := range []string{"welcome to nginx", "apache2", "iis windows", "default web site", "it works"} {
		if strings.Contains(t, d) {
			return true
		}
	}
	return false
}
