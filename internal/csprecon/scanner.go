// Package csprecon derives subdomain candidates from Content-Security-Policy
// (Wave 1 item 6): one GET, parse the CSP response header plus <meta
// http-equiv="Content-Security-Policy">, extract host-sources, and return
// same-registrable-domain hosts as Subdomains for the Takeover stage.
//
// Echo-guard: CSP keywords ('self', 'none', nonces, hashes), schemes,
// and data:/blob: are never emitted. Deterministic, zero extra traffic.
package csprecon

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "csprecon" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

var (
	metaCSPRe = regexp.MustCompile(`(?is)<meta[^>]+http-equiv\s*=\s*["']?content-security-policy["']?[^>]*content\s*=\s*["']([^"']+)["']`)
	hostSrcRe = regexp.MustCompile(`(?i)(?:^|[\s;])(https?://[^\s;'"]+|\*\.[a-z0-9.\-]+|[a-z0-9.\-]+\.[a-z]{2,})`)
)

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resp, err := s.client.Get(cctx, sc.Target.Raw)
	if err != nil || resp == nil {
		return scanner.StageResult{}, nil
	}
	var policies []string
	if h := resp.Header.Get("Content-Security-Policy"); h != "" {
		policies = append(policies, h)
	}
	if h := resp.Header.Get("Content-Security-Policy-Report-Only"); h != "" {
		policies = append(policies, h)
	}
	if m := metaCSPRe.FindStringSubmatch(string(resp.Body)); len(m) == 2 {
		policies = append(policies, m[1])
	}
	if len(policies) == 0 {
		return scanner.StageResult{}, nil
	}
	seen := map[string]bool{}
	for _, p := range policies {
		for _, h := range extractHosts(p) {
			h = normalizeHost(h)
			if h == "" || seen[h] || isKeyword(h) {
				continue
			}
			seen[h] = true
		}
	}
	if len(seen) == 0 {
		return scanner.StageResult{}, nil
	}
	base := registrable(sc.Target.Host)
	var subs []string
	for h := range seen {
		if strings.EqualFold(h, sc.Target.Host) {
			continue // echo-guard: the target itself is not a discovery
		}
		if base != "" && (strings.EqualFold(h, base) || strings.HasSuffix(strings.ToLower(h), "."+base)) {
			subs = append(subs, strings.ToLower(h))
		}
	}
	sort.Strings(subs)
	var findings []models.Finding
	if len(subs) > 0 {
		shown := subs
		if len(shown) > 15 {
			shown = shown[:15]
		}
		findings = append(findings, models.Finding{
			ID:              "csprecon-subdomains",
			Title:           fmt.Sprintf("CSP advertises %d subdomain(s)", len(subs)),
			Description:     "Host-sources in Content-Security-Policy name infrastructure the application trusts. Each same-domain host is a candidate subdomain for takeover review. Reproduce: curl -sI the target and read Content-Security-Policy.",
			Severity:        models.SeverityInfo,
			Confidence:      models.ConfidenceHigh,
			Category:        models.CategoryExposure,
			Target:          sc.Target.Raw,
			Evidence:        models.Evidence{Observed: strings.Join(shown, ", "), Location: "Content-Security-Policy host-sources"},
			Source:          models.SourceRecon,
			DetectionMethod: "CSP host-source extraction (csprecon, 1 request)",
		})
	}
	return scanner.StageResult{Findings: findings, Subdomains: subs}, nil
}

// extractHosts pulls candidate host tokens from a CSP policy string.
func extractHosts(policy string) []string {
	var out []string
	for _, m := range hostSrcRe.FindAllStringSubmatch(policy, -1) {
		out = append(out, strings.Trim(m[1], "'\""))
	}
	return out
}

// normalizeHost strips scheme, port, path, and leading wildcard.
func normalizeHost(raw string) string {
	r := strings.TrimSpace(raw)
	r = strings.TrimPrefix(strings.TrimPrefix(r, "https://"), "http://")
	if i := strings.Index(r, "/"); i >= 0 {
		r = r[:i]
	}
	if i := strings.LastIndex(r, ":"); i >= 0 && strings.Count(r, ":") == 1 {
		r = r[:i]
	}
	r = strings.TrimPrefix(r, "*.")
	r = strings.ToLower(strings.TrimSuffix(r, "."))
	return r
}

func isKeyword(h string) bool {
	switch strings.ToLower(h) {
	case "self", "none", "unsafe-inline", "unsafe-eval", "strict-dynamic",
		"unsafe-hashes", "report-sample", "https:", "http:", "data:", "blob:",
		"mediastream:", "filesystem:", "wss:", "ws:":
		return true
	}
	if strings.HasPrefix(h, "'") || strings.HasPrefix(h, "nonce-") || strings.HasPrefix(h, "sha256-") || strings.HasPrefix(h, "sha384-") || strings.HasPrefix(h, "sha512-") {
		return true
	}
	return !strings.Contains(h, ".")
}

// registrable returns a two-label base (example.com) for same-domain
// comparison. Best-effort without a PSL dependency.
func registrable(host string) string {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	parts := strings.Split(h, ".")
	if len(parts) < 2 {
		return h
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
