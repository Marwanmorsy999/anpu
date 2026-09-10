// Package subpermute generates subdomain candidates offline (Wave 1
// item 44): permutations of observed subdomains (prefix/suffix/number
// affixes, joined splits) crossed with a 40-word list, then bounded
// DNS resolution (50 A lookups, DNS-only, zero target HTTP). Confirmed
// hosts become Subdomains for Takeover review. Deterministic:
// same input → same candidates.
package subpermute

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// wordlist and caps bound generation + resolution.
var affixes = []string{
	"www", "api", "dev", "staging", "test", "admin", "internal", "beta",
	"prod", "qa", "uat", "demo", "mail", "vpn", "cdn", "static", "assets",
	"blog", "shop", "app", "mobile", "m", "portal", "secure", "login",
	"auth", "sso", "git", "ci", "jenkins", "jira", "status", "monitor",
	"metrics", "logs", "backup", "db", "staging2", "old", "new",
}

// maxResolve bounds DNS lookups per scan.
const maxResolve = 50

// Scanner implements scanner.Scanner.
type Scanner struct {
	// lookupIP is overridable in tests.
	lookupIP func(host string) ([]net.IP, error)
}

// New builds a Scanner.
func New() *Scanner { return &Scanner{lookupIP: net.LookupIP} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "subpermute" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

// generate builds candidates from seeds (pure, tested).
func generate(seeds []string, host string) []string {
	base := registrable(host)
	seen := map[string]bool{}
	var out []string
	add := func(c string) {
		c = strings.ToLower(strings.TrimSuffix(c, "."))
		if c == "" || seen[c] || len(out) >= 500 {
			return
		}
		seen[c] = true
		out = append(out, c)
	}
	for _, a := range affixes {
		add(a + "." + base)
	}
	for _, seed := range seeds {
		seed = strings.ToLower(strings.TrimSuffix(seed, "."))
		left := strings.TrimSuffix(seed, "."+base)
		if left == seed {
			continue // outside our base
		}
		for _, a := range affixes {
			add(left + "-" + a + "." + base)
			add(a + "-" + left + "." + base)
		}
		add(left + "2." + base)
		add(left + "1." + base)
		// Split joins: "api-dev" → "apidev".
		if strings.Contains(left, "-") {
			add(strings.ReplaceAll(left, "-", "") + "." + base)
		}
		// Number strip: "web01" → "web".
		if n := stripTrailingDigits(left); n != left {
			add(n + "." + base)
		}
	}
	sort.Strings(out)
	return out
}

func stripTrailingDigits(s string) string {
	i := len(s)
	for i > 0 && s[i-1] >= '0' && s[i-1] <= '9' {
		i--
	}
	return s[:i]
}

func registrable(host string) string {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	parts := strings.Split(h, ".")
	if len(parts) < 2 {
		return h
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	host := strings.ToLower(strings.TrimSuffix(sc.Target.Host, "."))
	if host == "" || net.ParseIP(host) != nil || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return scanner.StageResult{}, nil
	}
	seeds := append([]string{host}, sc.Subdomains...)
	cands := generate(seeds, host)
	if len(cands) > maxResolve {
		cands = cands[:maxResolve]
	}
	var confirmed []string
	for _, c := range cands {
		select {
		case <-ctx.Done():
			return scanner.StageResult{Subdomains: confirmed}, nil
		default:
		}
		if ips, err := s.lookupIP(c); err == nil && len(ips) > 0 {
			confirmed = append(confirmed, c)
		}
	}
	var findings []models.Finding
	if len(confirmed) > 0 {
		shown := confirmed
		if len(shown) > 10 {
			shown = shown[:10]
		}
		findings = append(findings, models.Finding{
			ID: "subpermute-confirmed", Title: fmt.Sprintf("%d permutation subdomain(s) resolve (%s probed)", len(confirmed), strconv.Itoa(len(cands))),
			Description: "Offline permutation of observed names, confirmed by DNS resolution (no target HTTP): each is a candidate for takeover review. Reproduce offline: combine subdomains with common affixes and resolve. DNS-only signal.",
			Severity:    models.SeverityInfo, Confidence: models.ConfidenceMedium, Category: models.CategoryExposure,
			Target:   sc.Target.Raw,
			Evidence: models.Evidence{Observed: strings.Join(shown, ", "), Location: "offline permutation + DNS A"},
			Source:   models.SourceRecon, DetectionMethod: "subdomain permutation engine (subpermute, ≤50 DNS lookups)",
		})
	}
	return scanner.StageResult{Findings: findings, Subdomains: confirmed}, nil
}
