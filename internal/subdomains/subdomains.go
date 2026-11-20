// Package subdomains enumerates subdomains of the scan target using two
// complementary techniques:
//
//  1. Passive: querying public Certificate Transparency logs (crt.sh) —
//     the same data source tools like subfinder/amass aggregate. No
//     requests are sent to the target itself for this part.
//  2. Active (deep profile only): DNS brute-forcing a built-in list of
//     common subdomain prefixes.
//
// Every candidate is resolved against public DNS; only live hostnames
// are reported, each as an information-exposure finding that widens the
// target's known attack surface.
package subdomains

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	httpx "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

type Scanner struct {
	resolver *net.Resolver
	client   *httpx.Client
	scanCtx  *scanner.ScanContext
}

// dnsLookup is the DNS resolution entry point. It is a package-level var so
// tests can stub it with a fake resolver without touching real network.
var dnsLookup = func(ctx context.Context, resolver *net.Resolver, host string) ([]net.IPAddr, error) {
	return resolver.LookupIPAddr(ctx, host)
}

func New(client *httpx.Client) *Scanner {
	if client == nil {
		client = httpx.NewClientWithLocalNetworkAllowed(true)
	}
	return &Scanner{resolver: net.DefaultResolver, client: client}
}

func (s *Scanner) Name() string                       { return "subdomains" }
func (s *Scanner) Available(ctx context.Context) bool { return true }

var dnsBruteWords = []string{
	"www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
	"smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test", "portal",
	"ns", "ww1", "host", "support", "dev", "web", "bbs", "mx", "email",
	"cloud", "1", "mail1", "2", "forum", "owa", "www2", "gw", "admin",
	"store", "mx1", "cdn", "api", "staging", "stage", "beta", "alpha",
	"sandbox", "app", "intranet", "git", "jenkins", "ci", "jira", "wiki",
	"docs", "status", "monitor", "grafana", "kibana", "db", "database",
	"mysql", "postgres", "redis", "mongo", "backup", "old", "new", "demo",
	"sso", "auth", "login", "id", "assets", "static", "img", "images",
	"media", "files", "download", "downloads", "internal", "corp", "lab",
}

type crtshResponse struct {
	NameValue string `json:"name_value"`
}

func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	s.scanCtx = sc
	defer func() { s.scanCtx = nil }()
	// Per-stage deadline: subdomains ≤60s total.
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	host := strings.ToLower(strings.TrimSuffix(sc.Target.Host, "."))
	if host == "" || !strings.Contains(host, ".") {
		return scanner.StageResult{}, nil
	}

	var (
		found    = map[string]bool{}
		mu       sync.Mutex
		warnings []string
	)
	collect := func(names []string) {
		mu.Lock()
		defer mu.Unlock()
		for _, n := range names {
			n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
			if n == host || strings.HasSuffix(n, "."+host) {
				n = strings.TrimPrefix(n, "*.")
				if n != "" && net.ParseIP(n) == nil && strings.Contains(n, ".") {
					found[n] = true
				}
			}
		}
	}

	ctNames, ctWarn := s.queryCTLogs(ctx, host)
	if ctWarn != "" {
		warnings = append(warnings, ctWarn)
	}
	collect(ctNames)

	// Keyless passive indexes (Common Crawl, urlscan, CertSpotter,
	// hackertarget, Anubis-DB) — all profiles, zero target traffic.
	passiveNames, passiveWarns := s.queryPassiveSources(ctx, host)
	warnings = append(warnings, passiveWarns...)
	collect(passiveNames)

	// dnsgen-style permutations on standard profile and up (never safe).
	if sc.Config.Profile.Normalize() != models.ProfileSafe {
		collect(permutate(host, foundMapKeys(found)))
	}

	// dnsBrute is already internally concurrent; wait for it before taking
	// the candidate snapshot so deep-profile results cannot be missed.
	if sc.Config.Profile.Normalize() == models.ProfileUltra {
		collect(s.dnsBrute(ctx, host))
	}

	live := s.resolveAll(ctx, foundMapKeys(found))
	if len(live) == 0 {
		return scanner.StageResult{Warnings: warnings}, nil
	}

	sort.Strings(live)
	shown, extra := live, 0
	if len(live) > 50 {
		shown, extra = live[:50], len(live)-50
	}
	findings := []models.Finding{{
		ID:              "subdomains-discovered",
		Title:           fmt.Sprintf("%d live subdomain(s) discovered", len(live)),
		Description:     fmt.Sprintf("Passive certificate, crawl and search indexes%s revealed hostnames under %q that resolve in public DNS. Each is part of the organization's internet-facing attack surface and should be inventoried and kept patched.", enumSuffix(sc.Config.Profile), host),
		Severity:        models.SeverityLow,
		Confidence:      models.ConfidenceHigh,
		Category:        models.CategoryExposure,
		Target:          sc.Target.Raw,
		URL:             sc.Target.Raw,
		Evidence:        models.Evidence{Observed: strings.Join(shown, "\n") + extraSuffix(extra), Location: "DNS resolution + passive subdomain indexes"},
		Source:          models.SourceCustom,
		DetectionMethod: "subdomain enumeration (passive indexes + DNS)",
		Impact:          "Forgotten or unmonitored subdomains frequently run outdated software and are a common initial-access path.",
		Remediation:     "Inventory all subdomains; decommission unused hosts and keep remaining ones behind the same patching/monitoring regime as primary assets.",
	}}
	return scanner.StageResult{Findings: findings, Warnings: warnings, Subdomains: live}, nil
}

// DefaultCTLogBaseURL is the certificate-transparency log used when no
// override is configured.
const DefaultCTLogBaseURL = "https://crt.sh"

// ctlogBaseURL resolves the CT-log base URL: config field first, then
// ANPU_CTLOG_BASE_URL, then the default. The value must be a well-formed
// absolute http(s) URL; anything else falls back to the default so a
// misconfiguration cannot redirect requests to an unintended host.
func ctlogBaseURL(sc *scanner.ScanContext) string {
	base := ""
	if sc != nil {
		base = strings.TrimSpace(sc.Config.CTLogBaseURL)
	}
	if base == "" {
		base = strings.TrimSpace(os.Getenv("ANPU_CTLOG_BASE_URL"))
	}
	if base == "" {
		base = DefaultCTLogBaseURL
	}
	u, err := url.Parse(base)
	if err != nil || !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") {
		return DefaultCTLogBaseURL
	}
	return strings.TrimSuffix(base, "/")
}

func (s *Scanner) queryCTLogs(ctx context.Context, host string) ([]string, string) {
	base := ctlogBaseURL(s.scanCtx)
	u := fmt.Sprintf("%s/?q=%%25.%s&output=json", base, host)
	if err := scanner.ChargeBudget(s.scanCtx); err != nil {
		return nil, ""
	}
	resp, err := s.client.Get(ctx, u)
	if err != nil {
		return nil, fmt.Sprintf("crt.sh query failed (continuing with other sources): %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Sprintf("crt.sh returned status %d (continuing with other sources)", resp.StatusCode)
	}
	var rows []crtshResponse
	if err := json.Unmarshal(resp.Body, &rows); err != nil {
		return nil, fmt.Sprintf("could not parse crt.sh output: %v", err)
	}
	var out []string
	for _, r := range rows {
		out = append(out, strings.Split(r.NameValue, "\n")...)
	}
	return out, ""
}

func (s *Scanner) dnsBrute(ctx context.Context, host string) []string {
	sem := make(chan struct{}, 16)
	var mu sync.Mutex
	var out []string
	var wg sync.WaitGroup
	for _, w := range dnsBruteWords {
		wg.Add(1)
		go func(prefix string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			name := prefix + "." + host
			cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			if ips, err := dnsLookup(cctx, s.resolver, name); err == nil && len(ips) > 0 {
				mu.Lock()
				out = append(out, name)
				mu.Unlock()
			}
		}(w)
	}
	wg.Wait()
	return out
}

func (s *Scanner) resolveAll(ctx context.Context, candidates []string) []string {
	sem := make(chan struct{}, 20)
	var mu sync.Mutex
	var out []string
	var wg sync.WaitGroup
	for _, c := range candidates {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			if ips, err := dnsLookup(cctx, s.resolver, name); err == nil && len(ips) > 0 {
				mu.Lock()
				out = append(out, name)
				mu.Unlock()
			}
		}(c)
	}
	wg.Wait()
	if !scanner.AllowLocalNetwork {
		filtered := out[:0]
		for _, name := range out {
			if httpx.ValidateHostPublic(name) == nil {
				filtered = append(filtered, name)
			}
		}
		out = filtered
	}
	return out
}

func foundMapKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func enumSuffix(p models.Profile) string {
	switch p.Normalize() {
	case models.ProfileUltra:
		return ", name permutations and DNS brute-forcing"
	case models.ProfileSafe:
		return ""
	default:
		return " and name permutations"
	}
}
func extraSuffix(extra int) string {
	if extra > 0 {
		return fmt.Sprintf("\n… and %d more", extra)
	}
	return ""
}
