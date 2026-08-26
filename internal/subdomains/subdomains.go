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
	"sort"
	"strings"
	"sync"
	"time"

	httpx "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

type Scanner struct {
	resolver *net.Resolver
	client   *http.Client
}

func New() *Scanner {
	return &Scanner{resolver: net.DefaultResolver, client: &http.Client{Timeout: 20 * time.Second}}
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

	// dnsBrute is already internally concurrent; wait for it before taking
	// the candidate snapshot so deep-profile results cannot be missed.
	if sc.Config.Profile == models.ProfileDeep {
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
		Description:     fmt.Sprintf("Certificate Transparency logs%s revealed hostnames under %q that resolve in public DNS. Each is part of the organization's internet-facing attack surface and should be inventoried and kept patched.", dnsBruteSuffix(sc.Config.Profile), host),
		Severity:        models.SeverityLow,
		Confidence:      models.ConfidenceHigh,
		Category:        models.CategoryExposure,
		Target:          sc.Target.Raw,
		URL:             sc.Target.Raw,
		Evidence:        models.Evidence{Observed: strings.Join(shown, "\n") + extraSuffix(extra), Location: "DNS resolution + Certificate Transparency logs"},
		Source:          models.SourceCustom,
		DetectionMethod: "subdomain enumeration (CT logs + DNS)",
		Impact:          "Forgotten or unmonitored subdomains frequently run outdated software and are a common initial-access path.",
		Remediation:     "Inventory all subdomains; decommission unused hosts and keep remaining ones behind the same patching/monitoring regime as primary assets.",
	}}
	return scanner.StageResult{Findings: findings, Warnings: warnings}, nil
}

func (s *Scanner) queryCTLogs(ctx context.Context, host string) ([]string, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", host), nil)
	if err != nil {
		return nil, ""
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Sprintf("crt.sh query failed (continuing with other sources): %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Sprintf("crt.sh returned status %d (continuing with other sources)", resp.StatusCode)
	}
	var rows []crtshResponse
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
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
			if ips, err := s.resolver.LookupIPAddr(cctx, name); err == nil && len(ips) > 0 {
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
			if ips, err := s.resolver.LookupIPAddr(cctx, name); err == nil && len(ips) > 0 {
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

func dnsBruteSuffix(p models.Profile) string {
	if p == models.ProfileDeep {
		return " and DNS brute-forcing"
	}
	return ""
}
func extraSuffix(extra int) string {
	if extra > 0 {
		return fmt.Sprintf("\n… and %d more", extra)
	}
	return ""
}
