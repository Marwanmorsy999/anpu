package subdomains

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// Passive source endpoints. Package vars so tests can point them at
// httptest fixtures. All sources are free and keyless.
var (
	commonCrawlIndexBase = "https://index.commoncrawl.org"
	urlscanAPIBase       = "https://urlscan.io"
	certspotterAPIBase   = "https://api.certspotter.com"
	hackertargetAPIBase  = "https://api.hackertarget.com"
	anubisDBBase         = "https://anubisdb.com"
	anubisDBLegacyBase   = "https://jldc.me/anubis"
)

// sourceResult carries one passive source's harvest.
type sourceResult struct {
	names []string
	warn  string
}

// queryPassiveSources fans out to every keyless passive source at once.
// A dead source degrades silently (empty harvest, no warning) except for
// explicit rate-limit responses, which get a single warning.
func (s *Scanner) queryPassiveSources(ctx context.Context, host string) ([]string, []string) {
	queries := []func(context.Context, string) sourceResult{
		func(ctx context.Context, host string) sourceResult {
			names, warn := s.queryCTLogs(ctx, host)
			return sourceResult{names: names, warn: warn}
		},
		func(ctx context.Context, host string) sourceResult {
			return sourceResult{names: s.queryCommonCrawl(ctx, host)}
		},
		func(ctx context.Context, host string) sourceResult {
			return s.queryURLScan(ctx, host)
		},
		func(ctx context.Context, host string) sourceResult {
			return sourceResult{names: s.queryCertspotter(ctx, host)}
		},
		func(ctx context.Context, host string) sourceResult {
			return sourceResult{names: s.queryHackertarget(ctx, host)}
		},
		func(ctx context.Context, host string) sourceResult {
			return sourceResult{names: s.queryAnubisDB(ctx, host)}
		},
	}

	var mu sync.Mutex
	var all []string
	var warns []string
	var wg sync.WaitGroup
	for _, q := range queries {
		wg.Add(1)
		go func(query func(context.Context, string) sourceResult) {
			defer wg.Done()
			r := query(ctx, host)
			mu.Lock()
			all = append(all, r.names...)
			if r.warn != "" {
				warns = append(warns, r.warn)
			}
			mu.Unlock()
		}(q)
	}
	wg.Wait()
	return all, warns
}

// fetchCapped GETs a URL and returns up to maxBytes of the body for
// status-200 responses.
func (s *Scanner) fetchCapped(ctx context.Context, url string, maxBytes int64) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	return body, resp.StatusCode, err
}

// queryCommonCrawl harvests hostnames from the Common Crawl columnar
// index (domain match). No key required.
func (s *Scanner) queryCommonCrawl(ctx context.Context, host string) []string {
	index := s.latestCommonCrawlIndex(ctx)
	if index == "" {
		return nil
	}
	u := fmt.Sprintf("%s/%s-index?url=%s&output=json&matchType=domain&filter=status:200&collapse=urlkey&limit=500", commonCrawlIndexBase, index, host)
	body, _, err := s.fetchCapped(ctx, u, 4<<20)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var row struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil || row.URL == "" {
			continue
		}
		out = append(out, hostFromURL(row.URL))
	}
	return out
}

// latestCommonCrawlIndex resolves the newest crawl ID via collinfo.json,
// falling back to a recent known-good ID when the lookup fails.
func (s *Scanner) latestCommonCrawlIndex(ctx context.Context) string {
	body, _, err := s.fetchCapped(ctx, commonCrawlIndexBase+"/collinfo.json", 1<<20)
	if err == nil {
		var infos []struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &infos); err == nil && len(infos) > 0 && infos[0].ID != "" {
			return infos[0].ID
		}
	}
	return "CC-MAIN-2025-30"
}

// queryURLScan harvests via urlscan.io's keyless search API (capped at
// 100 results). A 429 surfaces one warning; anything else is silent.
func (s *Scanner) queryURLScan(ctx context.Context, host string) sourceResult {
	u := fmt.Sprintf("%s/api/v1/search/?q=domain:%s&size=100", urlscanAPIBase, host)
	body, status, err := s.fetchCapped(ctx, u, 2<<20)
	if err != nil {
		if status == http.StatusTooManyRequests {
			return sourceResult{warn: "urlscan.io rate-limited this scan (continuing with other sources)"}
		}
		return sourceResult{}
	}
	var doc struct {
		Results []struct {
			Page struct {
				Domain string `json:"domain"`
			} `json:"page"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return sourceResult{}
	}
	var out []string
	for _, r := range doc.Results {
		if r.Page.Domain != "" {
			out = append(out, r.Page.Domain)
		}
	}
	return sourceResult{names: out}
}

// queryCertspotter harvests DNS names from Certificate Transparency via
// CertSpotter's keyless API.
func (s *Scanner) queryCertspotter(ctx context.Context, host string) []string {
	u := fmt.Sprintf("%s/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", certspotterAPIBase, host)
	body, _, err := s.fetchCapped(ctx, u, 4<<20)
	if err != nil {
		return nil
	}
	var rows []struct {
		DNSNames []string `json:"dns_names"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.DNSNames...)
	}
	return out
}

// queryHackertarget harvests via hackertarget's keyless hostsearch
// (CSV lines of "hostname,ip").
func (s *Scanner) queryHackertarget(ctx context.Context, host string) []string {
	u := fmt.Sprintf("%s/hostsearch/?q=%s", hackertargetAPIBase, host)
	body, _, err := s.fetchCapped(ctx, u, 1<<20)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		if idx := strings.Index(line, ","); idx > 0 {
			out = append(out, strings.TrimSpace(line[:idx]))
		}
	}
	return out
}

// queryAnubisDB harvests via the keyless Anubis subdomain database,
// which returns a JSON array of hostnames. Tries anubisdb.com first
// with legacy jldc.me fallback.
func (s *Scanner) queryAnubisDB(ctx context.Context, host string) []string {
	for _, base := range []string{anubisDBBase, anubisDBLegacyBase} {
		if base == "" {
			continue
		}
		u := fmt.Sprintf("%s/subdomains/%s", base, host)
		body, _, err := s.fetchCapped(ctx, u, 1<<20)
		if err != nil {
			continue
		}
		var names []string
		if err := json.Unmarshal(body, &names); err != nil {
			continue
		}
		if len(names) > 0 {
			return names
		}
		// Empty but valid response — still try legacy? No, return empty
		// only if primary succeeded; fallback only on error/parse fail.
		// To keep behavior simple, return what we got if unmarshal worked.
		return names
	}
	return nil
}

// hostFromURL extracts the hostname from a URL string, tolerating
// missing schemes, userinfo, ports, and trailing dots.
func hostFromURL(raw string) string {
	lower := strings.ToLower(strings.TrimSpace(raw))
	if idx := strings.Index(lower, "://"); idx >= 0 {
		lower = lower[idx+3:]
	}
	if idx := strings.IndexAny(lower, "/?#"); idx >= 0 {
		lower = lower[:idx]
	}
	if idx := strings.LastIndex(lower, "@"); idx >= 0 {
		lower = lower[idx+1:]
	}
	if idx := strings.LastIndex(lower, ":"); idx >= 0 {
		lower = lower[:idx]
	}
	return strings.TrimSuffix(lower, ".")
}

// permutationAffixes are dnsgen-style mutations applied to discovered
// labels (standard profile and up — never on safe).
var permutationAffixes = []string{
	"dev", "development", "staging", "stage", "prod", "production",
	"test", "testing", "beta", "alpha", "old", "new", "backup",
	"internal", "corp", "demo", "qa", "dr", "api", "web", "app",
	"us", "eu", "uk", "asia", "cms", "cdn",
}

// maxPermutations caps dnsgen-style resolution volume.
const maxPermutations = 500

// permutate builds dnsgen-style candidates from confirmed hostnames:
// affix±label mutations plus digit suffixes on short labels.
func permutate(host string, names []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(n string) {
		if len(out) >= maxPermutations || seen[n] || n == host {
			return
		}
		seen[n] = true
		out = append(out, n)
	}
	for _, n := range names {
		if !strings.HasSuffix(n, "."+host) {
			continue
		}
		label := strings.TrimSuffix(n, "."+host)
		if strings.Contains(label, ".") || label == "" || label == "www" {
			continue
		}
		for _, aff := range permutationAffixes {
			add(aff + "-" + label + "." + host)
			add(label + "-" + aff + "." + host)
			if len(out) >= maxPermutations {
				return out
			}
		}
		if len(label) <= 8 {
			for _, d := range []string{"1", "2", "3", "01", "02"} {
				add(label + d + "." + host)
			}
		}
	}
	return out
}
