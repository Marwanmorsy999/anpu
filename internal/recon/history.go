package recon

// history.go — passive historical URL seeding (gau/waybackurls-style,
// zero target traffic).
//
// Public web archives remember URLs the live app no longer links to:
// old parameters, retired endpoints, versioned API paths. Recon pulls
// them from the Wayback Machine CDX API and the Common Crawl index and
// returns them as Endpoints so the crawler, Active, AuthZ, and Params
// stages work over a larger surface without sending one extra packet
// to the target.
//
// Fully passive (requests go to archive.org / index.commoncrawl.org
// only), so it runs on every profile including safe. Any archive
// failure degrades to a warning — never a scan failure. IP and
// localhost targets are skipped (archives index hostnames).

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

// Archive endpoints, overridable in tests.
var (
	waybackCDXBase  = "https://web.archive.org/cdx/search/cdx"
	commonCrawlBase = "https://index.commoncrawl.org"
	maxHistoryURLs  = 300
	historyTimeout  = 15 * time.Second
)

// fetchHistory returns same-host historical URLs from public archives.
func fetchHistory(ctx context.Context, client *anpuhttp.Client, host string) ([]models.Endpoint, []string) {
	var endpoints []models.Endpoint
	var warnings []string

	if ip := net.ParseIP(host); ip != nil {
		return nil, nil // archives index hostnames, not IPs
	}
	lower := strings.ToLower(strings.TrimSuffix(host, "."))
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return nil, nil
	}

	seen := map[string]bool{}
	add := func(raw, source string) {
		raw = strings.TrimSpace(raw)
		if raw == "" || seen[raw] {
			return
		}
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return
		}
		if !strings.EqualFold(u.Hostname(), host) {
			return
		}
		seen[raw] = true
		endpoints = append(endpoints, models.Endpoint{
			URL:      raw,
			Category: categorizePath(u.Path),
			Sources:  []string{source},
		})
	}

	wb, werr := fetchWayback(ctx, client, host, maxHistoryURLs)
	if werr != nil {
		// Only warn on non-404 issues; 404 just means no archive data for this host
		if !strings.Contains(strings.ToLower(werr.Error()), "status 404") {
			warnings = append(warnings, fmt.Sprintf("wayback history unavailable: %v", werr))
		}
	}
	for _, u := range wb {
		add(u, "wayback")
	}

	remaining := maxHistoryURLs - len(endpoints)
	if remaining > 0 {
		cc, cerr := fetchCommonCrawl(ctx, client, host, remaining)
		if cerr != nil {
			if !strings.Contains(strings.ToLower(cerr.Error()), "status 404") {
				warnings = append(warnings, fmt.Sprintf("commoncrawl history unavailable: %v", cerr))
			}
		}
		for _, u := range cc {
			add(u, "commoncrawl")
		}
	}

	return endpoints, warnings
}

// fetchWayback queries the CDX API for successful captures under host/*.
func fetchWayback(ctx context.Context, client *anpuhttp.Client, host string, limit int) ([]string, error) {
	q := fmt.Sprintf("%s?url=%s/*&output=json&filter=statuscode:200&collapse=urlkey&limit=%d",
		waybackCDXBase, url.QueryEscape(host), limit)
	cctx, cancel := context.WithTimeout(ctx, historyTimeout)
	defer cancel()
	resp, err := client.Get(cctx, q)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 || len(resp.Body) == 0 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	// CDX JSON: first row is the header ["urlkey","timestamp",...].
	var rows [][]string
	if err := json.Unmarshal(resp.Body, &rows); err != nil {
		return nil, fmt.Errorf("decoding cdx response: %w", err)
	}
	var out []string
	for i, r := range rows {
		if i == 0 {
			continue // header
		}
		if len(r) >= 3 && r[2] != "" {
			out = append(out, r[2])
		}
	}
	return out, nil
}

// fetchCommonCrawl resolves the latest index, then lists captures.
func fetchCommonCrawl(ctx context.Context, client *anpuhttp.Client, host string, limit int) ([]string, error) {
	cctx, cancel := context.WithTimeout(ctx, historyTimeout)
	defer cancel()

	idxResp, err := client.Get(cctx, commonCrawlBase+"/collinfo.json")
	if err != nil {
		return nil, err
	}
	if idxResp.StatusCode != 200 {
		return nil, fmt.Errorf("collinfo status %d", idxResp.StatusCode)
	}
	var infos []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(idxResp.Body, &infos); err != nil || len(infos) == 0 {
		return nil, fmt.Errorf("decoding collinfo response")
	}
	indexID := infos[0].ID

	q := fmt.Sprintf("%s/%s-index?url=%s&output=json&matchType=domain&filter=status:200&collapse=urlkey&limit=%d",
		commonCrawlBase, indexID, url.QueryEscape(host), limit)
	resp, err := client.Get(cctx, q)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 || len(resp.Body) == 0 {
		return nil, fmt.Errorf("index status %d", resp.StatusCode)
	}
	var out []string
	for _, line := range strings.Split(string(resp.Body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if rec.URL != "" {
			out = append(out, rec.URL)
		}
	}
	return out, nil
}
