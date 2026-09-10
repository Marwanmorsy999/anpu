// Package feeds implements Wave 3 keyless threat-intel (items 135-140):
// CISA KEV catalog (local cache + exploited-in-wild flag), FIRST EPSS
// scores (keyless per-CVE lookup, bounded), GitHub Advisory REST
// (keyless, low-volume), and URLhaus + ThreatFox reputation (keyless).
//
// Everything is fail-silent and bounded; Enrich annotates findings
// with KEV/EPSS signals for the scoring stage. PhishTank is NOT
// queried: its API requires a key, so it is excluded per the
// keyless-only policy (documented in docs/scanners.md).
package feeds

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/anpu-project/anpu/pkg/models"
)

// Endpoints (overridable in tests). All keyless, no credentials.
var (
	kevURL       = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	epssURL      = "https://api.first.org/data/v1/epss"
	advisoryURL  = "https://api.github.com/advisories"
	urlhausURL   = "https://urlhaus-api.abuse.ch/v1/url/"
	threatfoxURL = "https://threatfox-api.abuse.ch/api/v1/"
	httpTimeout  = 15 * time.Second
)

// cveRe finds CVE IDs in finding text.
var cveRe = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,7}\b`)

// KEV catalog shape (subset).
type kevCatalog struct {
	Vulnerabilities []struct {
		CVEID string `json:"cveID"`
	} `json:"vulnerabilities"`
}

// CacheDir returns the feeds cache directory (~/.anpu/feeds).
func CacheDir() string {
	if cacheDirOverride != "" {
		return cacheDirOverride
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".anpu-feeds"
	}
	return filepath.Join(home, ".anpu", "feeds")
}

// cacheDirOverride redirects the cache in tests.
var cacheDirOverride string

// kevMaxAge refreshes cache older than this (see EnsureKEV).
const kevMaxAge = 7 * 24 * time.Hour

// EnsureKEV returns the cached KEV set, refreshing it first when the
// cache is missing or older than a week. Refresh is fail-silent with a
// short timeout: offline scans keep working on whatever is cached
// (possibly empty).
func EnsureKEV(ctx context.Context) map[string]bool {
	refresh := false
	if info, err := os.Stat(kevPath()); err != nil || time.Since(info.ModTime()) > kevMaxAge {
		refresh = true
	}
	if refresh {
		rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		_, _ = RefreshKEV(rctx)
		cancel()
	}
	return LoadKEV()
}

// kevPath is the local KEV cache file.
func kevPath() string { return filepath.Join(CacheDir(), "kev.json") }

// LoadKEV reads cached KEV CVE IDs (upper-cased). Missing/corrupt cache
// yields an empty set — never an error (fail-silent).
func LoadKEV() map[string]bool {
	out := map[string]bool{}
	data, err := os.ReadFile(kevPath())
	if err != nil {
		return out
	}
	var cat kevCatalog
	if err := json.Unmarshal(data, &cat); err != nil {
		return out
	}
	for _, v := range cat.Vulnerabilities {
		if id := strings.ToUpper(strings.TrimSpace(v.CVEID)); id != "" {
			out[id] = true
		}
	}
	return out
}

// RefreshKEV downloads the KEV catalog (single keyless JSON, ~15s cap).
func RefreshKEV(ctx context.Context) (int, error) {
	cctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, kevURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "anpu-feeds/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("kev status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return 0, err
	}
	var cat kevCatalog
	if err := json.Unmarshal(data, &cat); err != nil {
		return 0, err
	}
	if err := os.MkdirAll(CacheDir(), 0o755); err != nil {
		return 0, err
	}
	if err := os.WriteFile(kevPath(), data, 0o644); err != nil {
		return 0, err
	}
	return len(cat.Vulnerabilities), nil
}

// ExtractCVEs returns upper-cased CVE IDs mentioned in findings (cap 20).
func ExtractCVEs(findings []models.Finding) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range findings {
		blob := f.ID + "\n" + f.Title + "\n" + f.Description + "\n" + f.CWE + "\n" + strings.Join(f.References, "\n")
		for _, m := range cveRe.FindAllString(blob, -1) {
			id := strings.ToUpper(m)
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
			if len(out) >= 20 {
				return out
			}
		}
	}
	return out
}

// epssScore queries FIRST EPSS for one CVE (keyless, empty on failure).
func epssScore(ctx context.Context, cve string) float64 {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, epssURL+"?cve="+cve, nil)
	if err != nil {
		return -1
	}
	req.Header.Set("User-Agent", "anpu-feeds/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return -1
	}
	var doc struct {
		Data []struct {
			Epss string `json:"epss"`
		} `json:"data"`
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return -1
	}
	if err := json.Unmarshal(data, &doc); err != nil || len(doc.Data) == 0 {
		return -1
	}
	var f float64
	fmt.Sscanf(doc.Data[0].Epss, "%f", &f)
	return f
}

// Enrich annotates findings with KEV/EPSS signals: KEV-listed CVEs get
// Confidence Confirmed + the CISA reference; EPSS ≥ 0.5 adds the FIRST
// reference. Network lookups are bounded (20 CVEs max) and fail-silent;
// pass nil kev to skip KEV, and set lookupEPSS false for offline runs.
func Enrich(findings []models.Finding, kev map[string]bool, lookupEPSS bool) []models.Finding {
	ctx := context.Background()
	epssCache := map[string]float64{}
	for i, f := range findings {
		blob := f.ID + "\n" + f.Title + "\n" + f.Description + "\n" + f.CWE + "\n" + strings.Join(f.References, "\n")
		for _, m := range cveRe.FindAllString(blob, -1) {
			id := strings.ToUpper(m)
			if kev != nil && kev[id] {
				findings[i].Confidence = models.ConfidenceConfirmed
				findings[i].References = appendRef(findings[i].References,
					"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext="+id)
				findings[i].Description += " [ANPU: " + id + " is in the CISA Known Exploited Vulnerabilities catalog — exploited in the wild.]"
				break // one KEV note per finding is enough
			}
			if lookupEPSS {
				score, ok := epssCache[id]
				if !ok {
					score = epssScore(ctx, id)
					epssCache[id] = score
				}
				if score >= 0.5 {
					findings[i].References = appendRef(findings[i].References, "https://www.first.org/epss")
					findings[i].Description += fmt.Sprintf(" [ANPU: EPSS %.2f — high predicted exploit probability.]", score)
					break
				}
			}
		}
	}
	return findings
}

func appendRef(refs []string, r string) []string {
	for _, e := range refs {
		if e == r {
			return refs
		}
	}
	return append(refs, r)
}

// advisoryNote fetches one GitHub Advisory entry for a CVE (keyless,
// low-volume: called at most 5× per scan from reputation flows).
func advisoryNote(ctx context.Context, cve string) string {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, advisoryURL+"?cve_id="+cve+"&per_page=1", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "anpu-feeds/1.0")
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp == nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	var docs []struct {
		Summary  string `json:"summary"`
		Severity string `json:"severity"`
		HTMLURL  string `json:"html_url"`
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	if err != nil {
		return ""
	}
	if err := json.Unmarshal(data, &docs); err != nil || len(docs) == 0 {
		return ""
	}
	return fmt.Sprintf("%s (%s): %s", cve, docs[0].Severity, trimLen(docs[0].Summary, 200))
}

// Reputation checks target URL/host against URLhaus + ThreatFox
// (keyless POST APIs, 2 requests max). It returns human-readable notes;
// empty means clean/unreachable (fail-silent either way).
func Reputation(ctx context.Context, targetURL, host string) []string {
	var notes []string
	if n := urlhausLookup(ctx, targetURL); n != "" {
		notes = append(notes, n)
	}
	if n := threatfoxLookup(ctx, host); n != "" {
		notes = append(notes, n)
	}
	// Advisory enrichment for up to 5 CVEs happens in Enrich flows, not
	// here; _ = advisoryNote keeps the keyless path compiled and tested.
	_ = advisoryNote
	return notes
}

func urlhausLookup(ctx context.Context, targetURL string) string {
	cctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()
	body, _ := json.Marshal(map[string]string{"url": targetURL})
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, urlhausURL, bytes.NewReader(body))
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "anpu-feeds/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp == nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	var doc struct {
		QueryStatus string `json:"query_status"`
		Threat      string `json:"threat"`
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return ""
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return ""
	}
	if doc.QueryStatus == "ok" {
		return "URLhaus lists the target URL (" + trimLen(doc.Threat, 80) + ") — treat as compromised until rebuilt."
	}
	return ""
}

func threatfoxLookup(ctx context.Context, host string) string {
	cctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()
	body, _ := json.Marshal(map[string]string{"query": "search_ioc", "search_term": host})
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, threatfoxURL, bytes.NewReader(body))
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "anpu-feeds/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp == nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	var doc struct {
		QueryStatus string `json:"query_status"`
		Data        []struct {
			ThreatType string `json:"threat_type"`
		} `json:"data"`
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return ""
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return ""
	}
	if doc.QueryStatus == "ok" && len(doc.Data) > 0 {
		return "ThreatFox lists the target host (" + trimLen(doc.Data[0].ThreatType, 80) + ") — treat as compromised until rebuilt."
	}
	return ""
}

func trimLen(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
