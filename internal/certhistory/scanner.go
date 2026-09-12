// Package certhistory mines certificate-transparency history (Wave 1
// item 42): one keyless query to crt.sh (https://crt.sh/?q=%25.host&
// output=json, no API key) returns every logged precertificate.
// New hostnames become Subdomains for Takeover review; a precert
// younger than 30 days is a Low "fresh certificate" note (young certs
// correlate with fresh phishing infra — review, don't block). Bounded:
// 1 archive request, 20 subdomains max. Target itself is never touched
// for this signal.
package certhistory

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// crtBase is overridable in tests.
var crtBase = "https://crt.sh"

// maxSubs bounds harvested subdomains.
const maxSubs = 20

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "certhistory" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

type crtEntry struct {
	NameValue string `json:"name_value"`
	NotBefore string `json:"not_before"`
}

// parseEntries extracts hostnames + youngest age (pure, tested).
func parseEntries(body []byte, host string, now time.Time) (subs []string, youngest time.Duration, ok bool) {
	var entries []crtEntry
	if err := json.Unmarshal(body, &entries); err != nil || len(entries) == 0 {
		return nil, 0, false
	}
	seen := map[string]bool{}
	youngest = time.Duration(1<<62 - 1)
	for _, e := range entries {
		for _, line := range strings.Split(e.NameValue, "\n") {
			n := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(line, ".")))
			n = strings.TrimPrefix(n, "*.")
			if n == "" || seen[n] || strings.Contains(n, " ") || !strings.Contains(n, ".") {
				continue
			}
			seen[n] = true
			if !strings.EqualFold(n, host) && (strings.EqualFold(n, host) || strings.HasSuffix(n, "."+strings.ToLower(host))) {
				if len(subs) < maxSubs {
					subs = append(subs, n)
				}
			}
		}
		if e.NotBefore != "" {
			if t, err := time.Parse("2006-01-02T15:04:05", e.NotBefore); err == nil {
				if d := now.Sub(t); d >= 0 && d < youngest {
					youngest = d
				}
			}
		}
	}
	sort.Strings(subs)
	return subs, youngest, true
}

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	host := strings.ToLower(strings.TrimSuffix(sc.Target.Host, "."))
	if host == "" || net.ParseIP(host) != nil || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return scanner.StageResult{}, nil
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	resp, err := s.client.Get(cctx, crtBase+"/?q=%25."+host+"&output=json")
	if err != nil || resp == nil || resp.StatusCode != 200 || len(resp.Body) == 0 {
		return scanner.StageResult{Warnings: []string{"certhistory: crt.sh unavailable — skipping (archive-only signal)"}}, nil
	}
	subs, youngest, ok := parseEntries(resp.Body, host, time.Now())
	if !ok {
		return scanner.StageResult{}, nil
	}
	var findings []models.Finding
	if youngest < 30*24*time.Hour {
		findings = append(findings, models.Finding{
			ID: "certhistory-fresh", Title: fmt.Sprintf("Certificate history is young (newest log entry %s ago)", youngest.Round(time.Hour)),
			Description: "The youngest crt.sh precertificate for this domain is under 30 days old. Fresh issuance is normal for new services but also typical of phishing stand-ups — correlate with content review. Reproduce: curl -s 'https://crt.sh/?q=%25.HOST&output=json'. Archive signal only; target untouched.",
			Severity:    models.SeverityLow, Confidence: models.ConfidenceMedium, Category: models.CategoryExposure,
			Target:   sc.Target.Raw,
			Evidence: models.Evidence{Observed: "youngest precert age " + youngest.Round(time.Hour).String(), Location: "crt.sh CT history"},
			Source:   models.SourceRecon, DetectionMethod: "CT history age (certhistory, 1 archive request)",
		})
	}
	return scanner.StageResult{Findings: findings, Subdomains: subs}, nil
}
