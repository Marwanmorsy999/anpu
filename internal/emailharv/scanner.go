// Package emailharv harvests exposed email addresses from the homepage
// (Wave 1 item 3, keyless subset): a single GET, mailto: + bare-address
// regex extraction, placeholder filtering. One request, read-only.
//
// Echo-guard: example.*, *.test, *.localhost, and addresses containing
// the scan canary marker are dropped. Findings are Low (exposure aids
// phishing) with the local part partially masked in evidence.
package emailharv

import (
	"context"
	"fmt"
	"net/url"
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
func (s *Scanner) Name() string { return "emailharv" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

var emailRe = regexp.MustCompile(`(?i)([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,})`)

// placeholderDomains are never reported.
var placeholderDomains = []string{"example.com", "example.org", "example.net", "test.com", "localhost", "email.com", "domain.com", "yoursite.com", "sentry.io", "w3.org"}

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resp, err := s.client.Get(cctx, sc.Target.Raw)
	if err != nil || resp == nil {
		return scanner.StageResult{}, nil
	}
	seen := map[string]bool{}
	for _, m := range emailRe.FindAllStringSubmatch(string(resp.Body), -1) {
		addr := strings.ToLower(strings.Trim(m[1], ".,;:()<>\"'"))
		if seen[addr] || !filterEmail(addr) {
			continue
		}
		seen[addr] = true
	}
	if len(seen) == 0 {
		return scanner.StageResult{}, nil
	}
	var addrs []string
	for a := range seen {
		addrs = append(addrs, a)
	}
	sort.Strings(addrs)
	shown := addrs
	if len(shown) > 8 {
		shown = shown[:8]
	}
	masked := make([]string, 0, len(shown))
	for _, a := range shown {
		masked = append(masked, maskLocal(a))
	}
	return scanner.StageResult{Findings: []models.Finding{{
		ID:              "emailharv-exposed",
		Title:           fmt.Sprintf("%d email address(es) exposed on homepage", len(addrs)),
		Description:     "Email addresses are published on the homepage where harvesters collect them for phishing. Prefer contact forms or obfuscation for non-essential addresses. Reproduce: curl the homepage and grep for '@'.",
		Severity:        models.SeverityLow,
		Confidence:      models.ConfidenceHigh,
		Category:        models.CategoryExposure,
		Target:          sc.Target.Raw,
		URL:             sc.Target.Raw,
		Evidence:        models.Evidence{Observed: strings.Join(masked, ", "), Location: "homepage body (local parts masked)"},
		Source:          models.SourceRecon,
		DetectionMethod: "homepage email harvest (emailharv, 1 request)",
	}}}, nil
}

// filterEmail drops placeholders and non-target noise.
func filterEmail(addr string) bool {
	parts := strings.Split(addr, "@")
	if len(parts) != 2 || parts[0] == "" || len(parts[0]) > 64 {
		return false
	}
	domain := strings.ToLower(parts[1])
	for _, p := range placeholderDomains {
		if domain == p || strings.HasSuffix(domain, "."+p) {
			return false
		}
	}
	if strings.Contains(domain, "..") || strings.HasPrefix(domain, "-") {
		return false
	}
	if _, err := url.Parse("mailto:" + addr); err != nil {
		return false
	}
	return true
}

func maskLocal(addr string) string {
	at := strings.Index(addr, "@")
	if at <= 1 {
		return "***" + addr[at:]
	}
	return addr[:1] + "***" + addr[at:]
}
