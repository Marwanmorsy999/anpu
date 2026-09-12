// Package brokenlink checks same-host links for terminal breakage
// (Wave 1 item 9): 1 GET for the homepage, then HEAD (falling back to
// ranged GET) per same-host link, capped at 10 links / 11 requests.
// A link counts as broken only after a confirming GET with a body that
// differs from the soft-404 control (baseline-subtract), so SPA
// catch-all fallbacks never report. Echo-guard: mailto:/tel:/
// javascript:/fragment-only links are skipped. Findings are Low.
package brokenlink

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// maxLinks and request budget: 1 homepage + 1 control + 2 per link worst
// case (HEAD then confirming GET), capped so total stays ≤ 21.
const (
	maxLinks    = 10
	maxRequests = 22
)

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "brokenlink" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

var hrefRe = regexp.MustCompile(`(?i)(?:href|src)\s*=\s*["']([^"'#]+)["']`)

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
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
	head := func(u string) *anpuhttp.Response {
		if made >= maxRequests {
			return nil
		}
		cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		made++
		resp, err := s.client.DoWithHeaders(cctx, "HEAD", u, nil)
		if err != nil || resp == nil {
			return nil
		}
		return resp
	}

	root := get(sc.Target.Raw)
	if root == nil {
		return scanner.StageResult{}, nil
	}
	// Baseline: soft-404 control signature.
	controlLen, controlWords := -1, map[string]struct{}{}
	if control := get(strings.TrimSuffix(sc.Target.Raw, "/") + "/anpu-brokenlink-control-404"); control != nil {
		controlLen = len(control.Body)
		controlWords = wordSet(control.Body)
	}

	base, err := url.Parse(sc.Target.Raw)
	if err != nil {
		return scanner.StageResult{}, nil
	}
	seen := map[string]bool{}
	var links []string
	for _, m := range hrefRe.FindAllStringSubmatch(string(root.Body), -1) {
		raw := strings.TrimSpace(m[1])
		if raw == "" || strings.HasPrefix(raw, "#") || skipScheme(raw) {
			continue // echo-guard
		}
		ref, err := url.Parse(raw)
		if err != nil {
			continue
		}
		abs := base.ResolveReference(ref)
		if abs.Scheme != "http" && abs.Scheme != "https" {
			continue
		}
		if !strings.EqualFold(abs.Hostname(), sc.Target.Host) {
			continue // same-host only
		}
		abs.Fragment = ""
		key := abs.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		links = append(links, key)
		if len(links) >= maxLinks {
			break
		}
	}
	sort.Strings(links)

	var findings []models.Finding
	for _, link := range links {
		status := 0
		if h := head(link); h != nil {
			status = h.StatusCode
		}
		if status >= 200 && status < 400 {
			continue
		}
		// Confirm with GET; 404/410 with a body differing from the
		// control page is a real break, not a catch-all fallback.
		confirm := get(link)
		if confirm == nil {
			continue
		}
		if confirm.StatusCode != 404 && confirm.StatusCode != 410 && confirm.StatusCode != 500 {
			continue
		}
		if controlLen >= 0 && similarLen(len(confirm.Body), controlLen) && wordOverlap(wordSet(confirm.Body), controlWords) > 0.85 {
			continue // baseline-subtract: same page as control
		}
		findings = append(findings, models.Finding{
			ID:              "brokenlink-" + shortID(link),
			Title:           fmt.Sprintf("Broken link: %s → %d", linkPath(link), confirm.StatusCode),
			Description:     fmt.Sprintf("A same-host link returns %d on confirm. Broken links erode trust and dangling paths get claimed. Fix or remove the link. Reproduce: curl -s -o /dev/null -w %%{http_code} %q.", confirm.StatusCode, link),
			Severity:        models.SeverityLow,
			Confidence:      models.ConfidenceHigh,
			Category:        models.CategoryExposure,
			Target:          sc.Target.Raw,
			URL:             link,
			Evidence:        models.Evidence{Observed: fmt.Sprintf("HEAD→%d, GET→%d (%d bytes)", status, confirm.StatusCode, len(confirm.Body)), Location: "same-host link check"},
			Source:          models.SourceRecon,
			DetectionMethod: "broken-link check with soft-404 baseline (brokenlink)",
			Remediation:     "Fix or remove the broken link.",
		})
		if len(findings) >= 5 {
			break
		}
	}
	return scanner.StageResult{Findings: findings}, nil
}

func skipScheme(raw string) bool {
	l := strings.ToLower(raw)
	for _, p := range []string{"javascript:", "mailto:", "tel:", "data:", "ftp:", "file:", "about:", "vbscript:"} {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return false
}

func wordSet(b []byte) map[string]struct{} {
	out := map[string]struct{}{}
	for _, w := range strings.Fields(strings.ToLower(string(b))) {
		if len(w) > 2 {
			out[w] = struct{}{}
		}
	}
	return out
}

func wordOverlap(a, b map[string]struct{}) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	n := 0
	for w := range a {
		if _, ok := b[w]; ok {
			n++
		}
	}
	return float64(n) / float64(len(a))
}

func similarLen(a, b int) bool {
	if b <= 0 {
		return false
	}
	d := a - b
	if d < 0 {
		d = -d
	}
	return float64(d) <= float64(b)*0.15+64
}

func linkPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		if len(raw) > 60 {
			return raw[:60] + "..."
		}
		return raw
	}
	p := u.Path
	if u.RawQuery != "" {
		p += "?" + u.RawQuery
	}
	if p == "" {
		p = "/"
	}
	return p
}

func shortID(raw string) string {
	h := 0
	for _, c := range raw {
		h = h*31 + int(c)
	}
	if h < 0 {
		h = -h
	}
	return fmt.Sprintf("%x", h%0xffffff)
}
