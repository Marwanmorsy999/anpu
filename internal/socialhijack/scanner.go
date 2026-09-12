// Package socialhijack flags social-link takeover exposure (Wave 1 item 7):
// one GET of the homepage, extraction of links to known social/developer
// platforms, and bounded HEAD verification (max 5 externals, 5s each).
// A profile URL that 404s (or resolves to a platform's "not found" page)
// is claimable by anyone — Low severity, needs-review.
//
// Safety: externals are HEAD-only, never authenticated, capped at 5 per
// scan. Verification failures degrade to warnings, never findings
// (offline CI must stay green and false-positive-free).
package socialhijack

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// maxVerify caps external HEAD verifications per scan.
const maxVerify = 5

// platforms maps known host suffixes to platform names.
var platforms = map[string]string{
	"github.com":        "GitHub",
	"twitter.com":       "Twitter/X",
	"x.com":             "Twitter/X",
	"linkedin.com":      "LinkedIn",
	"youtube.com":       "YouTube",
	"youtu.be":          "YouTube",
	"facebook.com":      "Facebook",
	"instagram.com":     "Instagram",
	"t.me":              "Telegram",
	"discord.gg":        "Discord",
	"discord.com":       "Discord",
	"medium.com":        "Medium",
	"npmjs.com":         "npm",
	"pypi.org":          "PyPI",
	"rubygems.org":      "RubyGems",
	"hub.docker.com":    "Docker Hub",
	"stackoverflow.com": "Stack Overflow",
	"twitch.tv":         "Twitch",
	"tiktok.com":        "TikTok",
	"gitlab.com":        "GitLab",
	"bitbucket.org":     "Bitbucket",
	"producthunt.com":   "Product Hunt",
	"angel.co":          "AngelList",
	"crunchbase.com":    "Crunchbase",
}

// additionalPlatforms is a test hook for hermetic verification tests.
var additionalPlatforms = map[string]string{}

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "socialhijack" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

var hrefRe = regexp.MustCompile(`(?i)href\s*=\s*["'](https?://[^"'#\s]+)["']`)

// platformOf returns the platform name for a URL host, or "".
func platformOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	h := strings.ToLower(u.Hostname())
	if n, ok := additionalPlatforms[h]; ok {
		return n
	}
	for suffix, name := range platforms {
		if h == suffix || strings.HasSuffix(h, "."+suffix) {
			// Echo-guard: bare platform homepages are not profile links.
			if strings.Trim(u.Path, "/") == "" {
				return ""
			}
			return name
		}
	}
	return ""
}

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resp, err := s.client.Get(cctx, sc.Target.Raw)
	if err != nil || resp == nil {
		return scanner.StageResult{}, nil
	}
	seen := map[string]string{} // url -> platform
	var order []string
	for _, m := range hrefRe.FindAllStringSubmatch(string(resp.Body), -1) {
		raw := strings.TrimSpace(m[1])
		plat := platformOf(raw)
		if plat == "" || seen[raw] != "" {
			continue
		}
		seen[raw] = plat
		order = append(order, raw)
	}
	if len(order) == 0 {
		return scanner.StageResult{}, nil
	}
	sort.Strings(order)
	var findings []models.Finding
	var warnings []string
	verified := 0
	for _, raw := range order {
		if verified >= maxVerify {
			break
		}
		verified++
		vctx, vcancel := context.WithTimeout(ctx, 5*time.Second)
		status, verr := s.headStatus(vctx, raw)
		vcancel()
		if verr != nil {
			warnings = append(warnings, fmt.Sprintf("socialhijack: could not verify %s: %v", raw, shortErr(verr)))
			continue
		}
		// Baseline-subtract: only a terminal 404 on the profile URL
		// itself counts — redirects to login/home are not findings.
		if status == http.StatusNotFound {
			findings = append(findings, models.Finding{
				ID:              "socialhijack-dangling-" + strings.ToLower(strings.ReplaceAll(seen[raw], " ", "")),
				Title:           fmt.Sprintf("Dangling %s profile link (claimable)", seen[raw]),
				Description:     fmt.Sprintf("The homepage links to %s which returns 404 — the handle may be unclaimed and registerable by anyone, enabling brand impersonation. Verify manually, then claim or remove the link. Reproduce: curl -sI %q.", seen[raw], raw),
				Severity:        models.SeverityLow,
				Confidence:      models.ConfidenceMedium,
				Category:        models.CategoryExposure,
				Target:          sc.Target.Raw,
				URL:             raw,
				Evidence:        models.Evidence{Observed: "HEAD " + raw + " → 404", Location: "homepage social link"},
				Source:          models.SourceRecon,
				DetectionMethod: "social-link HEAD verification (socialhijack)",
				Remediation:     "Claim the handle on the platform or remove the link.",
			})
		}
	}
	return scanner.StageResult{Findings: findings, Warnings: warnings}, nil
}

func (s *Scanner) headStatus(ctx context.Context, raw string) (int, error) {
	resp, err := s.client.DoWithHeaders(ctx, "HEAD", raw, nil)
	if err != nil || resp == nil {
		return 0, err
	}
	return resp.StatusCode, nil
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 140 {
		s = s[:140] + "..."
	}
	return s
}
