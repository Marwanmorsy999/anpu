// Package forbiddenbypass replays 403/401 endpoints with classic
// proxy-header and path-normalization variants (Wave 1 item 23,
// nomore403 technique family, read-only): X-Forwarded-For,
// X-Original-URL, X-Rewrite-URL, X-Custom-IP-Authorization, trailing
// slash toggle, and /%2e/ prefix. Up to 3 endpoints × (baseline +
// control + 6 variants) = 24 requests max. A 2xx variant dissimilar
// from BOTH the denial page and the site-root control is a finding.
//
// Stage-level complement to the Active engine's per-vector rule: this
// stage picks the most sensitive discovered endpoints (admin/auth
// first) and runs the full matrix with its own budget. GET-only,
// loopback IPs and path spellings only — never credentials or writes.
package forbiddenbypass

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// maxEndpoints and variants bound the budget: 3 × (2 + 6) = 24.
const (
	maxEndpoints = 3
	maxRequests  = 24
)

type variant struct {
	name    string
	url     func(base string) string
	headers map[string]string
}

func variantsFor(path string) []variant {
	toggled := path
	if strings.HasSuffix(path, "/") {
		toggled = strings.TrimSuffix(path, "/")
	} else {
		toggled = path + "/"
	}
	return []variant{
		{"X-Forwarded-For: 127.0.0.1", func(b string) string { return b }, map[string]string{"X-Forwarded-For": "127.0.0.1"}},
		{"X-Original-URL override", func(b string) string { return b }, map[string]string{"X-Original-URL": path, "X-Forwarded-For": "127.0.0.1"}},
		{"X-Rewrite-URL override", func(b string) string { return b }, map[string]string{"X-Rewrite-URL": path}},
		{"X-Custom-IP-Authorization", func(b string) string { return b }, map[string]string{"X-Custom-IP-Authorization": "127.0.0.1"}},
		{"trailing-slash toggle", func(b string) string { return toggleBase(b, toggled) }, nil},
		{"dot-segment prefix", func(b string) string { return dotPrefix(b) }, nil},
	}
}

func toggleBase(base, toggled string) string {
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}
	t, err := url.Parse(toggled)
	if err != nil {
		return ""
	}
	u.Path = t.Path
	return u.String()
}

func dotPrefix(base string) string {
	u, err := url.Parse(base)
	if err != nil || u.Path == "" {
		return ""
	}
	u.Path = "/%2e" + u.Path
	return u.String()
}

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "forbiddenbypass" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	targets := pickTargets(sc)
	made := 0
	do := func(u string, headers map[string]string) *anpuhttp.Response {
		if made >= maxRequests || u == "" {
			return nil
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		made++
		var resp *anpuhttp.Response
		var err error
		if len(headers) == 0 {
			resp, err = s.client.Get(cctx, u)
		} else {
			resp, err = s.client.DoWithHeaders(cctx, "GET", u, headers)
		}
		if err != nil || resp == nil {
			return nil
		}
		return resp
	}

	parsed, _ := url.Parse(sc.Target.Raw)
	siteRoot := sc.Target.Raw
	if parsed != nil {
		siteRoot = parsed.Scheme + "://" + parsed.Host + "/"
	}
	controlWords := map[string]struct{}{}
	if root := do(siteRoot, nil); root != nil {
		controlWords = wordSet(root.Body)
	}

	var findings []models.Finding
	for _, target := range targets {
		base := do(target, nil)
		if base == nil {
			continue
		}
		if base.StatusCode != 401 && base.StatusCode != 403 {
			continue // only denied resources are interesting
		}
		baseWords := wordSet(base.Body)
		u, err := url.Parse(target)
		if err != nil {
			continue
		}
		path := u.Path
		if path == "" {
			path = "/"
		}
		for _, v := range variantsFor(path) {
			if made >= maxRequests {
				break
			}
			vu := v.url(target)
			resp := do(vu, v.headers)
			if resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
				continue
			}
			got := wordSet(resp.Body)
			if overlap(got, baseWords) > 0.7 {
				continue
			}
			if overlap(got, controlWords) > 0.85 {
				continue // fallback page
			}
			findings = append(findings, models.Finding{
				ID:              "forbiddenbypass-success",
				Title:           fmt.Sprintf("403 bypass via %s on %s", v.name, displayPath(target)),
				Description:     fmt.Sprintf("GET %s is denied (%d) but the %s variant returns %d with clearly different content: authorization trusts proxy headers or normalizes paths inconsistently. Strip trusting headers at the edge and authorize on the canonical path. Reproduce: curl -s TARGET with the variant. Read-only replay — nothing was modified.", displayPath(target), base.StatusCode, v.name, resp.StatusCode),
				Severity:        models.SeverityMedium,
				Confidence:      models.ConfidenceMedium,
				Category:        models.CategoryVulnerability,
				CWE:             "CWE-863",
				Target:          sc.Target.Raw,
				URL:             target,
				Evidence:        models.Evidence{Observed: fmt.Sprintf("denied→%d, variant %q→%d (%d bytes, dissimilar)", base.StatusCode, v.name, resp.StatusCode, len(resp.Body)), Location: "header/path variant vs denial baseline"},
				Source:          models.SourceCustom,
				DetectionMethod: "forbidden-bypass matrix with dual baseline (forbiddenbypass, ≤24 requests)",
				Remediation:     "Ignore X-Forwarded-For-style headers for authz; normalize paths before checks.",
			})
			break
		}
		if len(findings) >= 3 {
			break
		}
	}
	return scanner.StageResult{Findings: findings}, nil
}

func pickTargets(sc *scanner.ScanContext) []string {
	var admin, other []string
	for _, ep := range sc.Endpoints {
		u, err := url.Parse(ep.URL)
		if err != nil || !strings.EqualFold(u.Hostname(), sc.Target.Host) {
			continue
		}
		switch ep.Category {
		case models.EndpointAdminLike, models.EndpointAuth:
			admin = append(admin, ep.URL)
		case models.EndpointPage, models.EndpointUnknown:
			other = append(other, ep.URL)
		}
	}
	sort.Strings(admin)
	sort.Strings(other)
	out := append(admin, other...)
	if len(out) > maxEndpoints {
		out = out[:maxEndpoints]
	}
	if len(out) == 0 {
		out = []string{sc.Target.Raw}
	}
	return out
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

func overlap(a, b map[string]struct{}) float64 {
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

func displayPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	p := u.Path
	if p == "" {
		p = "/"
	}
	return p
}
