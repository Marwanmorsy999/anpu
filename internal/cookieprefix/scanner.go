// Package cookieprefix audits __Host-/__Secure- cookie prefix rules
// (Wave 1 item 27): up to 3 same-host page GETs, parsing every
// Set-Cookie. __Host- requires Secure + Path=/ + no Domain;
// __Secure- requires Secure. Violations are Low findings naming the
// exact broken attribute. Passive analysis — complements the Cookies
// stage's Secure/HttpOnly/SameSite audit.
package cookieprefix

import (
	"context"
	"net/url"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// maxTargets bounds GETs per scan.
const maxTargets = 3

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "cookieprefix" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

// checkCookie returns violation descriptions (pure, tested).
func checkCookie(setCookie string) []string {
	parts := strings.Split(setCookie, ";")
	if len(parts) == 0 {
		return nil
	}
	name := strings.TrimSpace(parts[0])
	if i := strings.Index(name, "="); i >= 0 {
		name = name[:i]
	}
	name = strings.TrimSpace(name)
	attrs := map[string]string{}
	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if i := strings.Index(p, "="); i >= 0 {
			attrs[strings.ToLower(strings.TrimSpace(p[:i]))] = strings.TrimSpace(p[i+1:])
		} else {
			attrs[strings.ToLower(p)] = ""
		}
	}
	var out []string
	switch {
	case strings.HasPrefix(name, "__Host-"):
		if _, ok := attrs["secure"]; !ok {
			out = append(out, "missing Secure")
		}
		if v, ok := attrs["path"]; !ok || v != "/" {
			out = append(out, "Path must be /")
		}
		if _, ok := attrs["domain"]; ok {
			out = append(out, "must not set Domain")
		}
	case strings.HasPrefix(name, "__Secure-"):
		if _, ok := attrs["secure"]; !ok {
			out = append(out, "missing Secure")
		}
	}
	if len(out) == 0 {
		return nil
	}
	return []string{name + ": " + strings.Join(out, ", ")}
}

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	targets := []string{sc.Target.Raw}
	for _, ep := range sc.Endpoints {
		if len(targets) >= maxTargets {
			break
		}
		u, err := url.Parse(ep.URL)
		if err != nil || !strings.EqualFold(u.Hostname(), sc.Target.Host) || ep.URL == sc.Target.Raw {
			continue
		}
		targets = append(targets, ep.URL)
	}

	seen := map[string]bool{}
	var findings []models.Finding
	for _, target := range targets {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		resp, err := s.client.Get(cctx, target)
		cancel()
		if err != nil || resp == nil {
			continue
		}
		for _, setCookie := range resp.Header.Values("Set-Cookie") {
			for _, v := range checkCookie(setCookie) {
				if seen[v] {
					continue
				}
				seen[v] = true
				findings = append(findings, models.Finding{
					ID:              "cookieprefix-violation",
					Title:           "Cookie prefix rule violated: " + v,
					Description:     "Browsers enforce __Host-/__Secure- semantics: a cookie breaking the rule is rejected by modern browsers (session loss) or, worse, accepted where it should be pinned. Fix the attributes server-side. Reproduce: curl -sI TARGET | grep -i set-cookie.",
					Severity:        models.SeverityLow,
					Confidence:      models.ConfidenceHigh,
					Category:        models.CategoryConfiguration,
					CWE:             "CWE-565",
					Target:          sc.Target.Raw,
					URL:             target,
					Evidence:        models.Evidence{Observed: v, Location: "Set-Cookie"},
					Source:          models.SourceCustom,
					DetectionMethod: "cookie-prefix rule audit (cookieprefix, ≤3 requests)",
					Remediation:     "__Host-: Secure + Path=/ + no Domain. __Secure-: Secure.",
				})
				if len(findings) >= 4 {
					return scanner.StageResult{Findings: findings}, nil
				}
			}
		}
	}
	return scanner.StageResult{Findings: findings}, nil
}
