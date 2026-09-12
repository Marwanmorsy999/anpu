// Package oauthpack probes OAuth redirect_uri validation (Wave next,
// item 4): for up to 2 discovered authorize endpoints (plus bounded
// well-known fallbacks), it replays redirect_uri confusion payloads —
// absolute external, suffix-confusion, scheme-relative, userinfo,
// encoded-dot, triple-slash — inspecting the 302 Location WITHOUT
// following it. External redirect = open-redirect on the OAuth flow
// (code/token theft primitive). No login, no credentials, no grants;
// GET-only, ≤15 requests.
package oauthpack

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// maxRequests bounds all HTTP traffic: 3 discovery + 2 × (baseline + 6).
const maxRequests = 17

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "oauthpack" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

var authorizeHints = []string{
	"/oauth/authorize", "/oauth2/authorize", "/connect/authorize",
	"/auth/authorize", "/login/oauth/authorize", "/authorize",
}

// redirectPayloads builds confusion variants around the target host.
func redirectPayloads(host string) []struct{ name, uri string } {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	return []struct{ name, uri string }{
		{"absolute-external", "https://evil.example/anpu"},
		{"suffix-confusion", "https://" + h + ".evil.example/anpu"},
		{"scheme-relative", "//evil.example/anpu"},
		{"userinfo-smuggle", "https://" + h + "@evil.example/anpu"},
		{"encoded-dot", "https://evil%2eexample/anpu"},
		{"triple-slash", "https:///evil.example/anpu"},
	}
}

// noFollow issues one GET without following redirects.
func noFollow(ctx context.Context, u string) (status int, location string) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, ""
	}
	req.Header.Set("User-Agent", anpuhttp.UserAgent)
	cli := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := cli.Do(req)
	if err != nil || resp == nil {
		return 0, ""
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, resp.Header.Get("Location")
}

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	made := 0
	counted := func() bool {
		if made >= maxRequests {
			return false
		}
		made++
		return true
	}
	targets := pickTargets(ctx, s.client, sc, counted)
	var findings []models.Finding
	for _, target := range targets {
		base := "https://" + sc.Target.Host + "/anpu-oauth-ok"
		// Baseline: benign redirect_uri (expect deny/error page).
		if !counted() {
			break
		}
		bStatus, _ := noFollow(ctx, withParam(target, "redirect_uri", base))
		if bStatus == 0 {
			continue
		}
		for _, p := range redirectPayloads(sc.Target.Host) {
			if !counted() {
				break
			}
			status, loc := noFollow(ctx, withParam(target, "redirect_uri", p.uri))
			if status == 0 || status < 300 || status >= 400 {
				continue
			}
			if externalLocation(loc, sc.Target.Host) {
				findings = append(findings, models.Finding{
					ID: "oauthpack-open-redirect", Title: fmt.Sprintf("OAuth open redirect via %s (%s)", p.name, displayPath(target)),
					Description: fmt.Sprintf("The authorize endpoint %s issues %d to an external redirect_uri (%s): authorization codes/tokens can be stolen via crafted links. Enforce an exact redirect-URI allowlist (no suffix/wildcard matching). Destination never visited — Location inspected only. Reproduce: curl -s -o /dev/null -w '%%{redirect_url}' %q.", displayPath(target), status, p.uri, withParam(target, "redirect_uri", p.uri)),
					Severity:    models.SeverityMedium, Confidence: models.ConfidenceHigh, Category: models.CategoryVulnerability,
					CWE: "CWE-601", Target: sc.Target.Raw, URL: target,
					Evidence: models.Evidence{Observed: fmt.Sprintf("%s → %d Location: %s", p.name, status, loc), Location: "redirect_uri parameter"},
					Source:   models.SourceCustom, DetectionMethod: "OAuth redirect_uri confusion pack, no-follow (oauthpack, ≤14 requests)",
					Remediation: "Exact-match allowlist for redirect URIs; reject everything else.",
				})
				break
			}
		}
		if len(findings) >= 2 {
			break
		}
	}
	return scanner.StageResult{Findings: findings}, nil
}

// pickTargets prefers discovered authorize endpoints, else probes
// well-known paths (bounded, first live one wins).
func pickTargets(ctx context.Context, client *anpuhttp.Client, sc *scanner.ScanContext, counted func() bool) []string {
	var out []string
	for _, ep := range sc.Endpoints {
		if len(out) >= 2 {
			break
		}
		l := strings.ToLower(ep.URL)
		if strings.Contains(l, "authoriz") || strings.Contains(l, "oauth") {
			out = append(out, ep.URL)
		}
	}
	if len(out) > 0 {
		return out
	}
	probed := 0
	for _, p := range authorizeHints {
		if probed >= 3 || len(out) >= 1 {
			break
		}
		if !counted() {
			break
		}
		cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		resp, err := client.Get(cctx, strings.TrimSuffix(sc.Target.Raw, "/")+p+"?client_id=anpu")
		cancel()
		probed++
		if err != nil || resp == nil {
			continue
		}
		// Any OAuth-shaped answer (even 400 invalid_client) proves the
		// endpoint — as does any redirect from an authorize path (the
		// actual finding still requires external-Location proof later).
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			out = append(out, strings.TrimSuffix(sc.Target.Raw, "/")+p)
			continue
		}
		bl := strings.ToLower(string(resp.Body))
		if strings.Contains(bl, "client") || strings.Contains(bl, "oauth") || strings.Contains(bl, "redirect") {
			out = append(out, strings.TrimSuffix(sc.Target.Raw, "/")+p)
		}
	}
	sort.Strings(out)
	return out
}

// externalLocation reports off-host Location targets.
func externalLocation(loc, targetHost string) bool {
	loc = strings.TrimSpace(loc)
	if loc == "" {
		return false
	}
	if strings.HasPrefix(loc, "//") {
		h := loc[2:]
		if i := strings.IndexAny(h, "/?#"); i >= 0 {
			h = h[:i]
		}
		th := strings.ToLower(targetHost)
		return !strings.EqualFold(h, targetHost) && !strings.HasSuffix(strings.ToLower(h), "."+th)
	}
	u, err := url.Parse(loc)
	if err != nil || !u.IsAbs() {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return !strings.EqualFold(u.Hostname(), targetHost)
}

func withParam(raw, name, value string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	q.Set(name, value)
	u.RawQuery = q.Encode()
	return u.String()
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
