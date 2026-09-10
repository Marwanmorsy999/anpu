// Package redirectpack probes open redirects with a 10-payload pack
// (Wave 1 item 38): scheme-relative, absolute, backslash, encoded, and
// control-character variants against redirect-ish parameters (next,
// redirect, url, return, continue, dest, target, r, u, callback).
// A 3xx Location to an external host is a Medium finding; javascript:/
// data: executions are expected-blocked (a 3xx/200 carrying them is a
// High finding). GET-only, ≤2 URLs, 22 requests max. Never follows the
// redirect — Location is inspected, not visited.
package redirectpack

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// maxRequests bounds all HTTP traffic: 2 URLs × (baseline + 10).
const maxRequests = 22

var redirectParams = []string{"next", "redirect", "url", "return", "continue", "dest", "target", "r", "u", "callback"}

var redirectPayloads = []struct {
	name    string
	payload string
	danger  bool // script-scheme: must never execute
}{
	{"scheme-relative", "//evil.example/anpu", false},
	{"absolute-https", "https://evil.example/anpu", false},
	{"backslash", `\/\evil.example/anpu`, false},
	{"encoded-slashes", "%2f%2fevil.example/anpu", false},
	{"tab-prefix", "%09https://evil.example/anpu", false},
	{"whitelisted-host-prefix", "https://target.example.evil.example/anpu", false},
	{"at-sign", "https://target.example@evil.example/anpu", false},
	{"javascript-scheme", "javascript:alert(1)", true},
	{"data-scheme", "data:text/html,anpu", true},
	{"crlf-guard", "%0d%0aX-Anpu:1", true},
}

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "redirectpack" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

// externalLocation reports whether Location points off-site (pure,
// tested). Same-host and same-registrable-domain targets (www., app.,
// regional subdomains) are NOT external: a redirect that stays inside
// the site's own domain — including framework endpoints like
// /_next/image that echo a url parameter same-origin — is not an open
// redirect (CWE-601 needs an attacker-controlled external destination).
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
		return !sameSite(h, targetHost)
	}
	u, err := url.Parse(loc)
	if err != nil || !u.IsAbs() {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false // non-http schemes are the danger-class, handled separately
	}
	return !sameSite(u.Hostname(), targetHost)
}

// sameSite reports whether host is the target host or a subdomain of
// it (www., app., regional variants). The leading-dot suffix rule
// keeps evil-target.example (no dot boundary) correctly external.
func sameSite(host, targetHost string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	targetHost = strings.ToLower(strings.TrimSpace(targetHost))
	// Strip a port if present.
	if i := strings.LastIndex(host, ":"); i >= 0 && !strings.Contains(host[i:], "]") {
		host = host[:i]
	}
	if host == "" || targetHost == "" {
		return false
	}
	return host == targetHost || strings.HasSuffix(host, "."+targetHost)
}

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	targets := pickTargets(sc)
	made := 0
	// noFollow issues one GET without following redirects, so the
	// Location header is inspected exactly and the destination is never
	// visited. Only in-scope same-host URLs are ever requested.
	noFollow := func(u string) (status int, location string) {
		if made >= maxRequests {
			return 0, ""
		}
		made++
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

	var findings []models.Finding
	for _, t := range targets {
		param := redirectParam(t.URL)
		if param == "" {
			continue
		}
		for _, p := range redirectPayloads {
			if made >= maxRequests {
				break
			}
			status, loc := noFollow(withParam(t.URL, param, p.payload))
			if status == 0 {
				continue
			}
			if p.danger {
				// Script schemes must never survive into Location.
				ll := strings.ToLower(loc)
				if strings.Contains(ll, "javascript:") || strings.Contains(ll, "data:text") {
					findings = append(findings, mkFinding(sc, t.URL, "redirectpack-scheme", "Dangerous redirect scheme survived ("+p.name+")",
						"A redirect parameter emits a javascript:/data: URL: script execution on redirect is XSS. Allowlist http(s) hosts and reject other schemes.",
						models.SeverityHigh, p, status, loc))
					break
				}
				continue
			}
			if status >= 300 && status < 400 && externalLocation(loc, sc.Target.Host) {
				findings = append(findings, mkFinding(sc, t.URL, "redirectpack-open", "Open redirect via "+p.name,
					"The redirect parameter issues a "+fmt.Sprint(status)+" to an external host ("+p.payload+"): phishing and OAuth-token theft primitive. Validate redirect targets against an allowlist.",
					models.SeverityMedium, p, status, loc))
				break
			}
		}
		if len(findings) >= 2 {
			break
		}
	}
	return scanner.StageResult{Findings: findings}, nil
}

type target struct{ URL string }

func pickTargets(sc *scanner.ScanContext) []target {
	var out []target
	for _, ep := range sc.Endpoints {
		if len(out) >= 2 {
			break
		}
		u, err := url.Parse(ep.URL)
		if err != nil || !strings.EqualFold(u.Hostname(), sc.Target.Host) || u.RawQuery == "" {
			continue
		}
		out = append(out, target{URL: ep.URL})
	}
	if len(out) == 0 {
		out = []target{{URL: sc.Target.Raw + "?next=anputest"}}
	}
	return out
}

// redirectParam returns the first redirect-ish param, else the first param.
func redirectParam(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	q := u.Query()
	for _, p := range redirectParams {
		for k := range q {
			if strings.EqualFold(k, p) {
				return k
			}
		}
	}
	for k := range q {
		return k
	}
	return ""
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

func mkFinding(sc *scanner.ScanContext, targetURL, id, title, desc string, sev models.Severity, p struct {
	name    string
	payload string
	danger  bool
}, status int, loc string) models.Finding {
	return models.Finding{
		ID: id, Title: title,
		Description: desc + " The redirect destination was never visited — only status/Location were inspected (no redirect followed). Reproduce: curl -s -o /dev/null -w '%{redirect_url}' TARGET with the payload.",
		Severity:    sev, Confidence: models.ConfidenceHigh, Category: models.CategoryVulnerability, CWE: "CWE-601",
		Target: sc.Target.Raw, URL: targetURL,
		Evidence: models.Evidence{Observed: fmt.Sprintf("payload %q → %d Location: %s", p.payload, status, loc), Location: "redirect parameter"},
		Source:   models.SourceCustom, DetectionMethod: "open-redirect 10-payload pack (redirectpack, ≤22 requests)",
		Remediation: "Allowlist redirect hosts; reject non-http(s) schemes.",
	}
}
