// Package jwtconfirm tests alg:none acceptance differentially (Wave
// next, item 8): a crafted unsigned token (alg none, inert claims) is
// presented to up to 2 auth/API endpoints and compared against both a
// no-token baseline and a garbage-token control. Acceptance looks like
// the none-token diverging from BOTH rejections (2xx, or a distinct
// body while the two rejections agree). No valid token is forged or
// replayed — the probe carries no privileges and asserts nothing.
// Adversarial-gated (like h2smuggle): without Modules.Adversarial it
// warn-skips. GET-only Authorization headers, ≤7 requests.
package jwtconfirm

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// maxRequests bounds all HTTP traffic: 2 endpoints × (absent + garbage + none) + homepage.
const maxRequests = 7

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "jwtconfirm" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

// noneToken crafts an unsigned token with inert claims (pure).
func noneToken() string {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	return enc(`{"alg":"none","typ":"JWT"}`) + "." + enc(`{"sub":"anpu-probe","iat":0}`) + "."
}

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	if !sc.Config.Modules.Adversarial {
		return scanner.StageResult{Warnings: []string{"jwtconfirm skipped: requires --adversarial --confirm-authorized (authorized targets only)"}}, nil
	}
	targets := pickTargets(sc)
	if len(targets) == 0 {
		// Fall back to probing the homepage itself (some apps gate /).
		targets = []string{sc.Target.Raw}
	}
	made := 0
	get := func(u, token string) *anpuhttp.Response {
		if made >= maxRequests {
			return nil
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		made++
		var resp *anpuhttp.Response
		var err error
		if token == "" {
			resp, err = s.client.Get(cctx, u)
		} else {
			resp, err = s.client.DoWithHeaders(cctx, "GET", u, map[string]string{"Authorization": "Bearer " + token})
		}
		if err != nil || resp == nil {
			return nil
		}
		return resp
	}

	var findings []models.Finding
	probe := noneToken()
	for _, target := range targets {
		absent := get(target, "")
		garbage := get(target, "anpuinvalidtoken000")
		if absent == nil || garbage == nil {
			continue
		}
		// Rejections must agree with each other first (stable deny).
		if !sameResponse(absent, garbage) {
			continue
		}
		forged := get(target, probe)
		if forged == nil {
			continue
		}
		if sameResponse(forged, absent) || sameResponse(forged, garbage) {
			continue // rejected like everything else
		}
		if forged.StatusCode >= 200 && forged.StatusCode < 300 {
			findings = append(findings, models.Finding{
				ID: "jwtconfirm-none-accepted", Title: fmt.Sprintf("Unsigned JWT accepted at %s (alg:none)", displayPath(target)),
				Description: fmt.Sprintf("An unsigned alg:none token returns %d while absent and garbage tokens both return %d with matching bodies: the verifier likely trusts the header algorithm. Pin expected algorithms (e.g. RS256) and reject none. Confirm manually with your own test token. No privileges asserted — inert claims only. Reproduce: curl -H 'Authorization: Bearer <none-token>' TARGET.", forged.StatusCode, absent.StatusCode),
				Severity:    models.SeverityHigh, Confidence: models.ConfidenceMedium, Category: models.CategoryVulnerability,
				CWE: "CWE-347", Target: sc.Target.Raw, URL: target,
				Evidence: models.Evidence{Observed: fmt.Sprintf("absent→%d, garbage→%d (agree), none→%d (differs)", absent.StatusCode, garbage.StatusCode, forged.StatusCode), Location: "Authorization header differential"},
				Source:   models.SourceCustom, DetectionMethod: "alg:none acceptance differential (jwtconfirm, adversarial, ≤7 requests)",
				Remediation: "Allowlist algorithms server-side; never accept none.",
			})
			break
		}
		if len(findings) >= 1 {
			break
		}
	}
	return scanner.StageResult{Findings: findings}, nil
}

// sameResponse compares status + coarse body buckets.
func sameResponse(a, b *anpuhttp.Response) bool {
	if a.StatusCode != b.StatusCode {
		return false
	}
	la, lb := len(a.Body)/256, len(b.Body)/256
	if la != lb {
		return false
	}
	return overlap(wordSet(a.Body), wordSet(b.Body)) > 0.7
}

// pickTargets prefers auth/API endpoints, cap 2.
func pickTargets(sc *scanner.ScanContext) []string {
	var auth, other []string
	for _, ep := range sc.Endpoints {
		u, err := url.Parse(ep.URL)
		if err != nil || !strings.EqualFold(u.Hostname(), sc.Target.Host) {
			continue
		}
		switch ep.Category {
		case models.EndpointAuth, models.EndpointAdminLike:
			auth = append(auth, ep.URL)
		case models.EndpointAPI:
			other = append(other, ep.URL)
		}
		if len(auth)+len(other) >= 2 {
			break
		}
	}
	out := append(auth, other...)
	if len(out) > 2 {
		out = out[:2]
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
