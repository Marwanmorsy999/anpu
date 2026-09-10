// Package corsplus extends CORS analysis (Wave 1 item 41): null-Origin
// trust, sandbox/allowlist gaps, subdomain reflection, and
// credentialed-wildcard checks across discovered endpoints. The base
// CORS stage covers plain reflection; this pack sends Origin: null,
// Origin: https://evil.example, and Origin: https://sub.<target> with
// and without credentials context, requiring exact reflection plus
// Access-Control-Allow-Credentials: true for a finding. GET-only,
// ≤3 endpoints × 3 origins = 12 requests max.
package corsplus

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// maxRequests bounds all HTTP traffic: 3 endpoints × (baseline + 3).
const (
	maxEndpoints = 3
	maxRequests  = 12
)

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "corsplus" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	targets := pickTargets(sc)
	evilSub := "https://anpuevil." + strings.TrimSuffix(sc.Target.Host, ".")
	origins := []struct {
		origin string
		title  string
	}{
		{"null", "null-Origin trusted with credentials"},
		{"https://evil.example", "arbitrary Origin reflected with credentials"},
		{evilSub, "untrusted subdomain Origin reflected with credentials"},
	}
	made := 0
	probe := func(u, origin string) (acao, acac string, ok bool) {
		if made >= maxRequests {
			return "", "", false
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		made++
		resp, err := s.client.DoWithHeaders(cctx, "GET", u, map[string]string{"Origin": origin})
		if err != nil || resp == nil {
			return "", "", false
		}
		return resp.Header.Get("Access-Control-Allow-Origin"), resp.Header.Get("Access-Control-Allow-Credentials"), true
	}

	var findings []models.Finding
	for _, target := range targets {
		for _, o := range origins {
			if made >= maxRequests {
				break
			}
			acao, acac, ok := probe(target, o.origin)
			if !ok {
				continue
			}
			// Credentialed trust requires EXACT origin echo + credentials true.
			if !strings.EqualFold(strings.TrimSpace(acao), o.origin) {
				continue
			}
			if !strings.EqualFold(strings.TrimSpace(acac), "true") {
				continue
			}
			findings = append(findings, models.Finding{
				ID: "corsplus-credentialed", Title: "CORS credentialed trust: " + o.title,
				Description: fmt.Sprintf("GET %s with Origin: %s returns Access-Control-Allow-Origin: %s plus Allow-Credentials: true: any page of that origin reads credentialed responses (session theft). Never reflect untrusted origins with credentials. Reproduce: curl -s -H 'Origin: %s' -D- TARGET | grep -i access-control.", displayPath(target), o.origin, acao, o.origin),
				Severity:    models.SeverityMedium, Confidence: models.ConfidenceHigh, Category: models.CategoryVulnerability,
				CWE: "CWE-942", Target: sc.Target.Raw, URL: target,
				Evidence: models.Evidence{Observed: fmt.Sprintf("Origin %s echoed + Allow-Credentials: true", o.origin), Location: "CORS preflight-less probe"},
				Source:   models.SourceCustom, DetectionMethod: "CORS null/evil/subdomain matrix (corsplus, ≤12 requests)",
				Remediation: "Allowlist origins; never combine reflection with credentials.",
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
	out := []string{sc.Target.Raw}
	for _, ep := range sc.Endpoints {
		if len(out) >= maxEndpoints {
			break
		}
		u, err := url.Parse(ep.URL)
		if err != nil || !strings.EqualFold(u.Hostname(), sc.Target.Host) || ep.URL == sc.Target.Raw {
			continue
		}
		out = append(out, ep.URL)
	}
	return out
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
