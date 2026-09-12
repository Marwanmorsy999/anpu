// Package doh probes for publicly exposed DNS-over-HTTPS (DoH) endpoints.
// DoH resolves DNS via HTTPS (RFC 8484) at /.well-known/dns-query or /dns-query.
// An open DoH resolver can be abused as an open proxy for DNS exfiltration
// and to bypass local DNS filtering. This is a network-level exposure check.
//
// One GET per candidate path (max 2), with accept: application/dns-message.
// Passive in sense of not probing external DoH providers — only the target itself.
package doh

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// Scanner implements scanner.Scanner for DoH exposure.
type Scanner struct {
	client *anpuhttp.Client
}

func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

func (s *Scanner) Name() string                     { return "doh" }
func (s *Scanner) Available(_ context.Context) bool { return true }

// dohQuery is a base64url DNS query for A example.com (cloudflare example).
// It decodes to a valid DNS wire query; a compliant DoH server should return
// application/dns-message.
const dohQuery = "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"

func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	host := sc.Target.Host
	if host == "" {
		return scanner.StageResult{}, nil
	}
	if net.ParseIP(host) != nil && !scanner.AllowLocalNetwork {
		return scanner.StageResult{}, nil
	}
	lower := strings.ToLower(strings.TrimSuffix(host, "."))
	if (lower == "localhost" || strings.HasSuffix(lower, ".localhost")) && !scanner.AllowLocalNetwork {
		return scanner.StageResult{}, nil
	}

	// Prefer target's scheme, but try https first (DoH is TLS-only per RFC).
	schemes := []string{"https", "http"}
	if sc.Target.URL.Scheme == "http" {
		schemes = []string{"http", "https"}
	}
	paths := []string{"/.well-known/dns-query", "/dns-query"}

	var findings []models.Finding
	for _, scheme := range schemes {
		for _, p := range paths {
			u := fmt.Sprintf("%s://%s%s?dns=%s", scheme, sc.Target.Host, p, dohQuery)
			if sc.Target.Port != "" {
				// Include explicit port when target used non-default port
				u = fmt.Sprintf("%s://%s:%s%s?dns=%s", scheme, sc.Target.Host, sc.Target.Port, p, dohQuery)
			}
			cctx, cancel := context.WithTimeout(ctx, 7*time.Second)
			headers := map[string]string{
				"Accept": "application/dns-message",
			}
			resp, err := s.client.DoWithHeaders(cctx, "GET", u, headers)
			cancel()
			if err != nil || resp == nil {
				continue
			}
			ct := strings.ToLower(resp.Header.Get("Content-Type"))
			if resp.StatusCode == 200 && strings.Contains(ct, "application/dns-message") && len(resp.Body) >= 12 {
				findings = append(findings, models.Finding{
					ID:              "doh-exposed-" + strings.ReplaceAll(p, "/", "-"),
					Title:           fmt.Sprintf("DNS-over-HTTPS (DoH) endpoint exposed at %s", p),
					Description:     fmt.Sprintf("The target exposes a DNS-over-HTTPS resolver at %s://%s%s (HTTP %d, Content-Type %s). An open DoH endpoint can be abused for DNS tunneling, data exfiltration, and to bypass local DNS controls.", scheme, sc.Target.Host, p, resp.StatusCode, ct),
					Severity:        models.SeverityMedium,
					Confidence:      models.ConfidenceHigh,
					Category:        models.CategoryConfiguration,
					CWE:             "CWE-16",
					Target:          sc.Target.Raw,
					URL:             u,
					Evidence:        models.Evidence{Observed: fmt.Sprintf("GET %s → %d %s (%d bytes)", p, resp.StatusCode, ct, len(resp.Body)), Location: "DoH probe"},
					Source:          models.SourceCustom,
					DetectionMethod: "GET DoH query with accept: application/dns-message",
					Remediation:     "If DoH is not intentionally offered to the public, restrict /dns-query to authenticated clients or disable the endpoint. Open DoH resolvers should require authentication and rate-limiting.",
				})
				// One positive is enough; avoid noisy duplicate for second path
				return scanner.StageResult{Findings: findings}, nil
			}
			// Also consider 200 with JSON DoH (application/dns-json) as exposure, but
			// RFC 8484 mandates dns-message, so we keep gate tight.
		}
		// Prefer https; if https probe succeeded or got 200 JSON, we already returned.
		// Don't double-probe http if https was clearly not a DoH server (immediate 404).
	}
	return scanner.StageResult{Findings: findings}, nil
}
