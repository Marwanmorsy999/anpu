// Package h2smuggle probes HTTP/2 desync posture (Wave 1 item 36,
// safe-subset, adversarial-gated): it runs ONLY when the scan was
// started with --adversarial --confirm-authorized (read from
// Config.Modules.Adversarial); otherwise it skips with a warning.
//
// Method: (1) TLS ALPN handshake detects h2 support (0 HTTP requests).
// (2) On h2-capable hosts, a CL.TE desync pair with a benign body is
// timed against two baselines; a consistent delay differential is a
// Medium needs-review finding. No cache poisoning, no stored payloads,
// benign strings only, 5 requests max.
package h2smuggle

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// maxRequests bounds all HTTP traffic: 2 baselines + 2 probes + control.
const maxRequests = 5

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
	// alpnProtocols is overridable in tests.
	alpnProtocols func(host, port string) []string
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner {
	return &Scanner{client: client, alpnProtocols: liveALPN}
}

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "h2smuggle" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

func liveALPN(host, port string) []string {
	if port == "" {
		port = "443"
	}
	dialer := &net.Dialer{Timeout: 6 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port),
		&tls.Config{InsecureSkipVerify: true, ServerName: host, NextProtos: []string{"h2", "http/1.1"}}) // #nosec G402 -- fingerprint-only handshake probe; cert is observed, not trusted.
	if err != nil {
		return nil
	}
	defer conn.Close()
	if p := conn.ConnectionState().NegotiatedProtocol; p != "" {
		return []string{p}
	}
	return nil
}

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	if !sc.Config.Modules.Adversarial {
		return scanner.StageResult{Warnings: []string{"h2smuggle skipped: requires --adversarial --confirm-authorized (authorized targets only)"}}, nil
	}
	host := sc.Target.Host
	if host == "" || net.ParseIP(host) != nil || sc.Target.URL.Scheme != "https" {
		return scanner.StageResult{}, nil
	}
	protos := s.alpnProtocols(host, sc.Target.Port)
	supportsH2 := false
	for _, p := range protos {
		if p == "h2" {
			supportsH2 = true
		}
	}
	if !supportsH2 {
		return scanner.StageResult{}, nil // no H2, no desync surface
	}
	made := 0
	timedPost := func(body string) (time.Duration, bool) {
		if made >= maxRequests {
			return 0, false
		}
		cctx, cancel := context.WithTimeout(ctx, 12*time.Second)
		defer cancel()
		made++
		start := time.Now()
		// Benign body with conflicting lengths; server should 400/ignore.
		// Nothing is stored, nothing is poisoned.
		resp, err := s.client.PostXML(cctx, sc.Target.Raw, body, map[string]string{
			"Content-Length":    "4",
			"Transfer-Encoding": "chunked",
		})
		el := time.Since(start)
		if err != nil || resp == nil {
			return 0, false
		}
		return el, true
	}
	b1, ok1 := timedPost("x=1")
	b2, ok2 := timedPost("x=1")
	p1, ok3 := timedPost("0\r\n\r\nX")
	p2, ok4 := timedPost("0\r\n\r\nX")
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return scanner.StageResult{}, nil
	}
	baseAvg := (b1 + b2) / 2
	probeAvg := (p1 + p2) / 2
	// Consistent ≥2s differential on both probes (not one jitter spike).
	if probeAvg-baseAvg >= 2*time.Second && p1-b1 >= 2*time.Second && p2-b2 >= 2*time.Second {
		return scanner.StageResult{Findings: []models.Finding{{
			ID: "h2smuggle-timing", Title: "Possible HTTP desync (CL.TE timing differential, needs review)",
			Description: fmt.Sprintf("H2-capable host shows a consistent delay differential (baseline ~%s vs desync-pair ~%s): front/back desync handling. This is timing evidence only — confirm manually with single-request analysis before acting. Benign bodies only; nothing stored. Reproduce under authorization: resend the CL.TE pair and time it.", baseAvg.Round(time.Millisecond), probeAvg.Round(time.Millisecond)),
			Severity:    models.SeverityMedium, Confidence: models.ConfidenceLow, Category: models.CategoryVulnerability,
			CWE: "CWE-444", Target: sc.Target.Raw, URL: sc.Target.Raw,
			Evidence: models.Evidence{Observed: fmt.Sprintf("baseline %s/%s vs probe %s/%s", b1.Round(time.Millisecond), b2.Round(time.Millisecond), p1.Round(time.Millisecond), p2.Round(time.Millisecond)), Location: "CL.TE pair timing"},
			Source:   models.SourceCustom, DetectionMethod: "H2 desync safe-subset timing (h2smuggle, adversarial, ≤5 requests)",
			Remediation: "Normalize to one transfer mechanism at the edge; reject ambiguous lengths.",
		}}}, nil
	}
	return scanner.StageResult{}, nil
}
