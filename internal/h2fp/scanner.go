// Package h2fp fingerprints HTTP/2 and HTTP/3 support (Wave 1 item 37):
// TLS ALPN handshake (0 HTTP requests) plus one GET for Alt-Svc and
// server hints. Findings are Info; negotiated h2/announced h3 are also
// recorded as Technology. Passive, safe-eligible, deterministic.
package h2fp

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
	// alpn is overridable in tests.
	alpn func(host, port string) string
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client, alpn: liveALPN} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "h2fp" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

func liveALPN(host, port string) string {
	if port == "" {
		port = "443"
	}
	dialer := &net.Dialer{Timeout: 6 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port),
		&tls.Config{InsecureSkipVerify: true, ServerName: host, NextProtos: []string{"h2", "http/1.1"}}) //nolint:gosec // fingerprint only
	if err != nil {
		return ""
	}
	defer conn.Close()
	return conn.ConnectionState().NegotiatedProtocol
}

// parseAltSvc extracts advertised protocols (pure, tested).
func parseAltSvc(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(strings.Trim(strings.TrimSpace(part), `"`))
		if part == "" {
			continue
		}
		fields := strings.SplitN(part, "=", 2)
		proto := strings.Trim(fields[0], `"`)
		if proto != "" {
			out = append(out, proto)
		}
	}
	return out
}

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	var findings []models.Finding
	var techs []models.Technology
	if sc.Target.URL.Scheme == "https" && net.ParseIP(sc.Target.Host) == nil {
		if proto := s.alpn(sc.Target.Host, sc.Target.Port); proto != "" {
			techs = append(techs, models.Technology{Name: "HTTP/" + proto, Category: "protocol", Confidence: 1.0,
				Evidence: models.Evidence{Observed: "ALPN: " + proto, Location: "TLS handshake"}})
			if proto == "h2" {
				findings = append(findings, info(sc.Target.Raw, "h2fp-h2", "HTTP/2 negotiated via ALPN",
					"The server negotiates h2: review HTTP/2-specific hardening (continuation-flood limits, rapid-reset mitigations) alongside HTTP/1.1 tests.", "ALPN: h2"))
			}
		}
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resp, err := s.client.Get(cctx, sc.Target.Raw)
	if err != nil || resp == nil {
		return scanner.StageResult{Findings: findings, Technologies: techs}, nil
	}
	if alt := resp.Header.Get("Alt-Svc"); alt != "" {
		protos := parseAltSvc(alt)
		for _, p := range protos {
			if strings.HasPrefix(p, "h3") {
				techs = append(techs, models.Technology{Name: "HTTP/3 (" + p + ")", Category: "protocol", Confidence: 0.9,
					Evidence: models.Evidence{Observed: "Alt-Svc: " + alt, Location: "response headers"}})
				findings = append(findings, info(sc.Target.Raw, "h2fp-h3", "HTTP/3 advertised via Alt-Svc",
					"QUIC/HTTP-3 endpoint advertised ("+p+"): include UDP/443 in scope reviews and apply the same authz tests over the new transport.", "Alt-Svc: "+alt))
				break
			}
		}
	}
	return scanner.StageResult{Findings: findings, Technologies: techs}, nil
}

func info(target, id, title, desc, observed string) models.Finding {
	return models.Finding{
		ID: id, Title: title, Description: desc + " Reproduce: openssl s_client -alpn h2 -connect host:443 | grep ALPN; curl -sI TARGET | grep -i alt-svc.", Severity: models.SeverityInfo,
		Confidence: models.ConfidenceHigh, Category: models.CategoryExposure,
		Target: target, Evidence: models.Evidence{Observed: observed, Location: "TLS ALPN / Alt-Svc"},
		Source: models.SourceRecon, DetectionMethod: "H2/H3 fingerprint (h2fp, ≤1 request)",
	}
}
