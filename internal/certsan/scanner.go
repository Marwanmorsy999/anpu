// Package certsan extracts TLS certificate Subject Alternative Names
// (Wave 1 item 2): a single TLS handshake (zero HTTP requests) reveals
// every DNS name the certificate covers — a passive, keyless subdomain
// signal. Names are returned as Subdomains for the Takeover stage.
//
// Deterministic and ghost-compatible (plain crypto/tls handshake).
package certsan

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// Scanner implements scanner.Scanner (no HTTP client needed).
type Scanner struct{}

// New builds a Scanner.
func New() *Scanner { return &Scanner{} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "certsan" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	host := sc.Target.Host
	if host == "" || net.ParseIP(host) != nil {
		return scanner.StageResult{}, nil // IPs carry no SAN subdomain signal
	}
	port := sc.Target.Port
	if port == "" {
		if sc.Target.URL.Scheme == "http" {
			return scanner.StageResult{}, nil // plaintext: no TLS cert
		}
		port = "443"
	}
	addr := net.JoinHostPort(host, port)
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, // #nosec G402 -- scanner must complete handshakes with misconfigured targets to analyze them.
		ServerName:         host,
	})
	if err != nil {
		return scanner.StageResult{Warnings: []string{fmt.Sprintf("certsan: TLS handshake failed: %v", trimErr(err))}}, nil
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return scanner.StageResult{}, nil
	}
	leaf := state.PeerCertificates[0]
	seen := map[string]bool{}
	var subs []string
	add := func(n string) {
		n = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(n, ".")))
		if n == "" || seen[n] || strings.Contains(n, "*") || strings.Contains(n, " ") {
			return
		}
		seen[n] = true
		subs = append(subs, n)
	}
	if leaf.Subject.CommonName != "" {
		add(leaf.Subject.CommonName)
	}
	for _, san := range leaf.DNSNames {
		add(san)
	}
	// Echo-guard: drop the target's own hostname from the "new" list.
	var fresh []string
	for _, n := range subs {
		if !strings.EqualFold(n, host) {
			fresh = append(fresh, n)
		}
	}
	var findings []models.Finding
	if len(fresh) > 0 {
		shown := fresh
		if len(shown) > 15 {
			shown = shown[:15]
		}
		findings = append(findings, models.Finding{
			ID:              "certsan-extra-names",
			Title:           fmt.Sprintf("Certificate covers %d additional hostname(s)", len(fresh)),
			Description:     "The TLS certificate's Subject Alternative Names list hostnames beyond the scanned target. Each is a candidate subdomain for takeover review. Reproduce: openssl s_client -connect host:443 -servername host | openssl x509 -noout -ext subjectAltName",
			Severity:        models.SeverityInfo,
			Confidence:      models.ConfidenceHigh,
			Category:        models.CategoryExposure,
			Target:          sc.Target.Raw,
			Evidence:        models.Evidence{Observed: strings.Join(shown, ", "), Location: "TLS certificate SAN"},
			Source:          models.SourceRecon,
			DetectionMethod: "TLS handshake SAN extraction (certsan)",
		})
	}
	return scanner.StageResult{Findings: findings, Subdomains: fresh}, nil
}

func trimErr(err error) string {
	s := err.Error()
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}
