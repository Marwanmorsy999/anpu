// Package cswsh checks WebSocket cross-site hijacking posture (Wave 1
// item 17): for up to 4 same-host WebSocket endpoints (discovered
// ws/wss URLs first, then common paths), it performs a bare-minimum
// HTTP Upgrade handshake carrying Origin: https://evil.example. A
// 101 Switching Protocols against a cross-site Origin means the
// handshake does not validate Origin — Low severity, needs-review
// (message-level auth may still exist). A 403/401 is silent (protected).
//
// Raw TCP/TLS dials only (no HTTP client requests counted); 5s timeout
// per dial; no frames are ever sent, so no application state is touched.
package cswsh

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// maxTargets bounds raw-socket handshakes per scan.
const maxTargets = 4

// Scanner implements scanner.Scanner (no HTTP client needed).
type Scanner struct{}

// New builds a Scanner.
func New() *Scanner { return &Scanner{} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "cswsh" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

var commonWSPaths = []string{"/ws", "/websocket", "/socket", "/ws/chat", "/socket.io/?EIO=4&transport=websocket"}

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	if net.ParseIP(sc.Target.Host) != nil && !scanner.AllowLocalNetwork {
		return scanner.StageResult{}, nil
	}
	var candidates []string
	for _, ep := range sc.Endpoints {
		if len(candidates) >= maxTargets {
			break
		}
		if strings.HasPrefix(strings.ToLower(ep.URL), "ws://") || strings.HasPrefix(strings.ToLower(ep.URL), "wss://") {
			candidates = append(candidates, ep.URL)
		}
	}
	scheme := sc.Target.URL.Scheme
	if scheme == "" {
		scheme = "https"
	}
	wsScheme := "wss"
	if scheme == "http" {
		wsScheme = "ws"
	}
	for _, p := range commonWSPaths {
		if len(candidates) >= maxTargets {
			break
		}
		host := sc.Target.Host
		if sc.Target.Port != "" {
			host = net.JoinHostPort(sc.Target.Host, sc.Target.Port)
		}
		candidates = append(candidates, wsScheme+"://"+host+p)
	}

	var findings []models.Finding
	checked := 0
	for _, raw := range candidates {
		if checked >= maxTargets {
			break
		}
		select {
		case <-ctx.Done():
			return scanner.StageResult{Findings: findings}, nil
		default:
		}
		checked++
		status, err := handshakeStatus(raw)
		if err != nil {
			continue // closed/filtered — silent
		}
		if status == 101 {
			findings = append(findings, models.Finding{
				ID:              "cswsh-no-origin-check",
				Title:           "WebSocket handshake accepts cross-site Origin (possible CSWSH)",
				Description:     fmt.Sprintf("The endpoint %s answered 101 Switching Protocols to a handshake carrying Origin: https://evil.example. If the application then relies on cookies/session without per-message CSRF protection, any visited site can drive the socket. Confirm manually and enforce an Origin allowlist server-side. No frames were sent. Reproduce: open a raw socket and send an Upgrade request with a foreign Origin.", raw),
				Severity:        models.SeverityLow,
				Confidence:      models.ConfidenceMedium,
				Category:        models.CategoryVulnerability,
				CWE:             "CWE-1385",
				Target:          sc.Target.Raw,
				URL:             raw,
				Evidence:        models.Evidence{Observed: "Upgrade + Origin: https://evil.example → 101 (0 frames sent)", Location: "WebSocket handshake"},
				Source:          models.SourceCustom,
				DetectionMethod: "cross-Origin WebSocket handshake (cswsh, ≤4 raw dials)",
				Remediation:     "Validate Origin against an allowlist during the handshake; require per-message tokens.",
			})
			if len(findings) >= 2 {
				break
			}
		}
	}
	return scanner.StageResult{Findings: findings}, nil
}

// handshakeStatus performs a minimal Upgrade handshake with a foreign
// Origin and returns the HTTP status. No WebSocket frames are sent.
func handshakeStatus(raw string) (int, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return 0, err
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if strings.EqualFold(u.Scheme, "wss") {
			port = "443"
		} else {
			port = "80"
		}
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 5*time.Second)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if strings.EqualFold(u.Scheme, "wss") {
		tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: host}) //nolint:gosec // handshake probe only
		if err := tlsConn.Handshake(); err != nil {
			return 0, err
		}
		conn = tlsConn
	}
	path := u.RequestURI()
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: anpuZHJmN3QyZGVmN3QyZQ==\r\nSec-WebSocket-Version: 13\r\nOrigin: https://evil.example\r\n\r\n", path, u.Host)
	if _, err := conn.Write([]byte(req)); err != nil {
		return 0, err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return 0, err
	}
	var proto string
	var status int
	if _, err := fmt.Sscanf(strings.TrimSpace(line), "%s %d", &proto, &status); err != nil {
		return 0, err
	}
	return status, nil
}
