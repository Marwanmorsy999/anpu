// Package portscan performs a bounded TCP connect scan of common ports
// on the scan target's host. It is intentionally conservative:
//
//   - only a fixed list of well-known service ports is probed (no
//     full 65k sweep),
//   - connections time out quickly (2s) and are closed immediately,
//   - the host must pass the same public-address guard as every other
//     ANPU engine before any socket is opened.
//
// Open ports are reported as informational attack-surface findings;
// ANPU does not fingerprint or exploit them.
package portscan

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// Scanner implements scanner.Scanner for TCP port probing.
type Scanner struct {
	dialer *net.Dialer
	dial   func(context.Context, string, string) (net.Conn, error)
}

func New() *Scanner {
	d := &net.Dialer{Timeout: 2 * time.Second}
	return &Scanner{dialer: d, dial: d.DialContext}
}

func (s *Scanner) Name() string { return "portscan" }

func (s *Scanner) Available(ctx context.Context) bool { return true }

func (s *Scanner) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if s.dial != nil {
		return s.dial(ctx, network, address)
	}
	return s.dialer.DialContext(ctx, network, address)
}

// commonPorts covers the services most commonly exposed on web-facing
// infrastructure: mail, databases, dev/admin panels, caches, message
// queues, and alternate HTTP listeners.
var commonPorts = []struct {
	Port int
	Svc  string
}{
	{21, "FTP"}, {22, "SSH"}, {23, "Telnet"}, {25, "SMTP"}, {53, "DNS"},
	{80, "HTTP"}, {110, "POP3"}, {111, "RPCBind"}, {143, "IMAP"},
	{443, "HTTPS"}, {445, "SMB"}, {465, "SMTPS"}, {587, "Submission"},
	{993, "IMAPS"}, {995, "POP3S"}, {1433, "MSSQL"}, {1521, "Oracle"},
	{2049, "NFS"}, {2375, "Docker API"}, {3000, "Node/Dev HTTP"},
	{3306, "MySQL"}, {3389, "RDP"}, {5000, "Flask/Dev HTTP"},
	{5432, "PostgreSQL"}, {5900, "VNC"}, {6379, "Redis"}, {8000, "HTTP-alt"},
	{8008, "HTTP-alt"}, {8080, "HTTP-proxy"}, {8081, "HTTP-alt"},
	{8443, "HTTPS-alt"}, {8888, "HTTP-alt"}, {9090, "Prometheus/HTTP"},
	{9200, "Elasticsearch"}, {11211, "Memcached"}, {27017, "MongoDB"},
}

// riskyServices maps open ports to the severity of exposing them on a
// public host. Databases/caches/admin surfaces are worse than a plain
// extra web listener.
var riskyServices = map[string]models.Severity{
	"FTP": models.SeverityMedium, "Telnet": models.SeverityHigh,
	"SMTP": models.SeverityLow, "POP3": models.SeverityLow,
	"IMAP": models.SeverityLow, "SMB": models.SeverityHigh,
	"MSSQL": models.SeverityHigh, "Oracle": models.SeverityHigh,
	"NFS": models.SeverityHigh, "Docker API": models.SeverityCritical,
	"MySQL": models.SeverityHigh, "RDP": models.SeverityMedium,
	"PostgreSQL": models.SeverityHigh, "VNC": models.SeverityHigh,
	"Redis": models.SeverityHigh, "Elasticsearch": models.SeverityMedium,
	"Memcached": models.SeverityMedium, "MongoDB": models.SeverityHigh,
}

func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	host := sc.Target.Host
	if sc.Target.Port != "" && sc.Target.Port != "80" && sc.Target.Port != "443" {
		_ = sc.Target.Port
	}

	if err := anpuhttp.ValidateHostPublic(host); err != nil && !scanner.AllowLocalNetwork {
		return scanner.StageResult{}, fmt.Errorf("port scan blocked by local-network guard: %w", err)
	}

	lies := 0
	for _, p := range []int{1, 9} {
		if conn, err := s.dialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", p))); err == nil {
			conn.Close()
			lies++
		}
	}
	if lies == 2 {
		return scanner.StageResult{
			Warnings: []string{fmt.Sprintf("port scan unreliable: %s accepted connections on sanity-check ports 1/9, indicating a transparent proxy or middlebox is answering for all ports; results suppressed", host)},
		}, nil
	}

	type openPort struct {
		port int
		svc  string
	}
	var (
		mu   sync.Mutex
		open []openPort
		wg   sync.WaitGroup
		sem  = make(chan struct{}, 128)
	)

	for _, p := range commonPorts {
		wg.Add(1)
		go func(port int, svc string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
			conn, err := s.dialContext(ctx, "tcp", addr)
			if err == nil {
				conn.Close()
				mu.Lock()
				open = append(open, openPort{port, svc})
				mu.Unlock()
			}
		}(p.Port, p.Svc)
	}
	wg.Wait()

	if len(open) == 0 {
		return scanner.StageResult{}, nil
	}

	sort.Slice(open, func(i, j int) bool { return open[i].port < open[j].port })

	var (
		lines    []string
		findings []models.Finding
	)
	for _, op := range open {
		line := fmt.Sprintf("%d/tcp open (%s)", op.port, op.svc)
		lines = append(lines, line)

		sev := models.SeverityInfo
		if r, ok := riskyServices[op.svc]; ok {
			sev = r
		}
		if sev == models.SeverityInfo && (op.port == 80 || op.port == 443) {
			continue
		}
		findings = append(findings, models.Finding{
			ID:          fmt.Sprintf("portscan-open-%d", op.port),
			Title:       fmt.Sprintf("Port %d open (%s)", op.port, op.svc),
			Description: fmt.Sprintf("A TCP %s service accepts connections on %s:%d. Open network services expand the attack surface and each should be intentionally exposed, patched, and firewalled where possible.", op.svc, host, op.port),
			Severity:    sev,
			Confidence:  models.ConfidenceConfirmed,
			Category:    models.CategoryConfiguration,
			CWE:         "CWE-200",
			Target:      sc.Target.Raw,
			URL:         fmt.Sprintf("tcp://%s:%d", host, op.port),
			Evidence: models.Evidence{
				Observed: line,
				Location: "TCP connect probe",
			},
			Source:          models.SourceCustom,
			DetectionMethod: "TCP connect scan",
			Impact:          "Exposed services can be probed for known vulnerabilities; data stores and admin interfaces reachable from the internet are frequently compromised.",
			Remediation:     "Close ports that are not intentionally public; restrict databases/caches/admin services to private networks or VPN access.",
		})
	}

	if len(findings) > 0 {
		summary := models.Finding{
			ID:          "portscan-summary",
			Title:       fmt.Sprintf("%d non-web TCP port(s) open", len(findings)),
			Description: "Summary of all open ports detected during the connect scan." + cdnCaveat(sc),
			Severity:    models.SeverityInfo,
			Confidence:  models.ConfidenceConfirmed,
			Category:    models.CategoryConfiguration,
			Target:      sc.Target.Raw,
			URL:         sc.Target.Raw,
			Evidence: models.Evidence{
				Observed: joinLines(lines),
				Location: "TCP connect scan",
			},
			Source:          models.SourceCustom,
			DetectionMethod: "TCP connect scan",
		}
		findings = append([]models.Finding{summary}, findings...)
	}

	return scanner.StageResult{Findings: findings}, nil
}

func cdnCaveat(sc *scanner.ScanContext) string {
	for _, t := range sc.Technologies {
		switch t.Name {
		case "Cloudflare", "Amazon CloudFront", "Vercel", "Fastly":
			return fmt.Sprintf(" Note: %s was fingerprinted for this host, so the scanned addresses are the CDN edge, not necessarily your origin. Verify these ports directly against the origin server (e.g. by hostname or allow-listed IP) before acting.", t.Name)
		}
	}
	return ""
}

func joinLines(lines []string) string {
	out := ""
	for i, l := range lines {
		if i > 0 {
			out += "\n"
		}
		out += l
	}
	return out
}
