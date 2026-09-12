// Package axfrplus sweeps zone transfers across all NS (Wave 1 item
// 43): NS lookup for the target's registrable base, then one AXFR
// attempt per nameserver (DNS TCP, 5s each, usually ≤4). A successful
// transfer is a High finding with the record count (names only —
// record data beyond names is not stored). Failures are silent; zone
// transfers are standard DNS behavior, read-only.
package axfrplus

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
	"github.com/miekg/dns"
)

// timeouts are overridable in tests.
var (
	dnsTimeout   = 5 * time.Second
	resolverAddr = "8.8.8.8:53"
)

// Scanner implements scanner.Scanner.
type Scanner struct{}

// New builds a Scanner.
func New() *Scanner { return &Scanner{} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "axfrplus" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

// baseDomain returns the registrable base (pure, tested).
func baseDomain(host string) string {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	parts := strings.Split(h, ".")
	if len(parts) < 2 {
		return h
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	host := strings.ToLower(strings.TrimSuffix(sc.Target.Host, "."))
	if host == "" || net.ParseIP(host) != nil || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return scanner.StageResult{}, nil
	}
	base := baseDomain(host)
	nss, err := lookupNS(base)
	if err != nil || len(nss) == 0 {
		return scanner.StageResult{}, nil
	}
	var findings []models.Finding
	for _, ns := range nss {
		select {
		case <-ctx.Done():
			return scanner.StageResult{Findings: findings}, nil
		default:
		}
		names, ok := tryAXFR(base, ns)
		if !ok || len(names) == 0 {
			continue
		}
		shown := names
		if len(shown) > 10 {
			shown = shown[:10]
		}
		findings = append(findings, models.Finding{
			ID: "axfrplus-transfer", Title: fmt.Sprintf("Zone transfer (AXFR) allowed by %s (%d records)", ns, len(names)),
			Description: fmt.Sprintf("Nameserver %s answered a full AXFR for %s: the entire zone layout (internal names included) is public. Restrict transfers to secondaries via ACL/TSIG. Only record names were counted — contents not stored. Reproduce: dig AXFR %s @%s.", ns, base, base, ns),
			Severity:    models.SeverityHigh, Confidence: models.ConfidenceHigh, Category: models.CategoryExposure,
			CWE: "CWE-200", Target: sc.Target.Raw,
			Evidence: models.Evidence{Observed: fmt.Sprintf("%d names via %s, e.g. %s", len(names), ns, strings.Join(shown, ", ")), Location: "DNS AXFR"},
			Source:   models.SourceRecon, DetectionMethod: "AXFR sweep across NS (axfrplus)",
			Remediation: "Deny AXFR to the world; allowlist secondaries.",
		})
		break // one open server proves the misconfig
	}
	return scanner.StageResult{Findings: findings}, nil
}

func lookupNS(base string) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(base), dns.TypeNS)
	c := new(dns.Client)
	c.Timeout = dnsTimeout
	resp, _, err := c.Exchange(m, resolverAddr)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, a := range resp.Answer {
		if ns, ok := a.(*dns.NS); ok {
			out = append(out, strings.TrimSuffix(ns.Ns, "."))
		}
	}
	return out, nil
}

// tryAXFR attempts a transfer, returning record OWNER names only.
func tryAXFR(zone, ns string) ([]string, bool) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zone), dns.TypeAXFR)
	t := new(dns.Transfer)
	t.DialTimeout = dnsTimeout
	t.ReadTimeout = dnsTimeout
	ch, err := t.In(m, net.JoinHostPort(ns, "53"))
	if err != nil {
		return nil, false
	}
	seen := map[string]bool{}
	var names []string
	timeout := time.After(10 * time.Second)
	for {
		select {
		case env, ok := <-ch:
			if !ok {
				return names, len(names) > 0
			}
			if env.Error != nil {
				return names, len(names) > 0
			}
			for _, rr := range env.RR {
				n := strings.ToLower(strings.TrimSuffix(rr.Header().Name, "."))
				if !seen[n] {
					seen[n] = true
					names = append(names, n)
				}
				if len(names) > 500 {
					return names, true
				}
			}
		case <-timeout:
			return names, len(names) > 0
		}
	}
}
