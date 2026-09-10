// Package dnsaudit audits DNSSEC/CAA/DANE posture (Wave 1 item 4) using
// DNS queries only — zero HTTP requests to the target. Checks: CAA
// record presence, DNSKEY presence (signed zone hint), and TLSA/DANE
// records for _443._tcp.<host>.
//
// Fail-closed lookups degrade to warnings, never errors. Pure parsing
// helpers are unit-tested; live lookups are hermetic-safe (no target
// traffic) and skipped for IPs/localhost.
package dnsaudit

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
	"github.com/miekg/dns"
)

// resolver is overridable in tests.
var (
	resolverAddr = "8.8.8.8:53"
	queryTimeout = 6 * time.Second
)

// Scanner implements scanner.Scanner.
type Scanner struct{}

// New builds a Scanner.
func New() *Scanner { return &Scanner{} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "dnsaudit" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	host := strings.ToLower(strings.TrimSuffix(sc.Target.Host, "."))
	if host == "" || net.ParseIP(host) != nil || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return scanner.StageResult{}, nil
	}
	var findings []models.Finding
	var warnings []string

	caa, cerr := query(host, dns.TypeCAA)
	if cerr != nil {
		warnings = append(warnings, fmt.Sprintf("dnsaudit: CAA lookup failed: %v", shortErr(cerr)))
	} else if len(caa) == 0 {
		findings = append(findings, finding(sc.Target.Raw, "dnsaudit-missing-caa",
			"No CAA record published",
			"The zone publishes no CAA record, so any public CA may issue certificates for this host. Publish a restrictive CAA record (e.g. 0 issue \"letsencrypt.org\").",
			models.SeverityLow, "DNS CAA query"))
	}

	keys, kerr := query(host, dns.TypeDNSKEY)
	if kerr != nil {
		warnings = append(warnings, fmt.Sprintf("dnsaudit: DNSKEY lookup failed: %v", shortErr(kerr)))
	} else if len(keys) == 0 {
		findings = append(findings, finding(sc.Target.Raw, "dnsaudit-unsigned-zone",
			"Zone appears unsigned (no DNSKEY)",
			"No DNSKEY records were returned, suggesting the zone is not DNSSEC-signed and responses could be spoofed. Enable DNSSEC signing at the registrar/DNS provider.",
			models.SeverityLow, "DNS DNSKEY query"))
	}

	tlsa, terr := query("_443._tcp."+host, dns.TypeTLSA)
	if terr != nil {
		warnings = append(warnings, fmt.Sprintf("dnsaudit: TLSA lookup failed: %v", shortErr(terr)))
	} else if len(tlsa) > 0 {
		findings = append(findings, finding(sc.Target.Raw, "dnsaudit-dane-present",
			fmt.Sprintf("DANE TLSA records published (%d)", len(tlsa)),
			"TLSA records pin the TLS certificate in DNS (DANE). Ensure they are kept in sync with certificate renewals or clients will hard-fail.",
			models.SeverityInfo, "DNS TLSA query"))
	}
	return scanner.StageResult{Findings: findings, Warnings: warnings}, nil
}

// query returns answer RRs for name/type via the configured resolver.
func query(name string, qtype uint16) ([]dns.RR, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	c := new(dns.Client)
	c.Timeout = queryTimeout
	resp, _, err := c.Exchange(m, resolverAddr)
	if err != nil {
		return nil, err
	}
	return resp.Answer, nil
}

func finding(target, id, title, desc string, sev models.Severity, method string) models.Finding {
	return models.Finding{
		ID: id, Title: title, Description: desc, Severity: sev,
		Confidence: models.ConfidenceHigh, Category: models.CategoryConfiguration,
		Target: target, Evidence: models.Evidence{Observed: title, Location: "DNS query (" + resolverAddr + ")"},
		Source: models.SourceRecon, DetectionMethod: method,
	}
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 160 {
		s = s[:160] + "..."
	}
	return s
}
