// Package emailauth audits email-authentication posture (Wave 1 item 5):
// SPF, DMARC, DKIM selectors (bounded 3), BIMI, TLS-RPT via DNS TXT,
// plus MTA-STS via a single HTTPS fetch. DNS-only except one optional
// GET to https://mta-sts.<host>/.well-known/mta-sts.txt.
//
// Missing DMARC/SPF is Low (spoofing exposure); everything else is
// Info. Pure parsers are unit-tested; live DNS degrades to warnings.
package emailauth

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// dkimSelectors bounds DKIM probing to 3 common selectors.
var dkimSelectors = []string{"default", "selector1", "google"}

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
	// lookupTXT is overridable in tests.
	lookupTXT func(ctx context.Context, name string) ([]string, error)
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner {
	return &Scanner{client: client, lookupTXT: liveTXT}
}

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "emailauth" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

func liveTXT(ctx context.Context, name string) ([]string, error) {
	r := &net.Resolver{}
	cctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	return r.LookupTXT(cctx, name)
}

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	host := strings.ToLower(strings.TrimSuffix(sc.Target.Host, "."))
	if host == "" || net.ParseIP(host) != nil || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return scanner.StageResult{}, nil
	}
	var findings []models.Finding
	var warnings []string

	txt, err := s.lookupTXT(ctx, host)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("emailauth: apex TXT lookup failed: %v", shortErr(err)))
	} else {
		if !hasPrefixRecord(txt, "v=spf1") {
			// Canonical title + CWE-345 match the dnsintel SPF finding
			// so the pipeline merges both into one row (max wins).
			f := mkFinding(sc.Target.Raw, "emailauth-missing-spf",
				fmt.Sprintf("No SPF record for %s", host),
				"The domain publishes no SPF record, so receivers cannot reject forged envelope senders. Publish a restrictive TXT record (e.g. \"v=spf1 -all\" for non-sending domains).",
				models.SeverityLow, "DNS TXT SPF query")
			f.CWE = "CWE-345"
			findings = append(findings, f)
		} else if spf := spfRecord(txt); spfAllPass(spf) {
			f := mkFinding(sc.Target.Raw, "emailauth-spf-all-pass",
				fmt.Sprintf("Permissive SPF policy for %s", host),
				fmt.Sprintf("The SPF record %q authorizes every sender. Replace +all with -all or ~all.", spf),
				models.SeverityLow, "DNS TXT SPF query")
			f.CWE = "CWE-345"
			findings = append(findings, f)
		}
	}

	dmarc, derr := s.lookupTXT(ctx, "_dmarc."+host)
	if derr != nil {
		warnings = append(warnings, fmt.Sprintf("emailauth: DMARC lookup failed: %v", shortErr(derr)))
	} else if !hasPrefixRecord(dmarc, "v=DMARC1") {
		f := mkFinding(sc.Target.Raw, "emailauth-missing-dmarc",
			fmt.Sprintf("No DMARC record for %s", host),
			"Without DMARC, SPF/DKIM failures carry no domain-owner policy and spoofed mail is more likely to be delivered. Publish _dmarc TXT starting at p=none with rua reporting, then enforce p=reject.",
			models.SeverityLow, "DNS TXT DMARC query")
		f.CWE = "CWE-345"
		findings = append(findings, f)
	} else if pol := dmarcPolicy(dmarc); pol == "none" {
		f := mkFinding(sc.Target.Raw, "emailauth-dmarc-monitor-only",
			fmt.Sprintf("DMARC policy is p=none for %s (monitoring only)", host),
			"DMARC is published but takes no enforcement action on spoofed mail. Move to p=quarantine, then p=reject, once legitimate flows are aligned.",
			models.SeverityInfo, "DNS TXT DMARC query")
		f.CWE = "CWE-345"
		findings = append(findings, f)
	}

	foundDKIM := false
	for _, sel := range dkimSelectors {
		recs, serr := s.lookupTXT(ctx, sel+"._domainkey."+host)
		if serr == nil && hasPrefixRecord(recs, "v=DKIM1") {
			foundDKIM = true
			break
		}
	}
	if !foundDKIM {
		findings = append(findings, mkFinding(sc.Target.Raw, "emailauth-dkim-unconfirmed",
			"No DKIM key found under common selectors",
			"No DKIM TXT record answered for the probed selectors (default, selector1, google). If the domain sends mail, publish the provider's DKIM key; if it never sends mail, this is expected — keep SPF -all and DMARC p=reject.",
			models.SeverityInfo, "DNS TXT DKIM probe (3 selectors)"))
	}

	if bimi, berr := s.lookupTXT(ctx, "default._bimi."+host); berr == nil && len(bimi) > 0 {
		findings = append(findings, mkFinding(sc.Target.Raw, "emailauth-bimi-present",
			"BIMI record published",
			"BIMI publishes a brand logo for authenticated mail. Ensure the logo SVG and (for Gmail) the VMC certificate stay valid.",
			models.SeverityInfo, "DNS TXT BIMI query"))
	}
	if rpt, rerr := s.lookupTXT(ctx, "_smtp._tls."+host); rerr == nil && hasPrefixRecord(rpt, "v=TLSRPT") {
		findings = append(findings, mkFinding(sc.Target.Raw, "emailauth-tlsrpt-present",
			"TLS-RPT reporting enabled",
			"TLS-RPT is configured to receive TLS failure reports for inbound mail. Monitor the rua address for downgrade attacks.",
			models.SeverityInfo, "DNS TXT TLS-RPT query"))
	}

	// MTA-STS: single HTTPS fetch (bounded, read-only).
	stsURL := "https://mta-sts." + host + "/.well-known/mta-sts.txt"
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	if resp, rerr := s.client.Get(cctx, stsURL); rerr == nil && resp != nil && resp.StatusCode == 200 && strings.Contains(strings.ToLower(string(resp.Body)), "mode:") {
		findings = append(findings, mkFinding(sc.Target.Raw, "emailauth-mtasts-present",
			"MTA-STS policy published",
			"MTA-STS enforces TLS for inbound mail delivery. Keep the policy mode at enforce and the MX list in sync with DNS.",
			models.SeverityInfo, "HTTPS MTA-STS fetch"))
	}
	return scanner.StageResult{Findings: findings, Warnings: warnings}, nil
}

// hasPrefixRecord reports whether any TXT record starts with prefix
// (case-insensitive), tolerating multi-string TXT joins.
func hasPrefixRecord(recs []string, prefix string) bool {
	lp := strings.ToLower(prefix)
	for _, r := range recs {
		if strings.HasPrefix(strings.ToLower(cleanTXT(r)), lp) {
			return true
		}
	}
	return false
}

// cleanTXT strips whitespace and stray quoting from a TXT record (some
// resolvers/test fixtures quote whole records).
func cleanTXT(r string) string {
	return strings.Trim(strings.TrimSpace(r), "\"")
}

func spfRecord(recs []string) string {
	for _, r := range recs {
		if strings.HasPrefix(strings.ToLower(cleanTXT(r)), "v=spf1") {
			return cleanTXT(r)
		}
	}
	return ""
}

func spfAllPass(spf string) bool {
	fields := strings.Fields(strings.ToLower(spf))
	for _, f := range fields {
		if f == "+all" {
			return true
		}
	}
	return false
}

func dmarcPolicy(recs []string) string {
	for _, r := range recs {
		for _, part := range strings.Split(strings.ToLower(r), ";") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "p=") {
				return strings.TrimPrefix(part, "p=")
			}
		}
	}
	return ""
}

func mkFinding(target, id, title, desc string, sev models.Severity, method string) models.Finding {
	return models.Finding{
		ID: id, Title: title, Description: desc, Severity: sev,
		Confidence: models.ConfidenceHigh, Category: models.CategoryConfiguration,
		Target: target, Evidence: models.Evidence{Observed: title, Location: "DNS TXT / MTA-STS"},
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
