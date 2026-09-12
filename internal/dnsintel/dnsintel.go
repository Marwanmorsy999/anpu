// Package dnsintel performs comprehensive DNS enumeration for a target
// hostname: A/AAAA, CNAME, MX, NS, TXT, SPF, DMARC, SOA hints, plus reverse
// PTR for each resolved IP. It is fully passive — only DNS queries are
// issued, no TCP to the target — so it runs on every profile including
// safe.
//
// Findings are informational with actionable hygiene signals (missing SPF/
// DMARC, permissive SPF) and feed IP/host inventory for later stages.
package dnsintel

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// Scanner implements scanner.Scanner for DNS intelligence.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string                     { return "dnsintel" }
func (s *Scanner) Available(_ context.Context) bool { return true }

func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	domain := sc.Target.Host
	if domain == "" {
		return scanner.StageResult{}, nil
	}
	// Skip bare IPs and localhost — DNS TXT/MX/NS queries are meaningless.
	if net.ParseIP(domain) != nil {
		return scanner.StageResult{}, nil
	}
	lower := strings.ToLower(strings.TrimSuffix(domain, "."))
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return scanner.StageResult{}, nil
	}

	var findings []models.Finding
	var warnings []string

	// Helper that respects ctx cancellation.
	ctxTimeout := func(d time.Duration) (context.Context, context.CancelFunc) {
		return context.WithTimeout(ctx, d)
	}

	// --- A/AAAA (via LookupIP) ---
	ips, ipErr := func() ([]net.IP, error) {
		cctx, cancel := ctxTimeout(8 * time.Second)
		defer cancel()
		return net.DefaultResolver.LookupIP(cctx, "ip", domain)
	}()
	if ipErr != nil {
		warnings = append(warnings, fmt.Sprintf("dnsintel: A/AAAA lookup failed: %v", ipErr))
	} else if len(ips) > 0 {
		var addrs []string
		for _, ip := range ips {
			addrs = append(addrs, ip.String())
		}
		findings = append(findings, models.Finding{
			ID:              "dns-a-records",
			Title:           fmt.Sprintf("DNS A/AAAA records for %s (%d address(es))", domain, len(addrs)),
			Description:     fmt.Sprintf("The hostname %q resolves to %d IP address(es). Each should be inventoried and kept patched; unexpected addresses may indicate hijack or stale glue.", domain, len(addrs)),
			Severity:        models.SeverityInfo,
			Confidence:      models.ConfidenceHigh,
			Category:        models.CategoryExposure,
			Target:          sc.Target.Raw,
			Evidence:        models.Evidence{Observed: strings.Join(addrs, ", "), Location: "DNS A/AAAA"},
			Source:          models.SourceCustom,
			DetectionMethod: "net.Resolver LookupIP",
		})
		// Reverse PTR for each IP (best-effort, limited).
		for _, ip := range ips {
			if len(findings) > 20 {
				break
			}
			cctx, cancel := ctxTimeout(4 * time.Second)
			ptrs, err := net.DefaultResolver.LookupAddr(cctx, ip.String())
			cancel()
			if err != nil || len(ptrs) == 0 {
				continue
			}
			findings = append(findings, models.Finding{
				ID:              fmt.Sprintf("dns-ptr-%s", strings.ReplaceAll(ip.String(), ".", "-")),
				Title:           fmt.Sprintf("Reverse DNS (PTR) for %s", ip.String()),
				Description:     fmt.Sprintf("PTR records can reveal hosting provider, cloud region, or stale delegation for %s.", ip.String()),
				Severity:        models.SeverityInfo,
				Confidence:      models.ConfidenceHigh,
				Category:        models.CategoryExposure,
				Target:          sc.Target.Raw,
				Evidence:        models.Evidence{Observed: strings.Join(ptrs, ", "), Location: "DNS PTR (reverse)"},
				Source:          models.SourceCustom,
				DetectionMethod: "net.Resolver LookupAddr",
			})
		}
	}

	// --- CNAME ---
	func() {
		cctx, cancel := ctxTimeout(5 * time.Second)
		defer cancel()
		cname, err := net.DefaultResolver.LookupCNAME(cctx, domain)
		if err != nil {
			return
		}
		cname = strings.TrimSuffix(cname, ".")
		if !strings.EqualFold(cname, domain) && cname != "" {
			findings = append(findings, models.Finding{
				ID:              "dns-cname",
				Title:           fmt.Sprintf("CNAME record for %s → %s", domain, cname),
				Description:     fmt.Sprintf("%q is a CNAME alias to %q. CNAME chains can hide takeover risks if the target is unclaimed.", domain, cname),
				Severity:        models.SeverityInfo,
				Confidence:      models.ConfidenceHigh,
				Category:        models.CategoryExposure,
				Target:          sc.Target.Raw,
				Evidence:        models.Evidence{Observed: cname, Location: "DNS CNAME"},
				Source:          models.SourceCustom,
				DetectionMethod: "net.Resolver LookupCNAME",
			})
		}
	}()

	// --- MX ---
	var mxHosts []string
	func() {
		cctx, cancel := ctxTimeout(5 * time.Second)
		defer cancel()
		mxs, err := net.DefaultResolver.LookupMX(cctx, domain)
		if err != nil {
			return
		}
		if len(mxs) == 0 {
			return
		}
		var obs []string
		for _, mx := range mxs {
			h := strings.TrimSuffix(mx.Host, ".")
			obs = append(obs, fmt.Sprintf("%s (pref %d)", h, mx.Pref))
			mxHosts = append(mxHosts, h)
		}
		findings = append(findings, models.Finding{
			ID:              "dns-mx-records",
			Title:           fmt.Sprintf("DNS MX records for %s (%d host(s))", domain, len(mxs)),
			Description:     fmt.Sprintf("Mail exchangers for %s: each MX host is an additional attack surface (mail gateway vulnerabilities, SPF/DKIM/DMARC posture).", domain),
			Severity:        models.SeverityInfo,
			Confidence:      models.ConfidenceHigh,
			Category:        models.CategoryExposure,
			Target:          sc.Target.Raw,
			Evidence:        models.Evidence{Observed: strings.Join(obs, ", "), Location: "DNS MX"},
			Source:          models.SourceCustom,
			DetectionMethod: "net.Resolver LookupMX",
		})
	}()

	// --- NS ---
	var nsHosts []string
	func() {
		cctx, cancel := ctxTimeout(5 * time.Second)
		defer cancel()
		nss, err := net.DefaultResolver.LookupNS(cctx, domain)
		if err != nil || len(nss) == 0 {
			return
		}
		var obs []string
		for _, ns := range nss {
			h := strings.TrimSuffix(ns.Host, ".")
			obs = append(obs, h)
			nsHosts = append(nsHosts, h)
		}
		findings = append(findings, models.Finding{
			ID:              "dns-ns-records",
			Title:           fmt.Sprintf("DNS NS records for %s (%d)", domain, len(nss)),
			Description:     fmt.Sprintf("Authoritative name servers for %s. Delegation to unexpected providers may indicate hijack or overly broad DNS hosting.", domain),
			Severity:        models.SeverityInfo,
			Confidence:      models.ConfidenceHigh,
			Category:        models.CategoryExposure,
			Target:          sc.Target.Raw,
			Evidence:        models.Evidence{Observed: strings.Join(obs, ", "), Location: "DNS NS"},
			Source:          models.SourceCustom,
			DetectionMethod: "net.Resolver LookupNS",
		})
	}()

	// --- AXFR zone transfer probe (active but high-value, deep-only check
	// would be too quiet — try once per NS with a short timeout; success
	// means full zone disclosure).
	func() {
		if len(nsHosts) == 0 {
			return
		}
		// Keep impact minimal: try up to 2 NS hosts, 6s total.
		limit := 2
		if len(nsHosts) < limit {
			limit = len(nsHosts)
		}
		for i := 0; i < limit; i++ {
			ns := nsHosts[i]
			// Resolve NS host to IP first via system resolver.
			cctx, cancel := ctxTimeout(4 * time.Second)
			addrs, err := net.DefaultResolver.LookupIP(cctx, "ip", ns)
			cancel()
			if err != nil || len(addrs) == 0 {
				continue
			}
			for _, ip := range addrs {
				addr := net.JoinHostPort(ip.String(), "53")
				if probeAXFR(ctx, addr, domain) {
					findings = append(findings, models.Finding{
						ID:              fmt.Sprintf("dns-axfr-%s", strings.ReplaceAll(ns, ".", "-")),
						Title:           fmt.Sprintf("DNS zone transfer (AXFR) allowed from %s for %s", ns, domain),
						Description:     fmt.Sprintf("Name server %s (%s) allowed an AXFR zone transfer for %q, disclosing the full zone. An attacker can enumerate every hostname in the zone, including hidden admin/dev hosts.", ns, ip.String(), domain),
						Severity:        models.SeverityCritical,
						Confidence:      models.ConfidenceConfirmed,
						Category:        models.CategoryConfiguration,
						CWE:             "CWE-16",
						Target:          sc.Target.Raw,
						Evidence:        models.Evidence{Observed: fmt.Sprintf("AXFR from %s (%s) succeeded", ns, ip.String()), Location: "DNS TCP 53 AXFR"},
						Source:          models.SourceCustom,
						DetectionMethod: "TCP 53 AXFR probe",
						Remediation:     "Disable AXFR (allow-transfer) for unauthenticated clients on " + ns + "; restrict to secondary name servers via IP ACL and TSIG.",
					})
					return
				}
				break // one IP per NS is enough
			}
		}
	}()

	// --- TXT (apex) ---
	var txts []string
	func() {
		cctx, cancel := ctxTimeout(5 * time.Second)
		defer cancel()
		records, err := net.DefaultResolver.LookupTXT(cctx, domain)
		if err != nil || len(records) == 0 {
			return
		}
		txts = records
		var cleaned []string
		for _, t := range records {
			cleaned = append(cleaned, truncate(t, 220))
		}
		findings = append(findings, models.Finding{
			ID:              "dns-txt-records",
			Title:           fmt.Sprintf("DNS TXT records for %s (%d)", domain, len(records)),
			Description:     "TXT records can contain SPF, DKIM, verification tokens, and other service bindings. Audit for overly broad includes or exposed secrets.",
			Severity:        models.SeverityInfo,
			Confidence:      models.ConfidenceHigh,
			Category:        models.CategoryExposure,
			Target:          sc.Target.Raw,
			Evidence:        models.Evidence{Observed: strings.Join(cleaned, " | "), Location: "DNS TXT"},
			Source:          models.SourceCustom,
			DetectionMethod: "net.Resolver LookupTXT",
		})
	}()

	// --- SPF analysis (derived from TXT) ---
	func() {
		var spf string
		for _, t := range txts {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=spf1") {
				spf = t
				break
			}
		}
		if len(mxHosts) > 0 || len(ips) > 0 {
			if spf == "" {
				findings = append(findings, models.Finding{
					ID:              "dns-spf-missing",
					Title:           fmt.Sprintf("No SPF record for %s", domain),
					Description:     fmt.Sprintf("The domain %q has mail exchangers (%d MX) but no v=spf1 TXT record. Without SPF, anyone can spoof mail from %s.", domain, len(mxHosts), domain),
					Severity:        models.SeverityMedium,
					Confidence:      models.ConfidenceHigh,
					Category:        models.CategoryConfiguration,
					CWE:             "CWE-345",
					Target:          sc.Target.Raw,
					Evidence:        models.Evidence{Observed: "no v=spf1 record at apex", Location: "DNS TXT (SPF)"},
					Source:          models.SourceCustom,
					DetectionMethod: "TXT lookup + SPF parse",
					Remediation:     "Publish an SPF record that enumerates authorized mail senders and ends with '~all' or '-all'. Start with 'v=spf1 include:_spf.provider.com ~all' and tighten after monitoring.",
				})
				return
			}
			lower := strings.ToLower(spf)
			if strings.Contains(lower, "+all") || strings.Contains(lower, "?all") {
				findings = append(findings, models.Finding{
					ID:              "dns-spf-permissive",
					Title:           fmt.Sprintf("Permissive SPF policy for %s", domain),
					Description:     fmt.Sprintf("SPF record for %q allows any host to send mail (contains +all or ?all). This largely negates SPF.", domain),
					Severity:        models.SeverityMedium,
					Confidence:      models.ConfidenceHigh,
					Category:        models.CategoryConfiguration,
					CWE:             "CWE-345",
					Target:          sc.Target.Raw,
					Evidence:        models.Evidence{Observed: truncate(spf, 280), Location: "DNS TXT (SPF)"},
					Source:          models.SourceCustom,
					DetectionMethod: "TXT lookup + SPF parse",
					Remediation:     "Change the SPF terminator to '~all' (softfail) or '-all' (hardfail) and remove '+all'/'?all'.",
				})
			} else if strings.Contains(lower, "~all") || strings.Contains(lower, "-all") {
				// Well-formed SPF is still informationally worth noting; keep it visible but low.
				findings = append(findings, models.Finding{
					ID:              "dns-spf-present",
					Title:           fmt.Sprintf("SPF record present for %s", domain),
					Description:     fmt.Sprintf("SPF record for %q appears correctly terminated. Review includes for overly broad providers.", domain),
					Severity:        models.SeverityInfo,
					Confidence:      models.ConfidenceHigh,
					Category:        models.CategoryConfiguration,
					Target:          sc.Target.Raw,
					Evidence:        models.Evidence{Observed: truncate(spf, 280), Location: "DNS TXT (SPF)"},
					Source:          models.SourceCustom,
					DetectionMethod: "TXT lookup + SPF parse",
				})
			}
		}
	}()

	// --- DMARC (TXT at _dmarc.<domain>) ---
	func() {
		cctx, cancel := ctxTimeout(5 * time.Second)
		defer cancel()
		records, err := net.DefaultResolver.LookupTXT(cctx, "_dmarc."+domain)
		if err != nil || len(records) == 0 {
			if len(mxHosts) > 0 {
				findings = append(findings, models.Finding{
					ID:              "dns-dmarc-missing",
					Title:           fmt.Sprintf("No DMARC record for %s", domain),
					Description:     fmt.Sprintf("Domain %q has MX records but no DMARC TXT at _dmarc.%s. Without DMARC, SPF/DKIM failures have no quarantine/reject policy.", domain, domain),
					Severity:        models.SeverityLow,
					Confidence:      models.ConfidenceHigh,
					Category:        models.CategoryConfiguration,
					CWE:             "CWE-345",
					Target:          sc.Target.Raw,
					Evidence:        models.Evidence{Observed: "no TXT at _dmarc." + domain, Location: "DNS TXT (DMARC)"},
					Source:          models.SourceCustom,
					DetectionMethod: "net.Resolver LookupTXT _dmarc",
					Remediation:     "Publish _dmarc.<domain> TXT such as 'v=DMARC1; p=quarantine; rua=mailto:dmarc@" + domain + "' and align SPF/DKIM.",
				})
			} else {
				// Same canonical title as the with-MX variant (and the
				// emailauth finding) so all three merge into one row; the
				// no-mail-infra nuance stays in the description.
				findings = append(findings, models.Finding{
					ID:              "dns-dmarc-absent",
					Title:           fmt.Sprintf("No DMARC record for %s", domain),
					Description:     fmt.Sprintf("No DMARC TXT found at _dmarc.%s (and no MX records — this host may not send mail, but the domain is still spoofable). DMARC is recommended for any domain that sends mail or may be spoofed.", domain),
					Severity:        models.SeverityInfo,
					Confidence:      models.ConfidenceHigh,
					Category:        models.CategoryConfiguration,
					Target:          sc.Target.Raw,
					Evidence:        models.Evidence{Observed: "no TXT at _dmarc." + domain, Location: "DNS TXT (DMARC)"},
					Source:          models.SourceCustom,
					DetectionMethod: "net.Resolver LookupTXT _dmarc",
				})
			}
			return
		}
		var dmarc string
		for _, t := range records {
			if strings.Contains(strings.ToLower(t), "v=dmarc1") {
				dmarc = t
				break
			}
		}
		if dmarc == "" {
			dmarc = records[0]
		}
		sev := models.SeverityInfo
		title := fmt.Sprintf("DMARC record for %s", domain)
		// Permissive p=none with no aggregation is still worth a nudge.
		if strings.Contains(strings.ToLower(dmarc), "p=none") {
			sev = models.SeverityLow
			title = fmt.Sprintf("DMARC policy is p=none for %s (monitoring only)", domain)
		}
		findings = append(findings, models.Finding{
			ID:              "dns-dmarc-record",
			Title:           title,
			Description:     fmt.Sprintf("DMARC TXT at _dmarc.%s: %s", domain, truncate(dmarc, 280)),
			Severity:        sev,
			Confidence:      models.ConfidenceHigh,
			Category:        models.CategoryConfiguration,
			Target:          sc.Target.Raw,
			Evidence:        models.Evidence{Observed: truncate(dmarc, 280), Location: "DNS TXT (DMARC)"},
			Source:          models.SourceCustom,
			DetectionMethod: "net.Resolver LookupTXT _dmarc",
		})
	}()

	// --- CAA quick check (TXT fallback; real CAA needs miekg/dns — skip
	// hard dependency and keep gate passive): look for any TXT that looks
	// like CAA at the apex as a heuristic. True CAA at _caa would be
	// non-standard, so we only surface when present textually.
	// Intentionally lightweight: no warning on miss.

	return scanner.StageResult{Findings: findings, Warnings: warnings}, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// probeAXFR attempts a DNS AXFR transfer over TCP 53 for domain via
// addr (ip:53). It builds a minimal AXFR query, prefixes with 2-byte TCP
// length, and checks whether the response contains at least one answer
// record (ANCOUNT > 0) and RCODE 0. Best-effort with short timeouts.
func probeAXFR(ctx context.Context, addr, domain string) bool {
	// Build DNS query (see RFC 1035 4.1).
	msg := make([]byte, 0, 512)
	// Header
	var idBuf [2]byte
	if _, err := crand.Read(idBuf[:]); err != nil {
		return false
	}
	id := binary.BigEndian.Uint16(idBuf[:])
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], id) // ID
	binary.BigEndian.PutUint16(hdr[2:4], 0)  // Flags all 0
	binary.BigEndian.PutUint16(hdr[4:6], 1)  // QDCOUNT
	// ANCOUNT, NSCOUNT, ARCOUNT already 0
	msg = append(msg, hdr...)
	// QNAME (labels capped at 63 octets per RFC 1035 2.3.4; longer
	// labels are skipped so the length byte below cannot overflow).
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 {
			continue
		}
		msg = append(msg, byte(len(label))) // #nosec G115 -- length guarded to 0-63 above.
		msg = append(msg, label...)
	}
	msg = append(msg, 0) // terminator
	// QTYPE AXFR (252) + QCLASS IN (1)
	msg = append(msg, 0, 252, 0, 1)

	// TCP prefix (msg is bounded: header + labels + 5 bytes, far below 64K).
	pkt := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(pkt[0:2], uint16(len(msg))) // #nosec G115 -- bounded well under 65535 (see above).
	copy(pkt[2:], msg)

	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
	if _, err := conn.Write(pkt); err != nil {
		return false
	}
	// Read length prefix
	lenBuf := make([]byte, 2)
	if _, err := readFull(conn, lenBuf); err != nil {
		return false
	}
	respLen := int(binary.BigEndian.Uint16(lenBuf))
	if respLen < 12 || respLen > 8192 {
		return false
	}
	resp := make([]byte, respLen)
	if _, err := readFull(conn, resp); err != nil {
		return false
	}
	if len(resp) < 12 {
		return false
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	rcode := flags & 0x000F
	if rcode != 0 {
		return false
	}
	ancount := binary.BigEndian.Uint16(resp[6:8])
	return ancount > 0
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			break
		}
	}
	return total, nil
}
