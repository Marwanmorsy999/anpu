// Package nsecwalk enumerates DNS zones via NSEC chaining (Wave 2 item
// 2): from the zone apex it follows NSEC NextDomain pointers, keeping
// only in-scope names, up to 40 iterations. NSEC3-signed zones (hashed,
// non-enumerative) are detected and reported once without walking.
// DNS-only, zero target HTTP, short timeouts; failures degrade to
// warnings, never errors.
package nsecwalk

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
	"github.com/miekg/dns"
)

// Bounds: apex discovery strips + walk iterations + per-query timeout.
const (
	maxStrips = 4
	maxWalk   = 40
)

var (
	dnsTimeout = 5 * time.Second
	// resolverAddr honors ANPU_DNS_RESOLVER (host or host:port) so labs
	// and offline fixtures can point the walker at an internal resolver.
	resolverAddr = pickResolver()
)

func pickResolver() string {
	if v := strings.TrimSpace(os.Getenv("ANPU_DNS_RESOLVER")); v != "" {
		if strings.Contains(v, ":") {
			return v
		}
		return net.JoinHostPort(v, "53")
	}
	return "8.8.8.8:53"
}

// Scanner implements scanner.Scanner.
type Scanner struct{}

// New builds a Scanner.
func New() *Scanner { return &Scanner{} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "nsecwalk" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

// baseDomain returns the registrable base (pure, tested via behavior).
func baseDomain(host string) string {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	parts := strings.Split(h, ".")
	if len(parts) < 2 {
		return h
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func query(rrtype uint16, name, server string) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), rrtype)
	c := new(dns.Client)
	c.Timeout = dnsTimeout
	if strings.HasPrefix(server, "[") || strings.Count(server, ":") > 1 {
		server = "[" + strings.Trim(server, "[]") + "]:53"
	} else if !strings.Contains(server, ":") {
		server = net.JoinHostPort(server, "53")
	}
	resp, _, err := c.Exchange(m, server)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// apexSOA walks up from host to the zone apex carrying an SOA.
func apexSOA(host string) (string, error) {
	name := strings.ToLower(strings.TrimSuffix(host, "."))
	for i := 0; i <= maxStrips; i++ {
		resp, err := query(dns.TypeSOA, name, resolverAddr)
		if err == nil {
			for _, a := range resp.Answer {
				if _, ok := a.(*dns.SOA); ok {
					return name, nil
				}
			}
		}
		if idx := strings.Index(name, "."); idx >= 0 {
			name = name[idx+1:]
		} else {
			break
		}
	}
	return "", fmt.Errorf("no SOA found above %s", host)
}

// resolveHost returns A/AAAA addresses via the configured resolver.
func resolveHost(host string) []string {
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return []string{ip.String()}
	}
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		resp, err := query(qtype, host, resolverAddr)
		if err != nil || resp == nil {
			continue
		}
		var out []string
		for _, a := range resp.Answer {
			switch rr := a.(type) {
			case *dns.A:
				out = append(out, rr.A.String())
			case *dns.AAAA:
				out = append(out, rr.AAAA.String())
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return nil
}

// nameservers returns NS hostnames for the apex.
func nameservers(apex string) []string {
	resp, err := query(dns.TypeNS, apex, resolverAddr)
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range resp.Answer {
		if ns, ok := a.(*dns.NS); ok {
			out = append(out, strings.TrimSuffix(ns.Ns, "."))
		}
	}
	return out
}

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	host := strings.ToLower(strings.TrimSuffix(sc.Target.Host, "."))
	if host == "" || net.ParseIP(host) != nil || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return scanner.StageResult{}, nil
	}
	base := baseDomain(host)
	apex, err := apexSOA(host)
	if err != nil {
		return scanner.StageResult{}, nil // silent: nothing to walk
	}
	nss := nameservers(apex)
	if len(nss) == 0 {
		return scanner.StageResult{Warnings: []string{"nsecwalk: no nameservers for " + apex}}, nil
	}
	// Resolve NS hostnames to IPs via the configured resolver first —
	// dialing names would depend on system DNS. First responsive IP wins.
	ns := ""
	for _, candidate := range nss {
		for _, ip := range resolveHost(candidate) {
			ns = ip
			break
		}
		if ns != "" {
			break
		}
	}
	if ns == "" {
		return scanner.StageResult{Warnings: []string{"nsecwalk: nameservers unresolvable for " + apex}}, nil
	}

	// NSEC3 check first: hashed zones cannot be walked.
	if resp, err := query(dns.TypeNSEC3PARAM, apex, ns); err == nil {
		for _, a := range resp.Answer {
			if _, ok := a.(*dns.NSEC3PARAM); ok {
				return scanner.StageResult{Findings: []models.Finding{{
					ID: "nsecwalk-nsec3", Title: "Zone uses NSEC3 (enumeration-resistant)",
					Description: fmt.Sprintf("The zone at %s publishes NSEC3PARAM: names are hashed, so NSEC walking cannot enumerate it. No action needed — this is the hardened posture. Reproduce: dig NSEC3PARAM %s @%s.", apex, apex, ns),
					Severity:    models.SeverityInfo, Confidence: models.ConfidenceHigh, Category: models.CategoryExposure,
					Target:   sc.Target.Raw,
					Evidence: models.Evidence{Observed: "NSEC3PARAM present", Location: "DNS"},
					Source:   models.SourceRecon, DetectionMethod: "NSEC3PARAM probe (nsecwalk, DNS-only)",
				}}}, nil
			}
		}
	}

	seen := map[string]bool{}
	var names []string
	current := apex
	for i := 0; i < maxWalk; i++ {
		select {
		case <-ctx.Done():
			return scanner.StageResult{Subdomains: names}, nil
		default:
		}
		resp, err := query(dns.TypeNSEC, current, ns)
		if err != nil || resp == nil {
			break
		}
		advanced := false
		for _, a := range resp.Answer {
			nsec, ok := a.(*dns.NSEC)
			if !ok {
				continue
			}
			next := strings.ToLower(strings.TrimSuffix(nsec.NextDomain, "."))
			owner := strings.ToLower(strings.TrimSuffix(nsec.Hdr.Name, "."))
			for _, n := range []string{owner, next} {
				if !seen[n] && n != "" && (strings.EqualFold(n, base) || strings.HasSuffix(n, "."+base)) {
					seen[n] = true
					names = append(names, n)
				}
			}
			if strings.EqualFold(next, apex) || seen[next+":v"] {
				advanced = true
				current = ""
				break
			}
			seen[next+":v"] = true
			current = next
			advanced = true
			break
		}
		if !advanced || current == "" {
			break
		}
	}
	if len(names) == 0 {
		return scanner.StageResult{}, nil
	}
	sort.Strings(names)
	shown := names
	if len(shown) > 10 {
		shown = shown[:10]
	}
	return scanner.StageResult{Subdomains: names, Findings: []models.Finding{{
		ID: "nsecwalk-chain", Title: fmt.Sprintf("NSEC walking enumerated %d in-scope name(s)", len(names)),
		Description: fmt.Sprintf("The zone at %s is NSEC-signed without NSEC3: chaining NextDomain pointers disclosed %d names (e.g. %s). Migrate to NSEC3 or accept the exposure — every name is public DNS data. Reproduce: dig NSEC %s @%s and follow.", apex, len(names), strings.Join(shown, ", "), apex, ns),
		Severity:    models.SeverityInfo, Confidence: models.ConfidenceHigh, Category: models.CategoryExposure,
		Target:   sc.Target.Raw,
		Evidence: models.Evidence{Observed: strings.Join(shown, ", "), Location: "DNS NSEC chain"},
		Source:   models.SourceRecon, DetectionMethod: "NSEC chain walk, ≤40 hops (nsecwalk, DNS-only)",
		Remediation: "Deploy NSEC3 (RFC 5155) with opt-out/salted hashing.",
	}}}, nil
}
