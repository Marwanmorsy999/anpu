// Package rdap fetches domain registration intelligence via RDAP (Registration
// Data Access Protocol), the JSON successor to classic WHOIS port-43.
//
// It queries a public RDAP gateway (rdap.org, which federates to the
// authoritative registry) so no API key is needed. One HTTP GET, fully
// passive — safe for every profile. Failures degrade to a warning.
package rdap

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// rdapBase is the RDAP gateway base URL, overridable in tests.
var rdapBase = "https://rdap.org/domain"

// Scanner implements scanner.Scanner for RDAP WHOIS.
type Scanner struct {
	client *anpuhttp.Client
}

func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

func (s *Scanner) Name() string                     { return "rdap" }
func (s *Scanner) Available(_ context.Context) bool { return true }

// rdapDoc is the minimal subset of an RDAP domain response ANPU surfaces.
// Registries differ in `events` names ("registration" vs "creation"), so
// both are probed.
type rdapDoc struct {
	Handle      string   `json:"handle"`
	LDHName     string   `json:"ldhName"`
	UnicodeName string   `json:"unicodeName"`
	Status      []string `json:"status"`
	Events      []struct {
		EventAction string `json:"eventAction"`
		EventDate   string `json:"eventDate"`
	} `json:"events"`
	Entities []struct {
		Roles      []string `json:"roles"`
		VCardArray []any    `json:"vcardArray"`
	} `json:"entities"`
	Nameservers []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
	SecureDNS *struct {
		DelegationSigned *bool `json:"delegationSigned"`
	} `json:"secureDNS"`
	Port43 string `json:"port43"`
}

func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	domain := sc.Target.Host
	if domain == "" || net.ParseIP(domain) != nil {
		return scanner.StageResult{}, nil
	}
	lower := strings.ToLower(strings.TrimSuffix(domain, "."))
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return scanner.StageResult{}, nil
	}

	// RDAP is only meaningful for registrable domains. Public-suffix
	// trimming is handled by rdap.org's federation, so we just query
	// the host as-is; registries that don't serve the exact label
	// return 404 which we degrade to a warning.
	url := rdapBase + "/" + domain
	cctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	resp, err := s.client.Get(cctx, url)
	if err != nil {
		return scanner.StageResult{Warnings: []string{fmt.Sprintf("rdap: fetch %q failed: %v", domain, err)}}, nil
	}
	if resp.StatusCode != 200 || len(resp.Body) == 0 {
		return scanner.StageResult{Warnings: []string{fmt.Sprintf("rdap: %q returned HTTP %d", domain, resp.StatusCode)}}, nil
	}
	var doc rdapDoc
	if err := json.Unmarshal(resp.Body, &doc); err != nil {
		return scanner.StageResult{Warnings: []string{fmt.Sprintf("rdap: decoding response for %q: %v", domain, err)}}, nil
	}

	var findings []models.Finding

	// Summary: handle, status, unicode name.
	if doc.Handle != "" || len(doc.Status) > 0 || doc.LDHName != "" {
		observed := fmt.Sprintf("handle=%s status=[%s] ldhName=%s", doc.Handle, strings.Join(doc.Status, ","), doc.LDHName)
		findings = append(findings, models.Finding{
			ID:              "rdap-domain-summary",
			Title:           fmt.Sprintf("RDAP registration for %s", domain),
			Description:     fmt.Sprintf("Domain %q RDAP: handle %q, status %v, authoritative name %q.", domain, doc.Handle, doc.Status, doc.LDHName),
			Severity:        models.SeverityInfo,
			Confidence:      models.ConfidenceHigh,
			Category:        models.CategoryExposure,
			Target:          sc.Target.Raw,
			Evidence:        models.Evidence{Observed: observed, Location: "RDAP " + rdapBase + "/" + domain},
			Source:          models.SourceCustom,
			DetectionMethod: "HTTP GET RDAP JSON",
		})
	}

	// Registrar via first entity with role registrar.
	if registrar := extractRegistrar(&doc); registrar != "" {
		findings = append(findings, models.Finding{
			ID:              "rdap-registrar",
			Title:           fmt.Sprintf("Registrar for %s: %s", domain, registrar),
			Description:     fmt.Sprintf("Domain %q is registered via %q (RDAP registrar entity). Useful for scoping ownership and phishing Lookalike comparisons.", domain, registrar),
			Severity:        models.SeverityInfo,
			Confidence:      models.ConfidenceHigh,
			Category:        models.CategoryExposure,
			Target:          sc.Target.Raw,
			Evidence:        models.Evidence{Observed: registrar, Location: "RDAP entities / registrar"},
			Source:          models.SourceCustom,
			DetectionMethod: "RDAP entity vCard",
		})
	}

	// Events: registration/creation, expiration, last changed
	if ev := extractEvent(&doc, "registration", "creation"); ev != "" {
		findings = append(findings, models.Finding{
			ID:              "rdap-creation",
			Title:           fmt.Sprintf("Domain %s created %s", domain, ev),
			Description:     fmt.Sprintf("Domain %q creation/registration date per RDAP: %s. Young domains are higher phishing risk.", domain, ev),
			Severity:        models.SeverityInfo,
			Confidence:      models.ConfidenceHigh,
			Category:        models.CategoryExposure,
			Target:          sc.Target.Raw,
			Evidence:        models.Evidence{Observed: ev, Location: "RDAP events / registration"},
			Source:          models.SourceCustom,
			DetectionMethod: "RDAP events",
		})
	}
	if ev := extractEvent(&doc, "expiration"); ev != "" {
		findings = append(findings, models.Finding{
			ID:              "rdap-expiration",
			Title:           fmt.Sprintf("Domain %s expires %s", domain, ev),
			Description:     fmt.Sprintf("RDAP expiration for %q: %s. Near-expiry domains risk takeover if not renewed.", domain, ev),
			Severity:        models.SeverityInfo,
			Confidence:      models.ConfidenceHigh,
			Category:        models.CategoryExposure,
			Target:          sc.Target.Raw,
			Evidence:        models.Evidence{Observed: ev, Location: "RDAP events / expiration"},
			Source:          models.SourceCustom,
			DetectionMethod: "RDAP events",
		})
	}

	// Nameservers
	if len(doc.Nameservers) > 0 {
		var ns []string
		for _, n := range doc.Nameservers {
			ns = append(ns, strings.TrimSuffix(n.LDHName, "."))
		}
		findings = append(findings, models.Finding{
			ID:              "rdap-nameservers",
			Title:           fmt.Sprintf("RDAP name servers for %s (%d)", domain, len(ns)),
			Description:     fmt.Sprintf("Delegated name servers per RDAP: %s. Compare with DNS NS to detect delegation mismatch.", strings.Join(ns, ", ")),
			Severity:        models.SeverityInfo,
			Confidence:      models.ConfidenceHigh,
			Category:        models.CategoryExposure,
			Target:          sc.Target.Raw,
			Evidence:        models.Evidence{Observed: strings.Join(ns, ", "), Location: "RDAP nameservers"},
			Source:          models.SourceCustom,
			DetectionMethod: "RDAP nameservers array",
		})
	}

	// DNSSEC
	if doc.SecureDNS != nil && doc.SecureDNS.DelegationSigned != nil {
		signed := *doc.SecureDNS.DelegationSigned
		title := fmt.Sprintf("DNSSEC not signed for %s", domain)
		sev := models.SeverityInfo
		desc := fmt.Sprintf("RDAP secureDNS.delegationSigned is %v for %q. Unsigned delegations are more vulnerable to DNS spoofing.", signed, domain)
		if signed {
			title = fmt.Sprintf("DNSSEC signed delegation for %s", domain)
			desc = fmt.Sprintf("RDAP reports DNSSEC delegationSigned=true for %q.", domain)
		} else if strings.HasSuffix(strings.ToLower(domain), ".com") || strings.HasSuffix(strings.ToLower(domain), ".net") {
			sev = models.SeverityLow
		}
		findings = append(findings, models.Finding{
			ID:              "rdap-dnssec",
			Title:           title,
			Description:     desc,
			Severity:        sev,
			Confidence:      models.ConfidenceHigh,
			Category:        models.CategoryConfiguration,
			Target:          sc.Target.Raw,
			Evidence:        models.Evidence{Observed: fmt.Sprintf("delegationSigned=%v", signed), Location: "RDAP secureDNS"},
			Source:          models.SourceCustom,
			DetectionMethod: "RDAP secureDNS",
		})
	}

	return scanner.StageResult{Findings: findings}, nil
}

func extractRegistrar(doc *rdapDoc) string {
	for _, e := range doc.Entities {
		for _, r := range e.Roles {
			if strings.EqualFold(r, "registrar") {
				// vCardArray is [ "vcard", [ [ "fn", {}, "text", "Name" ], ... ] ]
				if len(e.VCardArray) >= 2 {
					if arr, ok := e.VCardArray[1].([]any); ok {
						for _, item := range arr {
							if triple, ok := item.([]any); ok && len(triple) >= 4 {
								if name, ok := triple[0].(string); ok && strings.EqualFold(name, "fn") {
									if val, ok := triple[3].(string); ok && val != "" {
										return val
									}
								}
							}
						}
					}
				}
				return "(registrar entity present — name not parsed)"
			}
		}
	}
	return ""
}

func extractEvent(doc *rdapDoc, want ...string) string {
	wantSet := map[string]bool{}
	for _, w := range want {
		wantSet[strings.ToLower(w)] = true
	}
	for _, ev := range doc.Events {
		if wantSet[strings.ToLower(ev.EventAction)] {
			return ev.EventDate
		}
	}
	return ""
}
