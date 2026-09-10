// Package ipintel enriches each resolved IP of the target with reverse
// PTR, cloud/hosting fingerprints, and ASN via Team Cymru's DNS service.
// It is passive (only DNS) and safe for all profiles. Warnings are
// best-effort — the scan never fails because an ASN lookup timed out.
package ipintel

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// Scanner implements scanner.Scanner for IP intelligence.
type Scanner struct {
	client *anpuhttp.Client
}

func New() *Scanner { return &Scanner{} }

// NewWithClient is the pipeline constructor (needs HTTP for IP RDAP).
func NewWithClient(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

func (s *Scanner) Name() string                     { return "ipintel" }
func (s *Scanner) Available(_ context.Context) bool { return true }

// cloudHints maps lower-cased PTR substrings to a provider label.
var cloudHints = []struct {
	hit  string
	name string
}{
	{"amazonaws.com", "Amazon Web Services"},
	{".aws", "Amazon Web Services"},
	{"ec2.", "Amazon Web Services"},
	{"google", "Google Cloud"},
	{"goog ", "Google Cloud"},
	{"gcp", "Google Cloud"},
	{"cloudflare", "Cloudflare"},
	{"fastly", "Fastly"},
	{"akamai", "Akamai"},
	{"azure", "Microsoft Azure"},
	{"microsoft", "Microsoft Azure"},
	{"ovh", "OVH"},
	{"hetzner", "Hetzner"},
	{"digitalocean", "DigitalOcean"},
	{"linode", "Akamai/Linode"},
	{"vultr", "Vultr"},
	{"contabo", "Contabo"},
	{"alibaba", "Alibaba Cloud"},
	{"tencent", "Tencent Cloud"},
}

func detectProvider(ptrs []string) string {
	for _, p := range ptrs {
		lower := strings.ToLower(p)
		for _, h := range cloudHints {
			if strings.Contains(lower, h.hit) {
				return h.name
			}
		}
	}
	return ""
}

// ipRdapBase is the RDAP gateway for IP lookups, overridable in tests.
var ipRdapBase = "https://rdap.org/ip"

// asnForIP asks Team Cymru (origin.asn.cymru.com) for the ASN of ip.
// Format per https://team-cymru.com/community-services.html : for IPv4
// query "<reversed>.origin.asn.cymru.com" TXT -> "ASN | prefix | CC | registry | date".
// Returns empty on any error (best-effort).
func asnForIP(ctx context.Context, ip net.IP) string {
	if ip == nil || ip.To4() == nil {
		// IPv6 ASN via Cymru uses different zone (origin6) — skip to keep simple.
		return ""
	}
	parts := strings.Split(ip.String(), ".")
	if len(parts) != 4 {
		return ""
	}
	rev := fmt.Sprintf("%s.%s.%s.%s.origin.asn.cymru.com", parts[3], parts[2], parts[1], parts[0])
	cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	txts, err := net.DefaultResolver.LookupTXT(cctx, rev)
	if err != nil || len(txts) == 0 {
		return ""
	}
	// First TXT is the ASN line; keep it trimmed.
	return strings.TrimSpace(txts[0])
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

	// Resolve IPs fresh (dnsintel also does, but ipintel is independent
	// so stage order doesn't create hard coupling).
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	ips, err := net.DefaultResolver.LookupIP(cctx, "ip", domain)
	cancel()
	if err != nil || len(ips) == 0 {
		return scanner.StageResult{}, nil
	}

	var findings []models.Finding
	for _, ip := range ips {
		// PTR
		var ptrs []string
		func() {
			cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
			defer cancel()
			if names, err := net.DefaultResolver.LookupAddr(cctx, ip.String()); err == nil {
				ptrs = names
			}
		}()

		provider := detectProvider(ptrs)

		// Base IP finding (always emitted so the network inventory is visible).
		desc := fmt.Sprintf("IP %s for %q", ip.String(), domain)
		if provider != "" {
			desc += fmt.Sprintf(" (hosted on %s per PTR)", provider)
		} else if len(ptrs) > 0 {
			desc += fmt.Sprintf(" (PTR: %s)", strings.Join(ptrs, ", "))
		}
		findings = append(findings, models.Finding{
			ID:              fmt.Sprintf("ipintel-ip-%s", strings.ReplaceAll(ip.String(), ".", "-")),
			Title:           fmt.Sprintf("IP hosting %s: %s", domain, ip.String()),
			Description:     desc,
			Severity:        models.SeverityInfo,
			Confidence:      models.ConfidenceHigh,
			Category:        models.CategoryExposure,
			Target:          sc.Target.Raw,
			Evidence:        models.Evidence{Observed: ip.String(), Location: "DNS A/AAAA + PTR"},
			Source:          models.SourceCustom,
			DetectionMethod: "net.Resolver LookupIP + LookupAddr",
			References:      []string{},
		})

		if provider != "" {
			findings = append(findings, models.Finding{
				ID:              fmt.Sprintf("ipintel-provider-%s", strings.ReplaceAll(ip.String(), ".", "-")),
				Title:           fmt.Sprintf("Hosting provider for %s: %s", ip.String(), provider),
				Description:     fmt.Sprintf("Reverse DNS for %s indicates hosting on %s. Use provider-specific hardening (WAF, origin protection, bucket policies) for this surface.", ip.String(), provider),
				Severity:        models.SeverityInfo,
				Confidence:      models.ConfidenceHigh,
				Category:        models.CategoryTechnology,
				Target:          sc.Target.Raw,
				Evidence:        models.Evidence{Observed: strings.Join(ptrs, ", "), Location: "DNS PTR"},
				Source:          models.SourceCustom,
				DetectionMethod: "PTR keyword fingerprint",
			})
		}

		// ASN via Cymru (best-effort)
		if asn := asnForIP(ctx, ip); asn != "" {
			findings = append(findings, models.Finding{
				ID:              fmt.Sprintf("ipintel-asn-%s", strings.ReplaceAll(ip.String(), ".", "-")),
				Title:           fmt.Sprintf("ASN for %s", ip.String()),
				Description:     fmt.Sprintf("Autonomous System info for %s: %s (via Team Cymru). Useful for scoping network ranges belonging to the same owner.", ip.String(), asn),
				Severity:        models.SeverityInfo,
				Confidence:      models.ConfidenceHigh,
				Category:        models.CategoryExposure,
				Target:          sc.Target.Raw,
				Evidence:        models.Evidence{Observed: asn, Location: "DNS TXT origin.asn.cymru.com"},
				Source:          models.SourceCustom,
				DetectionMethod: "Team Cymru ASN TXT lookup",
			})
		}

		// IP RDAP (best-effort, needs HTTP client)
		if s.client != nil {
			if f := fetchIPRDAP(ctx, s.client, ip); f != nil {
				f.Target = sc.Target.Raw
				findings = append(findings, *f)
			}
		}
	}

	return scanner.StageResult{Findings: findings}, nil
}

// fetchIPRDAP queries rdap.org for IP registration. Returns a single
// informational finding with handle/name/country, or nil on any error.
func fetchIPRDAP(ctx context.Context, client *anpuhttp.Client, ip net.IP) *models.Finding {
	url := ipRdapBase + "/" + ip.String()
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	resp, err := client.Get(cctx, url)
	if err != nil || resp == nil || resp.StatusCode != 200 || len(resp.Body) == 0 {
		return nil
	}
	var doc struct {
		Handle   string `json:"handle"`
		Name     string `json:"name"`
		Country  string `json:"country"`
		Entities []struct {
			Roles      []string `json:"roles"`
			VCardArray []any    `json:"vcardArray"`
		} `json:"entities"`
		CIDR         string `json:"cidr0_cidrs"`
		StartAddress string `json:"startAddress"`
		EndAddress   string `json:"endAddress"`
		IPVersion    string `json:"ipVersion"`
	}
	// Some RDAP IP responses use startAddress/endAddress, others use cidr0_cidrs array.
	// Try generic decode: keep raw for evidence.
	var raw map[string]any
	if err := json.Unmarshal(resp.Body, &raw); err != nil {
		return nil
	}
	// Re-marshal into struct for known fields
	b, _ := json.Marshal(raw)
	_ = json.Unmarshal(b, &doc)

	handle := doc.Handle
	if handle == "" {
		if h, ok := raw["handle"].(string); ok {
			handle = h
		}
	}
	name := doc.Name
	if name == "" {
		if n, ok := raw["name"].(string); ok {
			name = n
		}
	}
	country := doc.Country
	if country == "" {
		if c, ok := raw["country"].(string); ok {
			country = c
		}
	}
	// Try to extract org from entities registrant
	if name == "" {
		for _, e := range doc.Entities {
			for _, r := range e.Roles {
				if r == "registrant" || r == "admin" {
					if len(e.VCardArray) >= 2 {
						if arr, ok := e.VCardArray[1].([]any); ok {
							for _, item := range arr {
								if triple, ok := item.([]any); ok && len(triple) >= 4 {
									if n, ok := triple[0].(string); ok && n == "fn" {
										if v, ok := triple[3].(string); ok && v != "" {
											name = v
											break
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	observed := handle
	if observed == "" {
		observed = name
	}
	if observed == "" {
		observed = doc.StartAddress + " - " + doc.EndAddress
		if observed == " - " {
			observed = ip.String()
		}
	}
	title := fmt.Sprintf("IP RDAP for %s", ip.String())
	if name != "" {
		title = fmt.Sprintf("IP %s — %s", ip.String(), name)
	}
	desc := fmt.Sprintf("RDAP for %s: handle %q, name %q, country %q, range %s - %s. Use for abuse contact and netrange scoping.", ip.String(), handle, name, country, doc.StartAddress, doc.EndAddress)
	if handle == "" && name == "" {
		desc = fmt.Sprintf("RDAP info for %s available at %s (handle/name not parsed). Range %s - %s.", ip.String(), url, doc.StartAddress, doc.EndAddress)
	}
	return &models.Finding{
		ID:              fmt.Sprintf("ipintel-rdap-%s", strings.ReplaceAll(ip.String(), ".", "-")),
		Title:           title,
		Description:     desc,
		Severity:        models.SeverityInfo,
		Confidence:      models.ConfidenceHigh,
		Category:        models.CategoryExposure,
		Evidence:        models.Evidence{Observed: observed, Location: "RDAP " + url},
		Source:          models.SourceCustom,
		DetectionMethod: "HTTP GET RDAP IP",
	}
}
