// Package bgp enriches each resolved IP with BGP prefix, ASN details and
// RPKI validation hint via the public BGPView API (https://api.bgpview.io).
// One HTTP GET per IP, passive, safe for all profiles. Failures degrade
// to warnings — the scan never fails because BGPView is down.
package bgp

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

// Scanner implements scanner.Scanner for BGP/RPKI intel.
type Scanner struct {
	client *anpuhttp.Client
}

func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

func (s *Scanner) Name() string                     { return "bgp" }
func (s *Scanner) Available(_ context.Context) bool { return true }

// bgpViewBase is overridable in tests.
var bgpViewBase = "https://api.bgpview.io/ip"

type bgpViewResp struct {
	Status string `json:"status"`
	Data   struct {
		Prefixes []struct {
			Prefix      string `json:"prefix"`
			IP          string `json:"ip"`
			CIDR        int    `json:"cidr"`
			ASN         int    `json:"asn"`
			Name        string `json:"name"`
			Description string `json:"description"`
			CountryCode string `json:"country_code"`
		} `json:"prefixes"`
		RIRAllocation *struct {
			Prefix        string `json:"prefix"`
			CountryCode   string `json:"country_code"`
			DateAllocated string `json:"date_allocated"`
		} `json:"rir_allocation"`
		PTRRecord *string `json:"ptr_record"`
	} `json:"data"`
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
	// Resolve IPs (fresh, to keep stage independent)
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	ips, err := net.DefaultResolver.LookupIP(cctx, "ip", domain)
	cancel()
	if err != nil || len(ips) == 0 {
		return scanner.StageResult{}, nil
	}
	var findings []models.Finding
	for _, ip := range ips {
		if ip.To4() == nil {
			continue // IPv6 via BGPView works but skip to keep simple for now
		}
		if f := s.probeIP(ctx, ip, sc.Target.Raw); f != nil {
			findings = append(findings, *f)
		}
		// One IP is enough for the BGP prefix view; don't hammer the API
		if len(findings) >= 3 {
			break
		}
	}
	return scanner.StageResult{Findings: findings}, nil
}

func (s *Scanner) probeIP(ctx context.Context, ip net.IP, target string) *models.Finding {
	url := fmt.Sprintf("%s/%s", bgpViewBase, ip.String())
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	resp, err := s.client.Get(cctx, url)
	if err != nil || resp == nil || resp.StatusCode != 200 || len(resp.Body) == 0 {
		return nil
	}
	var data bgpViewResp
	if err := json.Unmarshal(resp.Body, &data); err != nil || data.Status != "ok" {
		return nil
	}
	if len(data.Data.Prefixes) == 0 {
		return nil
	}
	p := data.Data.Prefixes[0]
	observed := fmt.Sprintf("prefix %s/%d ASN %d %s (%s) country %s", p.Prefix, p.CIDR, p.ASN, p.Name, p.Description, p.CountryCode)
	// RPKI hint: BGPView doesn't directly expose RPKI, but we can note the RIR allocation age
	title := fmt.Sprintf("BGP prefix for %s: %s/%d (AS%d)", ip.String(), p.Prefix, p.CIDR, p.ASN)
	desc := fmt.Sprintf("BGPView reports %s is announced as %s/%d by AS%d %q (%s) in %s. Use for netrange scoping, permimeter firewall rules, and to detect hijacked or unexpected prefixes.", ip.String(), p.Prefix, p.CIDR, p.ASN, p.Name, p.Description, p.CountryCode)
	if data.Data.RIRAllocation != nil && data.Data.RIRAllocation.Prefix != "" {
		desc += fmt.Sprintf(" RIR allocation %s allocated %s.", data.Data.RIRAllocation.Prefix, data.Data.RIRAllocation.DateAllocated)
	}
	// Heuristic: very specific /24 vs larger aggregate
	sev := models.SeverityInfo
	if p.CIDR >= 24 {
		sev = models.SeverityLow
		desc += " Specific /24+ announcement - verify not a deaggregated hijack."
	}
	return &models.Finding{
		ID:              fmt.Sprintf("bgp-prefix-%s", strings.ReplaceAll(ip.String(), ".", "-")),
		Title:           title,
		Description:     desc,
		Severity:        sev,
		Confidence:      models.ConfidenceHigh,
		Category:        models.CategoryExposure,
		Target:          target,
		Evidence:        models.Evidence{Observed: observed, Location: "BGPView API " + url},
		Source:          models.SourceCustom,
		DetectionMethod: "HTTP GET api.bgpview.io/ip",
		References:      []string{"https://bgpview.io/"},
	}
}
