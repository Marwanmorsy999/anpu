// Package takeoverplus extends subdomain-takeover coverage (Wave 1 item
// 24): 30 additional provider fingerprints in the dnsReaper family,
// evaluated against sc.Subdomains (populated by Subdomains, Subfinder,
// CertSAN, CSPRecon). For each candidate it resolves the CNAME chain;
// on a provider-pattern match it GETs the hostname and requires the
// provider's dangling marker in the body. Both signals are required —
// DNS-only or body-only never reports.
//
// NXDOMAIN + matching CNAME without HTTP confirmation is an Info
// "dangling CNAME" note at most. Bounded: 20 subdomains, 1 GET each.
package takeoverplus

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// maxHosts bounds DNS + HTTP work per scan.
const maxHosts = 20

type fingerprint struct {
	provider string
	cname    string // required CNAME substring (lowercase)
	marker   string // required body marker (lowercase)
}

// fingerprints ports the dnsReaper provider set beyond the 21 built-in
// takeovers: each entry needs a CNAME match AND a body marker.
func fingerprints() []fingerprint {
	return []fingerprint{
		{"Azure Websites", "azurewebsites.net", "404 web site not found"},
		{"Azure CDN", "azureedge.net", "the resource you are looking for has been removed"},
		{"AWS S3", "s3.amazonaws.com", "nosuchbucket"},
		{"AWS Elastic Beanstalk", "elasticbeanstalk.com", "404 not found"},
		{"Heroku", "heroku", "no such app"},
		{"GitHub Pages", "github.io", "there isn't a github pages site here"},
		{"Shopify", "myshopify.com", "sorry, this shop is currently unavailable"},
		{"Tumblr", "domains.tumblr.com", "whatever you were looking for doesn't currently exist"},
		{"WordPress", "wordpress.com", "do you want to register"},
		{"Bitbucket", "bitbucket.io", "repository not found"},
		{"Ghost", "ghost.io", "the thing you were looking for is no longer here"},
		{"Helpjuice", "helpjuice.com", "we could not find what you're looking for"},
		{"Tilda", "tilda.ws", "please renew your subscription"},
		{"Unbounce", "unbouncepages.com", "the requested url was not found on this server"},
		{"Webflow", "proxy.webflow.com", "the page you are looking for doesn't exist"},
		{"Pantheon", "pantheonsite.io", "404 error: site not found"},
		{"Surge", "surge.sh", "project not found"},
		{"Netlify", "netlify.app", "not found - request id:"},
		{"Firebase", "firebaseapp.com", "site not found"},
		{"Statuspage", "statuspage.io", "you are being redirected"},
		{"Zendesk", "zendesk.com", "help center closed"},
		{"Freshdesk", "freshdesk.com", "may have been moved"},
		{"Intercom", "custom.intercom.help", "this help center does not exist"},
		{"Readme.io", "readme.io", "project not found"},
		{"Strikingly", "s.strikinglydns.com", "page not found"},
		{"Wix", "wixdns.net", "error 404"},
		{"Weebly", "weebly.com", "the page you are looking for cannot be found"},
		{"Cargo", "cargocollective.com", "404 not found"},
		{"Uservoice", "uservoice.com", "this uservoice subdomain is currently available"},
		{"Brightcove", "bcvp0rtal.com", "error_code"},
	}
}

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
	// lookupCNAME and fetch are overridable in tests.
	lookupCNAME func(host string) (string, error)
	fetch       func(ctx context.Context, rawurl string) (int, string)
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner {
	s := &Scanner{client: client}
	s.lookupCNAME = net.LookupCNAME
	s.fetch = func(ctx context.Context, rawurl string) (int, string) {
		cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		resp, err := s.client.Get(cctx, rawurl)
		if err != nil || resp == nil {
			return 0, ""
		}
		return resp.StatusCode, strings.ToLower(string(resp.Body))
	}
	return s
}

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "takeoverplus" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	subs := sc.Subdomains
	sort.Strings(subs)
	if len(subs) > maxHosts {
		subs = subs[:maxHosts]
	}
	fps := fingerprints()
	var findings []models.Finding
	for _, sub := range subs {
		select {
		case <-ctx.Done():
			return scanner.StageResult{Findings: findings}, nil
		default:
		}
		sub = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(sub), "."))
		if sub == "" || net.ParseIP(sub) != nil {
			continue
		}
		cname, err := s.lookupCNAME(sub)
		if err != nil || cname == "" {
			continue
		}
		cname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cname), "."))
		if cname == sub || cname == sub+"." {
			continue // not a CNAME delegation
		}
		for _, fp := range fps {
			if !strings.Contains(cname, fp.cname) {
				continue
			}
			scheme := "https"
			if sc.Target.URL.Scheme == "http" {
				scheme = "http"
			}
			status, body := s.fetch(ctx, scheme+"://"+sub+"/")
			if status == 0 {
				continue
			}
			if strings.Contains(body, fp.marker) {
				findings = append(findings, models.Finding{
					ID:              "takeoverplus-" + slug(fp.provider),
					Title:           fmt.Sprintf("Subdomain takeover: %s points at unclaimed %s", sub, fp.provider),
					Description:     fmt.Sprintf("The CNAME %s → %s matches %s, and the dangling marker %q is served: the endpoint is unclaimed and registerable. Claim or remove the DNS record immediately. Reproduce: nslookup -type=CNAME %s; curl -s https://%s/.", sub, cname, fp.provider, fp.marker, sub, sub),
					Severity:        models.SeverityHigh,
					Confidence:      models.ConfidenceHigh,
					Category:        models.CategoryVulnerability,
					CWE:             "CWE-350",
					Target:          sc.Target.Raw,
					URL:             scheme + "://" + sub + "/",
					Evidence:        models.Evidence{Observed: fmt.Sprintf("CNAME %s; body marker %q", cname, fp.marker), Location: "CNAME + HTTP body"},
					Source:          models.SourceTakeover,
					DetectionMethod: "takeover fingerprint CNAME+body (takeoverplus, 30 sigs)",
					Remediation:     "Remove the dangling CNAME or claim the endpoint.",
				})
				break
			}
		}
		if len(findings) >= 5 {
			break
		}
	}
	return scanner.StageResult{Findings: findings}, nil
}

func slug(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
