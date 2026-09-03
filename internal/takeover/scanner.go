// Package takeover detects subdomain takeover vulnerabilities.
//
// A subdomain takeover occurs when a DNS CNAME record points to a cloud
// provider resource (GitHub Pages, Heroku, AWS S3, Netlify, Azure, etc.)
// that has since been deprovisioned. An attacker can register the resource
// on that provider and serve arbitrary content from the victim's domain.
//
// Detection strategy (two-signal requirement — both must fire):
//  1. The subdomain has a CNAME record whose target matches a known provider
//     fingerprint pattern.
//  2. An HTTP GET to the subdomain returns a body that contains one of the
//     provider's "unclaimed resource" error strings.
//
// Both signals are required to avoid false positives from shared-IP CDNs
// where the CNAME target is always present. Only GET is issued — no writes,
// no authentication, no side effects. Errors are warnings, not failures.
package takeover

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// providerSig describes one cloud provider's CNAME pattern and unclaimed-
// resource body fingerprints.
type providerSig struct {
	// Name is the provider name shown in findings.
	Name string
	// CNAMESuffix is matched (case-insensitive) against the CNAME target.
	CNAMESuffix []string
	// BodyFingerprints are substrings checked against the HTTP response body.
	// At least one must match for the finding to fire.
	BodyFingerprints []string
	// Severity reflects exploitability: takeovers that let an attacker serve
	// arbitrary content under the victim's domain are High.
	Severity models.Severity
}

// providerTable is the built-in list of providers and their signals.
// Sources: EdOverflow/can-i-take-over-xyz, projectdiscovery/nuclei-templates.
var providerTable = []providerSig{
	{
		Name:             "GitHub Pages",
		CNAMESuffix:      []string{"github.io", "github.com"},
		BodyFingerprints: []string{"There isn't a GitHub Pages site here.", "For root URLs (like http://example.com/) you must provide an index.html file"},
		Severity:         models.SeverityHigh,
	},
	{
		Name:             "Heroku",
		CNAMESuffix:      []string{"herokudns.com", "herokussl.com", "herokuapp.com"},
		BodyFingerprints: []string{"No such app", "herokucdn.com/error-pages/no-such-app.html"},
		Severity:         models.SeverityHigh,
	},
	{
		Name:             "AWS S3",
		CNAMESuffix:      []string{"s3.amazonaws.com", "s3-website"},
		BodyFingerprints: []string{"NoSuchBucket", "The specified bucket does not exist"},
		Severity:         models.SeverityHigh,
	},
	{
		Name:             "Netlify",
		CNAMESuffix:      []string{"netlify.app", "netlify.com"},
		BodyFingerprints: []string{"Not Found - Request ID", "netlify"},
		Severity:         models.SeverityHigh,
	},
	{
		Name:             "Azure",
		CNAMESuffix:      []string{"azurewebsites.net", "cloudapp.net", "trafficmanager.net", "blob.core.windows.net"},
		BodyFingerprints: []string{"404 Web Site not found", "The resource you are looking for has been removed"},
		Severity:         models.SeverityHigh,
	},
	{
		Name:             "Fastly",
		CNAMESuffix:      []string{"fastly.net"},
		BodyFingerprints: []string{"Fastly error: unknown domain", "Please check that this domain has been added to a service"},
		Severity:         models.SeverityHigh,
	},
	{
		Name:             "Shopify",
		CNAMESuffix:      []string{"myshopify.com", "shops.myshopify.com"},
		BodyFingerprints: []string{"Sorry, this shop is currently unavailable.", "Sorry, this shop is not available."},
		Severity:         models.SeverityHigh,
	},
	{
		Name:             "Zendesk",
		CNAMESuffix:      []string{"zendesk.com"},
		BodyFingerprints: []string{"Help Center Closed", "This help center no longer exists"},
		Severity:         models.SeverityMedium,
	},
	{
		Name:             "Ghost",
		CNAMESuffix:      []string{"ghost.io"},
		BodyFingerprints: []string{"The thing you were looking for is no longer here"},
		Severity:         models.SeverityHigh,
	},
	{
		Name:             "Surge.sh",
		CNAMESuffix:      []string{"surge.sh"},
		BodyFingerprints: []string{"project not found", "surge.sh"},
		Severity:         models.SeverityHigh,
	},
	{
		Name:             "Readme.io",
		CNAMESuffix:      []string{"readme.io"},
		BodyFingerprints: []string{"Project doesnt exist... yet!", "Project not found"},
		Severity:         models.SeverityMedium,
	},
}

// Scanner is the pipeline stage for subdomain takeover detection.
type Scanner struct {
	resolver *net.Resolver
	client   *http.Client
}

func New() *Scanner {
	return &Scanner{
		resolver: net.DefaultResolver,
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse // don't follow redirects
			},
		},
	}
}

func (s *Scanner) Name() string                     { return "takeover-scanner" }
func (s *Scanner) Available(_ context.Context) bool { return true }

// Run checks each subdomain in sc.Subdomains for takeover signals.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	if len(sc.Subdomains) == 0 {
		return scanner.StageResult{}, nil
	}

	type work struct {
		host string
	}
	jobs := make(chan work, len(sc.Subdomains))
	for _, h := range sc.Subdomains {
		jobs <- work{h}
	}
	close(jobs)

	var (
		mu       sync.Mutex
		findings []models.Finding
		warnings []string
	)

	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for j := range jobs {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			select {
			case <-ctx.Done():
				return
			default:
			}

			f, warn := s.check(ctx, host, sc.Target.Raw)
			mu.Lock()
			if f != nil {
				findings = append(findings, *f)
			}
			if warn != "" {
				warnings = append(warnings, warn)
			}
			mu.Unlock()
		}(j.host)
	}
	wg.Wait()

	return scanner.StageResult{Findings: findings, Warnings: warnings}, nil
}

// check performs CNAME lookup then HTTP fingerprint check for one host.
// Returns a finding if both signals fire, or a warning string on soft error.
func (s *Scanner) check(ctx context.Context, host, target string) (*models.Finding, string) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cname, err := s.resolver.LookupCNAME(cctx, host)
	if err != nil || cname == "" || cname == host+"." {
		return nil, "" // no CNAME or resolves to itself
	}
	cname = strings.ToLower(strings.TrimSuffix(cname, "."))

	// Find a matching provider.
	var matched *providerSig
	for i := range providerTable {
		for _, suffix := range providerTable[i].CNAMESuffix {
			if strings.HasSuffix(cname, suffix) {
				matched = &providerTable[i]
				break
			}
		}
		if matched != nil {
			break
		}
	}
	if matched == nil {
		return nil, "" // CNAME target not a known cloud provider
	}

	// Fetch the subdomain and check body fingerprints.
	body, warn := s.fetchBody(ctx, host)
	if warn != "" {
		return nil, warn
	}
	bodyLower := strings.ToLower(body)

	matchedFP := ""
	for _, fp := range matched.BodyFingerprints {
		if strings.Contains(bodyLower, strings.ToLower(fp)) {
			matchedFP = fp
			break
		}
	}
	if matchedFP == "" {
		return nil, "" // CNAME matches but body doesn't confirm unclaimed
	}

	f := &models.Finding{
		ID:    fmt.Sprintf("takeover-%s-%d", strings.ReplaceAll(host, ".", "-"), time.Now().UnixNano()),
		Title: fmt.Sprintf("Subdomain takeover: %s → %s (%s)", host, cname, matched.Name),
		Description: fmt.Sprintf(
			"%s has a CNAME record pointing to %s (%s), but the resource appears to be unclaimed. "+
				"An attacker can register this resource on %s and serve arbitrary content under your domain.",
			host, cname, matched.Name, matched.Name,
		),
		Severity:        matched.Severity,
		Confidence:      models.ConfidenceHigh,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-350",
		OWASP:           "A05:2021 - Security Misconfiguration",
		Target:          target,
		URL:             "https://" + host,
		Source:          models.SourceTakeover,
		DetectionMethod: fmt.Sprintf("CNAME → %s; body contains %q", cname, matchedFP),
		Evidence: models.Evidence{
			Observed: fmt.Sprintf("CNAME: %s → %s\nBody fingerprint matched: %q", host, cname, matchedFP),
			Location: host,
		},
		Impact:      "Attacker can host phishing pages, steal cookies scoped to the parent domain, or abuse the domain's email reputation.",
		Remediation: fmt.Sprintf("Remove the DNS CNAME record for %s, or re-provision the %s resource and point the CNAME to it.", host, matched.Name),
		References: []string{
			"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
			"https://github.com/EdOverflow/can-i-take-over-xyz",
		},
		FirstSeen: time.Now(),
	}
	return f, ""
}

// fetchBody GETs the subdomain and returns up to 32 KB of the response body.
func (s *Scanner) fetchBody(ctx context.Context, host string) (string, string) {
	url := "https://" + host
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Sprintf("takeover: build request for %s: %v", host, err)
	}
	req.Header.Set("User-Agent", "anpu-security-scanner/1.0")

	resp, err := s.client.Do(req)
	if err != nil {
		// Try plain HTTP as fallback (some dangling CNAMEs only serve HTTP).
		req2, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+host, nil)
		req2.Header.Set("User-Agent", "anpu-security-scanner/1.0")
		resp, err = s.client.Do(req2)
		if err != nil {
			return "", fmt.Sprintf("takeover: GET %s: %v", host, err)
		}
	}
	defer resp.Body.Close()

	buf, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	return string(buf), ""
}
