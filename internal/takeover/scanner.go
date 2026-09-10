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
	"errors"
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
// matchesSuffix reports dot-boundary CNAME matching: exact or "."+suffix.
func matchesSuffix(cname, suffix string) bool {
	suffix = strings.ToLower(suffix)
	if cname == suffix {
		return true
	}
	return strings.HasSuffix(cname, "."+suffix)
}

// matchesS3Website reports s3-website*.amazonaws.com endpoints:
// "<bucket>.s3-website[-<region>][.<region>].amazonaws.com".
func matchesS3Website(cname string) bool {
	if !strings.HasSuffix(cname, ".amazonaws.com") {
		return false
	}
	return strings.Contains(cname, ".s3-website")
}

var providerTable = []providerSig{
	{
		Name:             "GitHub Pages",
		CNAMESuffix:      []string{"github.io"},
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
		CNAMESuffix:      []string{"s3.amazonaws.com"},
		BodyFingerprints: []string{"NoSuchBucket", "The specified bucket does not exist"},
		Severity:         models.SeverityHigh,
	},
	{
		Name:             "Netlify",
		CNAMESuffix:      []string{"netlify.app", "netlify.com"},
		BodyFingerprints: []string{"Not Found - Request ID", "The site you are looking for could not be found on Netlify."},
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
		BodyFingerprints: []string{"project not found", "This Surge.sh project could not be found - the project does not exist."},
		Severity:         models.SeverityHigh,
	},
	{
		Name:             "Readme.io",
		CNAMESuffix:      []string{"readme.io"},
		BodyFingerprints: []string{"Project doesnt exist... yet!", "Project not found"},
		Severity:         models.SeverityMedium,
	},
	{
		Name:             "Vercel",
		CNAMESuffix:      []string{"vercel.app", "vercel-dns.com"},
		BodyFingerprints: []string{"The deployment could not be found on Vercel.", "DEPLOYMENT_NOT_FOUND"},
		Severity:         models.SeverityHigh,
	},
	{
		Name:             "Tumblr",
		CNAMESuffix:      []string{"domains.tumblr.com"},
		BodyFingerprints: []string{"Whatever you were looking for doesn't currently exist here"},
		Severity:         models.SeverityHigh,
	},
	{
		Name:             "Bitbucket",
		CNAMESuffix:      []string{"bitbucket.io"},
		BodyFingerprints: []string{"Repository not found"},
		Severity:         models.SeverityHigh,
	},
	{
		Name:             "Pantheon",
		CNAMESuffix:      []string{"pantheonsite.io", "getpantheon.com"},
		BodyFingerprints: []string{"The gods are wise, but do not know of the site yet."},
		Severity:         models.SeverityHigh,
	},
	{
		Name:             "Squarespace",
		CNAMESuffix:      []string{"squarespace.com"},
		BodyFingerprints: []string{"No Such Account"},
		Severity:         models.SeverityHigh,
	},
	{
		Name:             "BigCartel",
		CNAMESuffix:      []string{"bigcartel.com"},
		BodyFingerprints: []string{"Oops! We couldn't find that page."},
		Severity:         models.SeverityHigh,
	},
	{
		Name:             "Helpjuice",
		CNAMESuffix:      []string{"helpjuice.com"},
		BodyFingerprints: []string{"We could not find what you're looking for."},
		Severity:         models.SeverityMedium,
	},
	{
		Name:             "HelpScout Docs",
		CNAMESuffix:      []string{"helpscoutdocs.com"},
		BodyFingerprints: []string{"No settings were found for this company."},
		Severity:         models.SeverityMedium,
	},
	{
		Name:             "Ngrok",
		CNAMESuffix:      []string{"ngrok.io"},
		BodyFingerprints: []string{"ERR_NGROK_3200"},
		Severity:         models.SeverityMedium,
	},
	{
		Name:             "Firebase Hosting",
		CNAMESuffix:      []string{"firebaseapp.com"},
		BodyFingerprints: []string{"Site Not Found"},
		Severity:         models.SeverityMedium,
	},
}

// dnsResolver abstracts DNS lookups so tests can inject fixtures.
type dnsResolver interface {
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// Scanner is the pipeline stage for subdomain takeover detection.
type Scanner struct {
	resolver dnsResolver
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

	// Find a matching provider (dot-boundary: exact or "."+suffix).
	var matched *providerSig
	for i := range providerTable {
		for _, suffix := range providerTable[i].CNAMESuffix {
			if matchesSuffix(cname, suffix) {
				matched = &providerTable[i]
				break
			}
		}
		if matched != nil {
			break
		}
		// S3 website endpoints: s3-website*.amazonaws.com.
		if providerTable[i].Name == "AWS S3" && matchesS3Website(cname) {
			matched = &providerTable[i]
			break
		}
	}
	if matched == nil {
		// Unknown provider: a CNAME whose target does not resolve at
		// all is still dangling infrastructure worth investigating.
		return s.checkDangling(ctx, host, cname, target)
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

// checkDangling flags CNAME targets that do not resolve in public DNS
// at all (NXDOMAIN). Any provider — fingerprinted or not — is claimable
// when its DNS name is dead, so this catches takeovers the fingerprint
// table has never heard of. Medium confidence: transient DNS failures
// are possible, so the finding tells the operator to verify.
func (s *Scanner) checkDangling(ctx context.Context, host, cname, target string) (*models.Finding, string) {
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := s.resolver.LookupIPAddr(rctx, cname); err == nil {
		return nil, "" // target resolves — nothing dangling
	} else {
		var dnsErr *net.DNSError
		if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
			return nil, "" // transient/odd resolver error — stay silent
		}
	}
	f := &models.Finding{
		ID:    fmt.Sprintf("takeover-dangling-%s-%d", strings.ReplaceAll(host, ".", "-"), time.Now().UnixNano()),
		Title: fmt.Sprintf("Dangling CNAME record: %s → %s (target does not resolve)", host, cname),
		Description: fmt.Sprintf(
			"%s has a CNAME record pointing to %s, which does not resolve in public DNS (NXDOMAIN). "+
				"Dangling records are the raw material of subdomain takeovers: if the target name can be re-registered on its platform, "+
				"an attacker can serve arbitrary content under your domain. Verify whether %s is claimable.",
			host, cname, cname,
		),
		Severity:        models.SeverityMedium,
		Confidence:      models.ConfidenceMedium,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-350",
		OWASP:           "A05:2021 - Security Misconfiguration",
		Target:          target,
		URL:             "https://" + host,
		Source:          models.SourceTakeover,
		DetectionMethod: fmt.Sprintf("CNAME → %s; target NXDOMAIN in public DNS", cname),
		Evidence: models.Evidence{
			Observed: fmt.Sprintf("CNAME: %s → %s\ntarget: NXDOMAIN (no A/AAAA records)", host, cname),
			Location: host,
		},
		Impact:      "If the dead target name is re-registered by an attacker, they gain content hosting under your domain (phishing, cookie theft, reputation abuse).",
		Remediation: fmt.Sprintf("Remove the DNS CNAME record for %s unless the target service is re-provisioned.", host),
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
	defer func() { _ = resp.Body.Close() }()

	buf, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	return string(buf), ""
}
