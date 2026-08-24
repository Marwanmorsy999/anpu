// Package tls performs passive TLS analysis: certificate validity,
// expiration, hostname matching, negotiated protocol version, and
// whether HTTP traffic is redirected to HTTPS. It never attempts active
// exploitation (no cipher downgrade attempts, no fuzzing) — it only
// inspects what a normal TLS handshake and HTTP request/redirect reveal.
package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

const dialTimeout = 10 * time.Second

// Analyzer implements scanner.Scanner for TLS/HTTPS posture checks.
type Analyzer struct {
	client *anpuhttp.Client
}

func New(client *anpuhttp.Client) *Analyzer { return &Analyzer{client: client} }

func (a *Analyzer) Name() string { return "tls" }

func (a *Analyzer) Available(ctx context.Context) bool { return true }

func (a *Analyzer) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	target := sc.Target
	var findings []models.Finding

	httpsHost := target.Host
	port := target.Port
	if port == "" {
		port = "443"
	}

	connState, dialErr := probeTLS(ctx, httpsHost, port)
	httpsAvailable := dialErr == nil

	findings = append(findings, checkHTTPSAvailability(target.Raw, httpsHost, httpsAvailable, dialErr)...)

	if httpsAvailable {
		findings = append(findings, checkCertificate(target.Raw, httpsHost, connState)...)
		findings = append(findings, checkProtocolVersion(target.Raw, httpsHost, connState)...)
	}

	// Only check HTTP->HTTPS redirect behavior when the target itself was
	// given as http://, to avoid an extra request when the user already
	// scanned the https:// origin directly.
	if strings.EqualFold(target.URL.Scheme, "http") {
		findings = append(findings, a.checkHTTPRedirect(ctx, target.Raw)...)
	}

	return scanner.StageResult{Findings: findings}, nil
}

func probeTLS(ctx context.Context, host, port string) (*tls.ConnectionState, error) {
	dialer := &net.Dialer{Timeout: dialTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), &tls.Config{
		ServerName: host,
		// We want to see the *actual* certificate the server presents,
		// including if it's invalid, so we can report on it accurately.
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionSSL30, //nolint:staticcheck // intentionally permissive to observe legacy config
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	return &state, nil
}

func checkHTTPSAvailability(target, host string, available bool, dialErr error) []models.Finding {
	if available {
		return nil
	}
	ev := models.Evidence{Location: fmt.Sprintf("TLS handshake attempt to %s:443", host)}
	if dialErr != nil {
		ev.Observed = fmt.Sprintf("connection/handshake failed: %v", dialErr)
	} else {
		ev.Unavailable = true
	}
	return []models.Finding{{
		ID:              "tls-https-unavailable",
		Title:           "HTTPS not available on standard port",
		Description:     "ANPU could not establish a TLS connection to this host on port 443. The site may only be served over plain HTTP, or HTTPS may be available on a non-standard port.",
		Severity:        models.SeverityMedium,
		Confidence:      models.ConfidenceMedium,
		Category:        models.CategoryTLS,
		CWE:             "CWE-319",
		Target:          target,
		URL:             target,
		Evidence:        ev,
		Source:          models.SourceTLS,
		DetectionMethod: "TLS handshake attempt",
		Impact:          "Traffic to this host is not protected by TLS, exposing it to eavesdropping and tampering on the network path.",
		Remediation:     "Provision a TLS certificate and serve the site over HTTPS, redirecting plain-HTTP requests.",
		References:      []string{"https://letsencrypt.org/"},
	}}
}

func checkCertificate(target, host string, state *tls.ConnectionState) []models.Finding {
	if state == nil || len(state.PeerCertificates) == 0 {
		return []models.Finding{{
			ID:              "tls-no-certificate",
			Title:           "No TLS certificate presented",
			Description:     "The TLS handshake succeeded but no peer certificate was observed, which is unusual and worth manual investigation.",
			Severity:        models.SeverityMedium,
			Confidence:      models.ConfidenceLow,
			Category:        models.CategoryTLS,
			Target:          target,
			URL:             target,
			Evidence:        models.Evidence{Unavailable: true, Location: "TLS handshake"},
			Source:          models.SourceTLS,
			DetectionMethod: "TLS handshake inspection",
		}}
	}

	cert := state.PeerCertificates[0]
	var findings []models.Finding

	// Hostname match / chain validity.
	opts := x509.VerifyOptions{
		DNSName:       host,
		Intermediates: x509.NewCertPool(),
	}
	for _, c := range state.PeerCertificates[1:] {
		opts.Intermediates.AddCert(c)
	}
	if _, err := cert.Verify(opts); err != nil {
		findings = append(findings, models.Finding{
			ID:          "tls-certificate-invalid",
			Title:       "TLS certificate failed validation",
			Description: fmt.Sprintf("The presented TLS certificate did not pass standard validation for host %q: %v", host, err),
			Severity:    models.SeverityHigh,
			Confidence:  models.ConfidenceHigh,
			Category:    models.CategoryTLS,
			CWE:         "CWE-295",
			Target:      target,
			URL:         target,
			Evidence: models.Evidence{
				Observed: fmt.Sprintf("subject=%s issuer=%s error=%v", cert.Subject, cert.Issuer, err),
				Location: "TLS certificate chain",
			},
			Source:          models.SourceTLS,
			DetectionMethod: "TLS certificate chain verification",
			Impact:          "Clients (browsers) will show security warnings, and the connection cannot be trusted to actually be with the intended host, enabling potential man-in-the-middle interception.",
			Remediation:     "Install a valid certificate from a trusted CA covering this hostname, and ensure the full chain (including intermediates) is served.",
			References:      []string{"https://letsencrypt.org/"},
		})
	}

	// Expiration.
	now := time.Now()
	if now.After(cert.NotAfter) {
		findings = append(findings, expiryFinding(target, cert, true, now))
	} else if cert.NotAfter.Sub(now) < 14*24*time.Hour {
		findings = append(findings, expiryFinding(target, cert, false, now))
	}

	return findings
}

func expiryFinding(target string, cert *x509.Certificate, expired bool, now time.Time) models.Finding {
	title := "TLS certificate expiring soon"
	sev := models.SeverityMedium
	desc := fmt.Sprintf("The TLS certificate expires on %s, which is within 14 days of the scan time.", cert.NotAfter.Format(time.RFC3339))
	if expired {
		title = "TLS certificate has expired"
		sev = models.SeverityHigh
		desc = fmt.Sprintf("The TLS certificate expired on %s.", cert.NotAfter.Format(time.RFC3339))
	}
	return models.Finding{
		ID:          "tls-certificate-expiry",
		Title:       title,
		Description: desc,
		Severity:    sev,
		Confidence:  models.ConfidenceConfirmed,
		Category:    models.CategoryTLS,
		CWE:         "CWE-298",
		Target:      target,
		URL:         target,
		Evidence: models.Evidence{
			Observed: fmt.Sprintf("NotAfter=%s (checked at %s)", cert.NotAfter.Format(time.RFC3339), now.Format(time.RFC3339)),
			Location: "TLS certificate",
		},
		Source:          models.SourceTLS,
		DetectionMethod: "TLS certificate field inspection",
		Impact:          "Once expired, browsers and API clients will refuse or warn on the connection, effectively taking the site offline for most users.",
		Remediation:     "Renew the certificate, and consider automated renewal (e.g. Let's Encrypt with auto-renewal) to prevent recurrence.",
	}
}

func checkProtocolVersion(target, host string, state *tls.ConnectionState) []models.Finding {
	if state == nil {
		return nil
	}
	version := state.Version
	if version >= tls.VersionTLS12 {
		return nil
	}
	name := tlsVersionName(version)
	return []models.Finding{{
		ID:          "tls-outdated-protocol",
		Title:       fmt.Sprintf("Outdated TLS protocol version negotiated (%s)", name),
		Description: fmt.Sprintf("The server negotiated %s, which is deprecated and known to have cryptographic weaknesses compared to TLS 1.2+.", name),
		Severity:    models.SeverityHigh,
		Confidence:  models.ConfidenceHigh,
		Category:    models.CategoryTLS,
		CWE:         "CWE-327",
		Target:      target,
		URL:         target,
		Evidence: models.Evidence{
			Observed: fmt.Sprintf("negotiated protocol: %s", name),
			Location: "TLS handshake",
		},
		Source:          models.SourceTLS,
		DetectionMethod: "TLS handshake inspection",
		Impact:          "Legacy TLS versions are vulnerable to known cryptographic attacks (e.g. POODLE, BEAST) and are disabled by default in modern browsers, which may already be blocking users.",
		Remediation:     "Disable TLS versions below 1.2 in the server/load balancer configuration.",
		References:      []string{"https://tools.ietf.org/html/rfc8996"},
	}}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionSSL30:
		return "SSLv3"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", v)
	}
}

func (a *Analyzer) checkHTTPRedirect(ctx context.Context, httpTarget string) []models.Finding {
	resp, err := a.client.Get(ctx, httpTarget)
	if err != nil {
		return []models.Finding{{
			ID:              "tls-http-redirect-unknown",
			Title:           "Could not determine HTTP→HTTPS redirect behavior",
			Description:     fmt.Sprintf("An error occurred while checking whether plain-HTTP requests are redirected to HTTPS: %v", err),
			Severity:        models.SeverityInfo,
			Confidence:      models.ConfidenceLow,
			Category:        models.CategoryTLS,
			Target:          httpTarget,
			URL:             httpTarget,
			Evidence:        models.Evidence{Unavailable: true},
			Source:          models.SourceTLS,
			DetectionMethod: "HTTP request",
		}}
	}
	if strings.HasPrefix(strings.ToLower(resp.FinalURL), "https://") {
		return nil // properly redirected
	}
	return []models.Finding{{
		ID:          "tls-no-http-to-https-redirect",
		Title:       "Plain HTTP is not redirected to HTTPS",
		Description: "A plain HTTP request to this host was not redirected to HTTPS. Visitors who type or follow an http:// link will have their traffic served unencrypted unless their browser/HSTS preload forces HTTPS.",
		Severity:    models.SeverityMedium,
		Confidence:  models.ConfidenceHigh,
		Category:    models.CategoryTLS,
		CWE:         "CWE-319",
		Target:      httpTarget,
		URL:         resp.FinalURL,
		Evidence: models.Evidence{
			Observed: fmt.Sprintf("final URL after following redirects: %s (status %d)", resp.FinalURL, resp.StatusCode),
			Location: "HTTP request/response",
		},
		Source:          models.SourceTLS,
		DetectionMethod: "HTTP request following redirects",
		Impact:          "Requests made over plain HTTP (e.g. from an old bookmark, a typed URL, or a non-HTTPS link elsewhere) are exposed to network eavesdropping and tampering.",
		Remediation:     "Configure the web server to redirect all HTTP traffic to HTTPS (301/308), and add HSTS once that's in place.",
	}}
}
