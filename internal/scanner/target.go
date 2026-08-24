// Package scanner defines the core scanning pipeline: the Scanner
// interface that all scan modules (built-in analyzers and external
// integrations like Nuclei/ZAP) implement, target validation, and the
// orchestrator that runs the pipeline stages in order.
package scanner

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

// TargetValidationError explains why a target was rejected.
type TargetValidationError struct {
	Reason string
}

func (e *TargetValidationError) Error() string { return e.Reason }

// ValidatedTarget is a target URL that has passed validation, with its
// parsed form and resolved host information attached.
type ValidatedTarget struct {
	Raw  string
	URL  *url.URL
	Host string // hostname without port
	Port string
}

// AllowLocalNetwork, when true, disables the private/loopback network
// guard. It exists only for local testing against mock targets (see
// tests/) and must never be enabled by default.
//
// It is intentionally not exposed as a CLI flag: the only supported way
// to enable it is the ANPU_ALLOW_LOCAL_NETWORK=1 environment variable,
// read once at process start, so that scanning a local network is never
// one accidental flag away in normal use.
var AllowLocalNetwork = os.Getenv("ANPU_ALLOW_LOCAL_NETWORK") == "1"

// ValidateTarget parses and sanity-checks a scan target. It:
//   - requires an explicit http:// or https:// scheme
//   - rejects URLs with embedded userinfo (credentials in the URL)
//   - rejects targets that resolve to loopback, link-local, private, or
//     otherwise non-public IP ranges, to avoid accidentally scanning the
//     operator's own local network or cloud metadata endpoints
//   - rejects obviously malformed hosts
//
// This is a safety boundary, not an authorization check: ANPU cannot
// verify the user is actually authorized to test the target. That
// responsibility is the operator's, and the CLI must warn about it
// separately.
func ValidateTarget(raw string) (*ValidatedTarget, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, &TargetValidationError{"target URL is empty"}
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, &TargetValidationError{fmt.Sprintf("could not parse target URL: %v", err)}
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, &TargetValidationError{"target must use http:// or https://"}
	}

	if u.User != nil {
		return nil, &TargetValidationError{"target URL must not contain embedded credentials"}
	}

	host := u.Hostname()
	if host == "" {
		return nil, &TargetValidationError{"target URL has no host"}
	}

	if !AllowLocalNetwork {
		if err := guardAgainstLocalNetwork(host); err != nil {
			return nil, err
		}
	}

	return &ValidatedTarget{
		Raw:  raw,
		URL:  u,
		Host: host,
		Port: u.Port(),
	}, nil
}

// guardAgainstLocalNetwork rejects hosts that are, or resolve to,
// loopback/private/link-local/cloud-metadata addresses. This prevents
// ANPU from being pointed (accidentally or via a malicious redirect)
// at the operator's own infrastructure or internal services.
func guardAgainstLocalNetwork(host string) error {
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") ||
		lower == "metadata.google.internal" {
		return &TargetValidationError{
			fmt.Sprintf("refusing to scan %q: local/internal hostnames are blocked by default (use test fixtures or --allow-local-network for authorized internal testing)", host),
		}
	}

	ip := net.ParseIP(host)
	if ip != nil {
		return checkIPNotPrivate(ip, host)
	}

	// Best-effort DNS resolution so we can catch hostnames that point at
	// private ranges. If resolution fails here, we don't hard-fail —
	// the HTTP client will surface a clearer error later — but any IP
	// that *does* resolve is checked.
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil
	}
	for _, resolved := range ips {
		if err := checkIPNotPrivate(resolved, host); err != nil {
			return err
		}
	}
	return nil
}

func checkIPNotPrivate(ip net.IP, host string) error {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return &TargetValidationError{
			fmt.Sprintf("refusing to scan %q: resolves to a loopback/private/link-local address (%s); ANPU does not scan local networks by default", host, ip.String()),
		}
	}
	// Cloud metadata endpoint (169.254.169.254 is already covered by
	// IsLinkLocalUnicast, but keep this explicit for clarity/future IPv6
	// metadata ranges).
	if ip.String() == "169.254.169.254" {
		return &TargetValidationError{"refusing to scan cloud metadata endpoint"}
	}
	return nil
}
