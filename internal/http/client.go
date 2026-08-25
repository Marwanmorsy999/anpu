// Package http provides ANPU's shared HTTP client and response
// utilities. Every analyzer that needs to talk to the target goes
// through this client so that timeouts, redirect limits, and
// local-network protections are enforced in exactly one place.
package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"strings"
	"time"
)

const (
	// DefaultTimeout bounds a single request end-to-end.
	DefaultTimeout = 15 * time.Second
	// MaxRedirects caps redirect chains to avoid loops / redirect-based
	// SSRF into internal networks.
	MaxRedirects = 5
	// MaxBodyBytes caps how much of a response body ANPU will read into
	// memory for analysis (technology fingerprinting, link extraction).
	MaxBodyBytes = 5 * 1024 * 1024 // 5MB
	// UserAgent identifies ANPU truthfully to the target so operators can
	// see it in their logs — no user-agent spoofing.
	UserAgent = "anpu-security-scanner/0.1 (+https://github.com/anpu-project/anpu)"
)

// Client wraps *http.Client with ANPU's safety defaults.
type ipResolver interface {
	LookupIP(context.Context, string, string) ([]net.IP, error)
}

type Client struct {
	http              *stdhttp.Client
	allowInsecure     bool // allow scanning targets with invalid TLS certs (still reported)
	allowLocalNetwork bool // test-only override for local fixtures
	guardRedirects    bool
	resolver          ipResolver
	dialer            *net.Dialer
}

// NewClient builds a Client with conservative, safe-by-default settings.
// Local/private network destinations are rejected at connection time.
func NewClient() *Client {
	return newClient(false, false)
}

// NewClientWithLocalNetworkAllowed builds a client for local/integration
// fixtures. Production callers should leave this false; the CLI only enables
// it when ANPU_ALLOW_LOCAL_NETWORK=1 is explicitly set.
func NewClientWithLocalNetworkAllowed(allowLocalNetwork bool) *Client {
	return newClient(false, allowLocalNetwork)
}

// NewInsecureClient builds a Client that skips TLS certificate
// verification. It exists for testing against self-signed local
// fixtures (see tests/) and is not wired to any CLI flag — TLS
// certificate validity is something ANPU reports on (see internal/tls),
// not something it silently bypasses when talking to a real target.
func NewInsecureClient() *Client {
	return newClient(true, false)
}

// NewInsecureClientWithLocalNetworkAllowed combines the test-only TLS
// relaxation with the local-network override used by local fixtures.
func NewInsecureClientWithLocalNetworkAllowed(allowLocalNetwork bool) *Client {
	return newClient(true, allowLocalNetwork)
}

func newClient(insecureSkipVerify, allowLocalNetwork bool) *Client {
	c := &Client{
		guardRedirects:    true,
		allowInsecure:     insecureSkipVerify,
		allowLocalNetwork: allowLocalNetwork,
		resolver:          net.DefaultResolver,
		dialer: &net.Dialer{
			Timeout: 10 * time.Second,
		},
	}

	transport := &stdhttp.Transport{
		TLSClientConfig: &tls.Config{
			// InsecureSkipVerify is intentionally left false by default.
			// TLS validity is *reported on*, not silently bypassed — see
			// internal/tls.
			InsecureSkipVerify: insecureSkipVerify, //nolint:gosec // opt-in only, see NewInsecureClient doc
			MinVersion:         tls.VersionTLS10,
		},
		MaxIdleConnsPerHost:   10,
		ResponseHeaderTimeout: DefaultTimeout,
		// Do not use net.Dialer.DialContext directly. The target hostname
		// must be resolved and every selected IP validated immediately before
		// the socket is opened. This closes the DNS-rebinding gap where an
		// earlier validation can become stale before connect().
		DialContext: c.safeDialContext,
	}
	c.http = &stdhttp.Client{
		Transport: transport,
		Timeout:   DefaultTimeout,
		CheckRedirect: func(req *stdhttp.Request, via []*stdhttp.Request) error {
			if len(via) >= MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", MaxRedirects)
			}
			if c.guardRedirects {
				if err := c.guardRedirectTarget(req); err != nil {
					return err
				}
			}
			return nil
		},
	}
	return c
}

// safeDialContext resolves the hostname immediately before connecting and
// refuses every loopback/private/link-local/reserved address unless the
// explicit local-network test override is enabled.
//
// The returned connection is opened directly to the validated IP rather than
// resolving the hostname a second time inside net.Dialer. TLS still sees the
// original hostname because the HTTP transport keeps req.URL.Host unchanged,
// so certificate/SNI behavior remains correct.
func (c *Client) safeDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid dial address %q: %w", address, err)
	}
	if host == "" {
		return nil, fmt.Errorf("dial address %q has no host", address)
	}

	ips, err := c.resolveHost(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if !c.allowLocalNetwork {
			if err := checkIPNotPrivate(ip, host); err != nil {
				continue
			}
		}

		conn, dialErr := c.dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
	}

	if !c.allowLocalNetwork {
		for _, ip := range ips {
			if err := checkIPNotPrivate(ip, host); err != nil {
				return nil, err
			}
		}
	}

	return nil, fmt.Errorf("could not connect to %s: all resolved addresses failed", host)
}

func (c *Client) resolveHost(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}

	ips, err := c.resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolving %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("resolving %q returned no addresses", host)
	}
	return ips, nil
}

// guardRedirectTarget prevents a target from redirecting the scanner
// into a private/internal network (SSRF via redirect). Hostnames are
// resolved here for early rejection, and safeDialContext repeats the
// check immediately before every actual connection to defend against
// DNS rebinding.
func (c *Client) guardRedirectTarget(req *stdhttp.Request) error {
	host := req.URL.Hostname()
	if host == "" {
		return fmt.Errorf("redirect to URL with no host")
	}
	if c.allowLocalNetwork {
		return nil
	}

	lower := strings.ToLower(strings.TrimSuffix(host, "."))
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") || lower == "metadata.google.internal" {
		return fmt.Errorf("refusing to follow redirect to local/internal host %s", host)
	}

	ips, err := c.resolveHost(req.Context(), host)
	if err != nil {
		return fmt.Errorf("refusing to follow redirect to %q: %w", host, err)
	}
	for _, ip := range ips {
		if err := checkIPNotPrivate(ip, host); err != nil {
			return err
		}
	}
	return nil
}

// ValidateHostPublic reports whether host is safe to contact directly:
// not loopback/private/link-local/special-purpose, per the same policy
// the shared client enforces at dial time. Engines that open their own
// sockets (port scanner, DNS prober) must call this first unless
// AllowLocalNetwork-style test overrides apply to them.
func ValidateHostPublic(host string) error {
	lower := strings.ToLower(strings.TrimSuffix(host, "."))
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") || lower == "metadata.google.internal" {
		return fmt.Errorf("refusing to contact local/internal host %s", host)
	}
	if ip := net.ParseIP(host); ip != nil {
		return checkIPNotPrivate(ip, host)
	}
	ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip", host)
	if err != nil {
		return fmt.Errorf("resolving %q: %w", host, err)
	}
	for _, ip := range ips {
		if err := checkIPNotPrivate(ip, host); err != nil {
			return err
		}
	}
	return nil
}

// checkIPNotPrivate is intentionally stricter than net.IP.IsPrivate. It also
// rejects multicast and common special-purpose ranges that should not be
// treated as ordinary public scan targets.
func checkIPNotPrivate(ip net.IP, host string) error {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() ||
		ip.IsMulticast() || isSharedAddressSpace(ip) {
		return fmt.Errorf("refusing connection to %q: resolves to non-public/special address %s", host, ip.String())
	}
	return nil
}

func isSharedAddressSpace(ip net.IP) bool {
	// RFC 6598: 100.64.0.0/10 (carrier-grade NAT/shared address space).
	shared := net.IPNet{
		IP:   net.IPv4(100, 64, 0, 0),
		Mask: net.CIDRMask(10, 32),
	}
	// RFC 2544 / RFC 5737 / other reserved test/documentation ranges.
	reserved := []string{
		"192.0.0.0/24",
		"192.0.2.0/24",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"240.0.0.0/4",
	}
	if shared.Contains(ip) {
		return true
	}
	for _, cidr := range reserved {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

// Response is a captured HTTP response, with the body already read
// (bounded by MaxBodyBytes) so callers can inspect it repeatedly without
// re-issuing requests.
type Response struct {
	StatusCode int
	Header     stdhttp.Header
	Body       []byte
	FinalURL   string   // URL after following redirects
	Redirects  []string // chain of intermediate URLs
	TLS        *tls.ConnectionState
	Elapsed    time.Duration
}

// Get issues a GET request against rawURL with the shared safety
// settings and returns the captured response.
func (c *Client) Get(ctx context.Context, rawURL string) (*Response, error) {
	req, err := stdhttp.NewRequestWithContext(ctx, stdhttp.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "*/*")

	start := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, MaxBodyBytes)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	out := &Response{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       body,
		FinalURL:   resp.Request.URL.String(),
		Elapsed:    time.Since(start),
	}
	if resp.TLS != nil {
		out.TLS = resp.TLS
	}
	return out, nil
}

// DoWithHeaders issues a GET with extra headers through the same safety
// settings (redirect guard, safe dialing) and returns the captured
// response. Engines that need custom probes (CORS origin tests, OPTIONS
// audits) must use this instead of building their own clients so the
// local-network protections stay enforced in one place.
func (c *Client) DoWithHeaders(ctx context.Context, method, rawURL string, headers map[string]string) (*Response, error) {
	req, err := stdhttp.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("User-Agent", UserAgent)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	out := &Response{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       body,
		FinalURL:   resp.Request.URL.String(),
		Elapsed:    time.Since(start),
	}
	if resp.TLS != nil {
		out.TLS = resp.TLS
	}
	return out, nil
}

// HeadOrGet tries HEAD first (cheaper, lower impact) and falls back to
// GET if the server doesn't support HEAD meaningfully (405/501 or
// identical zero-length behavior isn't reliable enough to trust, so most
// analyzers should just use Get; HeadOrGet exists for cases where a
// cheap liveness probe is enough, e.g. redirect-chain discovery).
func (c *Client) HeadOrGet(ctx context.Context, rawURL string) (*Response, error) {
	req, err := stdhttp.NewRequestWithContext(ctx, stdhttp.MethodHead, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := c.http.Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode != stdhttp.StatusMethodNotAllowed && resp.StatusCode != stdhttp.StatusNotImplemented {
			out := &Response{
				StatusCode: resp.StatusCode,
				Header:     resp.Header,
				FinalURL:   resp.Request.URL.String(),
			}
			if resp.TLS != nil {
				out.TLS = resp.TLS
			}
			return out, nil
		}
	}
	return c.Get(ctx, rawURL)
}
