// Package http provides ANPU's shared HTTP client and response
// utilities. Every analyzer that needs to talk to the target goes
// through this client so that timeouts, redirect limits, and
// local-network protections are enforced in exactly one place.
package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	stdhttp "net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/proxy"
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
	limiter           *RateLimiter // nil = unlimited
	// viaProxy is true when all traffic is routed through an explicit
	// proxy (--proxy flag). The proxy endpoint itself is user-chosen
	// (often localhost:8080 for Burp/ZAP), so dial-time IP validation
	// is skipped for the proxy hop. URL-level guards (target
	// validation, redirect guards) still apply to the logical target.
	viaProxy bool
	// stealth controls anonymous browsing: random UA per request, optional
	// custom UA override, and jitter hook via limiter. stealth implies
	// randomAgent plus a small per-request jitter to avoid bursty traffic
	// fingerprinted by WAFs/IDS.
	randomAgent bool
	customUA    string
	stealth     bool
	// jar holds stateful cookies for adversarial multi-step flows (e.g.,
	// login → CSRF → IDOR). When non-nil, every request/response round-
	// trips through the jar so later probes replay session cookies.
	jar stdhttp.CookieJar
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
			InsecureSkipVerify: insecureSkipVerify, // #nosec G402 -- opt-in insecure client only (see NewInsecureClient doc); scanner must analyze misconfigured targets.
			MinVersion:         tls.VersionTLS12,
		},
		MaxIdleConnsPerHost:   10,
		ResponseHeaderTimeout: DefaultTimeout,
		// Honor standard proxy env (HTTP_PROXY/HTTPS_PROXY/NO_PROXY,
		// lowercase variants included) so Burp/proxychains-style routing
		// works without flags. An explicit WithProxy overrides this.
		Proxy: proxyFromEnvironment,
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

	// Explicit proxy mode: every connection goes to the user-chosen
	// proxy endpoint (e.g. Burp on 127.0.0.1:8080), so dial-time IP
	// validation would wrongly reject the proxy itself. The logical
	// target is still guarded at the URL level (target validation +
	// redirect guards), which proxying does not bypass.
	if c.viaProxy {
		return c.dialer.DialContext(ctx, network, address)
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

// WithAuth returns a Client that merges extraHeaders into every
// outgoing request.  When extraHeaders is nil or empty, the original
// Client is returned unchanged (no allocation).
func (c *Client) WithAuth(extraHeaders map[string]string) *Client {
	if len(extraHeaders) == 0 {
		return c
	}
	// Shallow-clone the Client so the original is unchanged.
	clone := *c
	// Swap the transport to one that injects headers.
	clone.http = &stdhttp.Client{
		Transport: &authTransport{
			base:    c.http.Transport,
			headers: extraHeaders,
		},
		Timeout:       c.http.Timeout,
		CheckRedirect: c.http.CheckRedirect,
	}
	return &clone
}

// authTransport is an http.RoundTripper that injects fixed headers before
// delegating to the base transport.
type authTransport struct {
	base    stdhttp.RoundTripper
	headers map[string]string
}

func (t *authTransport) RoundTrip(req *stdhttp.Request) (*stdhttp.Response, error) {
	// Clone the request so we never mutate the caller's copy.
	r := req.Clone(req.Context())
	for k, v := range t.headers {
		r.Header.Set(k, v)
	}
	return t.base.RoundTrip(r)
}

// WithRateLimiter returns a shallow copy of c with the given RateLimiter
// attached.  All subsequent requests from the returned Client will call
// limiter.Wait before issuing the network request.
func (c *Client) WithRateLimiter(limiter *RateLimiter) *Client {
	clone := *c
	clone.limiter = limiter
	return &clone
}

// Jar returns the cookie jar used for stateful sessions (may be nil).
func (c *Client) Jar() stdhttp.CookieJar { return c.jar }

// WithJar returns a shallow copy that stores and replays cookies via jar.
// Adversarial multi-step probes (login → IDOR, CSRF, etc.) use this so
// later requests carry the session established by earlier ones.
func (c *Client) WithJar(jar stdhttp.CookieJar) *Client {
	if jar == nil {
		return c
	}
	clone := *c
	clone.jar = jar
	if clone.http != nil {
		nh := *clone.http
		nh.Jar = jar
		clone.http = &nh
	}
	return &clone
}

// DoWithSession issues a request that participates in the cookie jar when
// present and otherwise behaves like DoWithHeaders. It is the stateful
// primitive for adversarial modules that need header/body/WS flows to
// share cookies (e.g., JWT → IDOR chaining). Extra headers are merged
// after stealth/UA handling.
func (c *Client) DoWithSession(ctx context.Context, method, rawURL string, headers map[string]string, body string) (*Response, error) {
	if c.limiter != nil {
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, err
		}
	}
	if err := c.maybeJitter(ctx); err != nil {
		return nil, err
	}
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, err := stdhttp.NewRequestWithContext(ctx, method, rawURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("User-Agent", c.effectiveUA())
	c.applyStealthHeaders(req)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if c.jar != nil {
		for _, ck := range c.jar.Cookies(req.URL) {
			req.AddCookie(ck)
		}
	}
	start := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if c.jar != nil {
		c.jar.SetCookies(req.URL, resp.Cookies())
	}
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	out := &Response{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       respBody,
		FinalURL:   resp.Request.URL.String(),
		Elapsed:    time.Since(start),
	}
	if resp.TLS != nil {
		out.TLS = resp.TLS
	}
	return out, nil
}

func (c *Client) applyJar(req *stdhttp.Request) {
	if c.jar == nil || req.URL == nil {
		return
	}
	for _, ck := range c.jar.Cookies(req.URL) {
		req.AddCookie(ck)
	}
}

func (c *Client) saveJar(req *stdhttp.Request, resp *stdhttp.Response) {
	if c.jar == nil || req.URL == nil || resp == nil {
		return
	}
	c.jar.SetCookies(req.URL, resp.Cookies())
}

// WithRandomAgent returns a copy that emits a random browser User-Agent
// per request (stealth). When false, the truthful ANPU UA is used so
// operators can identify scans in logs.
func (c *Client) WithRandomAgent(enabled bool) *Client {
	if !enabled {
		return c
	}
	clone := *c
	clone.randomAgent = true
	return &clone
}

// WithCustomUA returns a copy that always uses ua as the User-Agent.
func (c *Client) WithCustomUA(ua string) *Client {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return c
	}
	clone := *c
	clone.customUA = ua
	return &clone
}

// effectiveUA selects the User-Agent for a single request.
func (c *Client) effectiveUA() string {
	if c.customUA != "" {
		return c.customUA
	}
	if c.randomAgent || c.stealth {
		return RandomUserAgent()
	}
	return UserAgent
}

func (c *Client) applyStealthHeaders(req *stdhttp.Request) {
	if !c.stealth {
		return
	}
	req.Header.Set("Accept-Language", RandomAcceptLanguage())
	// Only randomize generic Accept; keep JSON/XML accepts for API probes.
	if cur := req.Header.Get("Accept"); cur == "" || cur == "*/*" {
		req.Header.Set("Accept", RandomAccept())
	}
	// Small header-order jitter: Go randomizes map iteration anyway, but
	// adding a random cache-buster header occasionally further mutates the
	// fingerprint without breaking the request.
	if uaMuTryAddNoise() {
		req.Header.Set("Cache-Control", "no-cache")
	}
}

func uaMuTryAddNoise() bool {
	uaMu.Lock()
	v := uaRng.Intn(4) == 0
	uaMu.Unlock()
	return v
}

// WithStealth returns a copy in stealth/anonymous mode: random browser
// UA per request plus a per-request jitter (50-250ms) plus TLS
// fingerprint randomization (cipher suites / curves / min version).
// Use for authorized red-team or bug-bounty where the operator wants to
// avoid trivial scanner fingerprinting. It does not hide the source IP —
// combine with --proxy socks5://tor:9050 for network-layer anonymity.
func (c *Client) WithStealth(enabled bool) *Client {
	if !enabled {
		return c
	}
	clone := *c
	clone.stealth = true
	clone.randomAgent = true
	// Randomize TLS fingerprint for this client instance
	if tr, ok := clone.http.Transport.(*stdhttp.Transport); ok {
		tcopy := tr.Clone()
		tcopy.TLSClientConfig = stealthTLSConfig(clone.allowInsecure)
		clone.http = &stdhttp.Client{
			Transport:     tcopy,
			Timeout:       clone.http.Timeout,
			CheckRedirect: clone.http.CheckRedirect,
		}
	} else if at, ok := clone.http.Transport.(*authTransport); ok {
		if inner, ok := at.base.(*stdhttp.Transport); ok {
			tcopy := inner.Clone()
			tcopy.TLSClientConfig = stealthTLSConfig(clone.allowInsecure)
			clone.http = &stdhttp.Client{
				Transport:     &authTransport{base: tcopy, headers: at.headers},
				Timeout:       clone.http.Timeout,
				CheckRedirect: clone.http.CheckRedirect,
			}
		}
	}
	return &clone
}

// stealthTLSConfig returns a randomized TLS config for stealth mode.
// It shuffles cipher suites (TLS 1.0-1.2) and curve preferences to
// vary the ClientHello fingerprint, while keeping InsecureSkipVerify
// as-is (security reporting, not bypass).
func stealthTLSConfig(insecureSkipVerify bool) *tls.Config {
	uaMu.Lock()
	choice := uaRng.Intn(3)
	uaMu.Unlock()
	cfg := &tls.Config{
		InsecureSkipVerify: insecureSkipVerify, // #nosec G402 -- scanner must complete handshakes with misconfigured targets to analyze them.
	}
	switch choice {
	case 0:
		cfg.MinVersion = tls.VersionTLS12
		cfg.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}
		cfg.CipherSuites = []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		}
	case 1:
		cfg.MinVersion = tls.VersionTLS12
		cfg.CurvePreferences = []tls.CurveID{tls.CurveP256, tls.X25519, tls.CurveP384}
		cfg.CipherSuites = []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		}
	default:
		cfg.MinVersion = tls.VersionTLS12
		cfg.CurvePreferences = []tls.CurveID{tls.CurveP256, tls.CurveP384, tls.X25519}
	}
	return cfg
}

// stealthJitter returns the per-request random sleep for stealth mode.
// Ghost mode uses Pareto 800-3500ms lognormal (plan P0); non-ghost retains
// the original 50-250ms uniform for fast safe scans.
func stealthJitter() time.Duration {
	if GhostEnabled {
		return ghostJitter()
	}
	// 50-250ms uniform. Uses the same locked RNG as UA selection to
	// avoid extra rand source.
	uaMu.Lock()
	n := uaRng.Intn(200) // 0-199
	uaMu.Unlock()
	return time.Duration(50+n) * time.Millisecond
}

// maybeJitter sleeps for stealth jitter if enabled, respecting ctx.
func (c *Client) maybeJitter(ctx context.Context) error {
	if !c.stealth {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(stealthJitter()):
		return nil
	}
}

// socksDialContext creates a DialContext that tunnels through a SOCKS5 proxy
// via x/net/proxy. The returned DialContext respects ctx cancellation.
func socksDialContext(pu *url.URL) func(context.Context, string, string) (net.Conn, error) {
	dialer, _ := proxy.FromURL(pu, proxy.Direct)
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		type res struct {
			c   net.Conn
			err error
		}
		ch := make(chan res, 1)
		go func() {
			c, err := dialer.Dial(network, address)
			ch <- res{c, err}
		}()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case r := <-ch:
			return r.c, r.err
		}
	}
}

// applyProxyToTransport applies the proxy URL pu to a *http.Transport clone
// handling both HTTP and SOCKS5 schemes via x/net/proxy.
func applyProxyToTransport(t *stdhttp.Transport, pu *url.URL, viaClone *Client) {
	scheme := strings.ToLower(pu.Scheme)
	if scheme == "socks5" || scheme == "socks5h" {
		// SOCKS5: use x/net/proxy dialer, no HTTP Proxy func (leak-free).
		t.Proxy = nil
		t.DialContext = socksDialContext(pu)
		return
	}
	t.Proxy = stdhttp.ProxyURL(pu)
	t.DialContext = viaClone.safeDialContext
}

// WithProxy returns a copy of c that routes all traffic through the
// given proxy URL (http, https, or socks5 — e.g. Burp/ZAP on
// http://127.0.0.1:8080). It overrides any proxy environment variables.
// Dial-time IP validation is skipped for the proxy hop (see viaProxy);
// URL-level target and redirect guards still apply.
//
// SOCKS5 is handled via golang.org/x/net/proxy (not http.ProxyURL) to
// avoid leaking the target IP when ProxyURL is misused.
func (c *Client) WithProxy(proxyRaw string) (*Client, error) {
	proxyRaw = strings.TrimSpace(proxyRaw)
	if proxyRaw == "" {
		return c, nil
	}
	pu, err := url.Parse(proxyRaw)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL %q: %w", proxyRaw, err)
	}
	switch strings.ToLower(pu.Scheme) {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, fmt.Errorf("invalid proxy URL %q: scheme must be http, https, or socks5", proxyRaw)
	}
	if pu.Host == "" {
		return nil, fmt.Errorf("invalid proxy URL %q: missing host:port", proxyRaw)
	}

	clone := *c
	clone.viaProxy = true
	// NOTE: Transport.DialContext holds a method value bound to the
	// original Client, so the (cloned) transport must be re-pointed at
	// the clone — otherwise the viaProxy exemption would never take
	// effect. Transport.Clone is used instead of a struct copy because
	// http.Transport contains a sync.Mutex (see `go vet` copylocks).
	switch tr := c.http.Transport.(type) {
	case *stdhttp.Transport:
		tcopy := tr.Clone()
		applyProxyToTransport(tcopy, pu, &clone)
		// If viaProxy but SOCKS dialer is used, we already set DialContext
		// to SOCKS; otherwise safeDialContext is set by helper.
		clone.http = &stdhttp.Client{
			Transport:     tcopy,
			Timeout:       c.http.Timeout,
			CheckRedirect: c.http.CheckRedirect,
		}
	case *GhostTransport:
		// Ghost wrapping std transport
		if inner, ok := tr.base.(*stdhttp.Transport); ok {
			tcopy := inner.Clone()
			applyProxyToTransport(tcopy, pu, &clone)
			clone.http = &stdhttp.Client{
				Transport:     &GhostTransport{base: tcopy, headerOrder: tr.headerOrder, spec: tr.spec},
				Timeout:       c.http.Timeout,
				CheckRedirect: c.http.CheckRedirect,
			}
		} else {
			return nil, fmt.Errorf("proxy cannot be applied: ghost transport is in an unexpected state")
		}
	case *authTransport:
		switch inner := tr.base.(type) {
		case *stdhttp.Transport:
			tcopy := inner.Clone()
			applyProxyToTransport(tcopy, pu, &clone)
			clone.http = &stdhttp.Client{
				Transport: &authTransport{
					base:    tcopy,
					headers: tr.headers,
				},
				Timeout:       c.http.Timeout,
				CheckRedirect: c.http.CheckRedirect,
			}
		case *GhostTransport:
			if ghostInner, ok := inner.base.(*stdhttp.Transport); ok {
				tcopy := ghostInner.Clone()
				applyProxyToTransport(tcopy, pu, &clone)
				newGhost := &GhostTransport{base: tcopy, headerOrder: inner.headerOrder, spec: inner.spec}
				clone.http = &stdhttp.Client{
					Transport: &authTransport{
						base:    newGhost,
						headers: tr.headers,
					},
					Timeout:       c.http.Timeout,
					CheckRedirect: c.http.CheckRedirect,
				}
			} else {
				return nil, fmt.Errorf("proxy cannot be applied: HTTP transport is in an unexpected state")
			}
		default:
			return nil, fmt.Errorf("proxy cannot be applied: HTTP transport is in an unexpected state")
		}
	default:
		return nil, fmt.Errorf("proxy cannot be applied: HTTP transport is in an unexpected state")
	}
	return &clone, nil
}

// proxyFromEnvironment implements standard HTTP_PROXY / HTTPS_PROXY /
// NO_PROXY handling (both upper- and lower-case names). It mirrors
// http.ProxyFromEnvironment without importing x/net.
func proxyFromEnvironment(req *stdhttp.Request) (*url.URL, error) {
	if req == nil || req.URL == nil {
		return nil, nil
	}
	scheme := strings.ToLower(req.URL.Scheme)
	var raw string
	if scheme == "https" {
		raw = firstNonEmpty(os.Getenv("HTTPS_PROXY"), os.Getenv("https_proxy"))
		if raw == "" {
			raw = firstNonEmpty(os.Getenv("HTTP_PROXY"), os.Getenv("http_proxy"))
		}
	} else {
		raw = firstNonEmpty(os.Getenv("HTTP_PROXY"), os.Getenv("http_proxy"))
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if noProxyMatch(req.URL.Hostname()) {
		return nil, nil
	}
	pu, err := url.Parse(raw)
	if err != nil {
		return nil, nil // ignore malformed env, fail open to direct
	}
	if pu.Scheme == "" {
		pu, err = url.Parse("http://" + raw)
		if err != nil {
			return nil, nil
		}
	}
	return pu, nil
}

// noProxyMatch reports whether host matches NO_PROXY / no_proxy
// (comma-separated suffixes, "*" meaning everything).
func noProxyMatch(host string) bool {
	raw := firstNonEmpty(os.Getenv("NO_PROXY"), os.Getenv("no_proxy"))
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, part := range strings.Split(raw, ",") {
		part = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(part, ".")))
		if part == "" {
			continue
		}
		if part == "*" || host == part || strings.HasSuffix(host, "."+strings.TrimPrefix(part, ".")) {
			return true
		}
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
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
	if c.limiter != nil {
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, err
		}
	}
	if err := c.maybeJitter(ctx); err != nil {
		return nil, err
	}
	req, err := stdhttp.NewRequestWithContext(ctx, stdhttp.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("User-Agent", c.effectiveUA())
	c.applyStealthHeaders(req)
	req.Header.Set("Accept", "*/*")
	c.applyJar(req)

	start := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	c.saveJar(req, resp)

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

// DoWithHeaders issues a request with extra headers through the same safety
// settings (redirect guard, safe dialing) and returns the captured
// response. Engines that need custom probes (CORS origin tests, OPTIONS
// audits) must use this instead of building their own clients so the
// local-network protections stay enforced in one place.
func (c *Client) DoWithHeaders(ctx context.Context, method, rawURL string, headers map[string]string) (*Response, error) {
	if c.limiter != nil {
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, err
		}
	}
	if err := c.maybeJitter(ctx); err != nil {
		return nil, err
	}
	req, err := stdhttp.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("User-Agent", c.effectiveUA())
	c.applyStealthHeaders(req)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	c.applyJar(req)

	start := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	c.saveJar(req, resp)

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

// PostJSON issues a POST request with a JSON body through the same safety
// settings as Get.  It is used by active rules that need to inject payloads
// into JSON request bodies (Phase 5 VectorJSONBody targets).
//
// extraHeaders is merged into the request after Content-Type is set so
// callers can pass auth headers from an AuthContext without overwriting it.
func (c *Client) PostJSON(ctx context.Context, rawURL, body string, extraHeaders map[string]string) (*Response, error) {
	if c.limiter != nil {
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, err
		}
	}
	if err := c.maybeJitter(ctx); err != nil {
		return nil, err
	}
	req, err := stdhttp.NewRequestWithContext(ctx, stdhttp.MethodPost, rawURL, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building POST request: %w", err)
	}
	req.Header.Set("User-Agent", c.effectiveUA())
	c.applyStealthHeaders(req)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, */*")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	c.applyJar(req)

	start := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	c.saveJar(req, resp)

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("reading POST response body: %w", err)
	}
	out := &Response{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       respBody,
		FinalURL:   resp.Request.URL.String(),
		Elapsed:    time.Since(start),
	}
	if resp.TLS != nil {
		out.TLS = resp.TLS
	}
	return out, nil
}

// PostRaw issues a POST request with a caller-specified Content-Type
// through the same safety settings as Get.  It is used by rules that
// probe content-type handling (e.g. schema content-confusion sends the
// same body as JSON, plain text, and form data and diffs the outcome).
//
// extraHeaders is merged into the request after Content-Type is set.
func (c *Client) PostRaw(ctx context.Context, rawURL, contentType, body string, extraHeaders map[string]string) (*Response, error) {
	if c.limiter != nil {
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, err
		}
	}
	if err := c.maybeJitter(ctx); err != nil {
		return nil, err
	}
	req, err := stdhttp.NewRequestWithContext(ctx, stdhttp.MethodPost, rawURL, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building POST request: %w", err)
	}
	req.Header.Set("User-Agent", c.effectiveUA())
	c.applyStealthHeaders(req)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json, */*")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	c.applyJar(req)

	start := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	c.saveJar(req, resp)

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("reading POST response body: %w", err)
	}
	out := &Response{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       respBody,
		FinalURL:   resp.Request.URL.String(),
		Elapsed:    time.Since(start),
	}
	if resp.TLS != nil {
		out.TLS = resp.TLS
	}
	return out, nil
}

// PostXML issues a POST request with an XML body through the same safety
// settings as Get.  It is used by the XXE active rule (Phase 12) which
// must send a well-formed XML document to endpoints that accept XML input.
//
// extraHeaders is merged into the request after Content-Type is set.
func (c *Client) PostXML(ctx context.Context, rawURL, body string, extraHeaders map[string]string) (*Response, error) {
	if c.limiter != nil {
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, err
		}
	}
	if err := c.maybeJitter(ctx); err != nil {
		return nil, err
	}
	req, err := stdhttp.NewRequestWithContext(ctx, stdhttp.MethodPost, rawURL, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building POST request: %w", err)
	}
	req.Header.Set("User-Agent", c.effectiveUA())
	c.applyStealthHeaders(req)
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("Accept", "application/xml, text/xml, */*")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	c.applyJar(req)

	start := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	c.saveJar(req, resp)

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("reading POST response body: %w", err)
	}
	out := &Response{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       respBody,
		FinalURL:   resp.Request.URL.String(),
		Elapsed:    time.Since(start),
	}
	if resp.TLS != nil {
		out.TLS = resp.TLS
	}
	return out, nil
}

// GetWithHost issues a GET request to rawURL but overrides the Host header
// sent on the wire to hostOverride.  This is used by the host-header-injection
// active rule (Phase 12D) which needs to send a forged Host value while still
// connecting to the real IP resolved from the original target URL.
//
// extraHeaders are merged in after Host is set so callers can inject
// X-Forwarded-Host and X-Forwarded-For in the same call.
func (c *Client) GetWithHost(ctx context.Context, rawURL, hostOverride string, extraHeaders map[string]string) (*Response, error) {
	if c.limiter != nil {
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, err
		}
	}
	if err := c.maybeJitter(ctx); err != nil {
		return nil, err
	}
	req, err := stdhttp.NewRequestWithContext(ctx, stdhttp.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("User-Agent", c.effectiveUA())
	c.applyStealthHeaders(req)
	// req.Host overrides the Host header on the wire; req.Header.Set("Host",...)
	// is ignored by Go's HTTP stack.
	req.Host = hostOverride
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	c.applyJar(req)

	start := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	c.saveJar(req, resp)

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

// PostMultipart issues a POST multipart/form-data request via the same
// safety settings as Get. It is used by the file upload active rule
// (P2) which sends a polyglot payload to endpoints that accept uploads.
// params are regular form fields, fileField/fileName/fileContent define
// an optional file part (when fileField != "").
func (c *Client) PostMultipart(ctx context.Context, rawURL string, params map[string]string, fileField, fileName string, fileContent []byte, extraHeaders map[string]string) (*Response, error) {
	if c.limiter != nil {
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, err
		}
	}
	if err := c.maybeJitter(ctx); err != nil {
		return nil, err
	}
	var bodyBuf bytes.Buffer
	w := multipart.NewWriter(&bodyBuf)
	for k, v := range params {
		_ = w.WriteField(k, v)
	}
	if fileField != "" {
		fw, err := w.CreateFormFile(fileField, fileName)
		if err != nil {
			return nil, err
		}
		if _, err := fw.Write(fileContent); err != nil {
			return nil, err
		}
	}
	_ = w.Close()
	req, err := stdhttp.NewRequestWithContext(ctx, stdhttp.MethodPost, rawURL, &bodyBuf)
	if err != nil {
		return nil, fmt.Errorf("building multipart request: %w", err)
	}
	req.Header.Set("User-Agent", c.effectiveUA())
	c.applyStealthHeaders(req)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Accept", "*/*")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	c.applyJar(req)
	start := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	c.saveJar(req, resp)
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("reading multipart response body: %w", err)
	}
	out := &Response{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       respBody,
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
	if c.limiter != nil {
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, err
		}
	}
	if err := c.maybeJitter(ctx); err != nil {
		return nil, err
	}
	req, err := stdhttp.NewRequestWithContext(ctx, stdhttp.MethodHead, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.effectiveUA())
	c.applyStealthHeaders(req)
	c.applyJar(req)
	resp, err := c.http.Do(req)
	if err == nil {
		defer resp.Body.Close()
		c.saveJar(req, resp)
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
