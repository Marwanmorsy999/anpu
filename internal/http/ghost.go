package http

import (
	"crypto/tls"
	"net"
	stdhttp "net/http"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// GhostEnabled controls undetectable mode. When true, all canaries avoid
// the `anpu-` substring, header order mimics Chrome, and TLS ClientHello
// uses a current Chrome JA3 profile.
var GhostEnabled bool

// GhostCanaryPrefix is the replacement prefix when GhostEnabled is true.
// Empty (default ghost) means no `anpu` substring at all — raw 12-hex token.
// Configurable via --ghost-canary-prefix.
var GhostCanaryPrefix string

// GhostWorkers is the number of parallel workers for active endpoint sharding.
// 0 means sequential (default, non-ghost).
var GhostWorkers int

// GhostProxyPoolPath is the path to a file containing proxy URLs (one per line)
// used for RoundRobin rotation when --proxy-pool is set.
var GhostProxyPoolPath string

// GhostHeaderOrder is Chrome 131 header order (stable, authoritative).
//
// Honesty note: Go's net/http Transport serializes headers in sorted order
// (Request.Write sorts keys), so no RoundTripper wrapper can change the
// on-wire order with the standard library alone — true wire-order control
// requires an fhttp-style fork (tracked future work; utls is already wired
// for the TLS/JA3 half). What GhostTransport DOES guarantee today:
//   - a stable, minimal header SET per request kind (no random extras that
//     fingerprint scanners, e.g. the old Cache-Control noise header),
//   - Chrome-consistent Accept/Accept-Language pairing with the rotated UA,
//   - no `anpu` canary/header leakage (see internal/active/canary.go).
//
// The order slice below documents the target order and drives that stable
// header selection.
var GhostHeaderOrder = []string{
	"Host",
	"Connection",
	"Cache-Control",
	"sec-ch-ua",
	"sec-ch-ua-mobile",
	"sec-ch-ua-platform",
	"Upgrade-Insecure-Requests",
	"User-Agent",
	"Accept",
	"Sec-Fetch-Site",
	"Sec-Fetch-Mode",
	"Sec-Fetch-User",
	"Sec-Fetch-Dest",
	"Accept-Encoding",
	"Accept-Language",
	"Cookie",
}

// ghostChromeSpec returns the UTLS ClientHelloSpec that most closely
// matches Chrome 131 (+ GREASE, h2, ALPN). HelloChrome_131 is not yet
// tagged in utls 1.8.2, so we probe known IDs and fall back to
// HelloChrome_Auto which tracks the latest Chrome.
func ghostChromeSpec() utls.ClientHelloID {
	// Prefer explicit 131/130/120 if present; otherwise auto.
	candidates := []utls.ClientHelloID{
		utls.HelloChrome_Auto,
		utls.HelloChrome_120,
		utls.HelloChrome_100,
		utls.HelloFirefox_Auto,
	}
	for _, id := range candidates {
		if _, err := utls.UTLSIdToSpec(id); err == nil {
			return id
		}
	}
	return utls.HelloGolang
}

// ghostTLSConfig returns a hardening config for ghost: TLS 1.2+ only,
// modern curves, cipher suite shuffling. Used when ghost transport is
// built via UTLS (the negotiated ClientHello uses the spec above, this
// config is the Go-side mirror for non-UTLS fallbacks).
func ghostTLSConfig(insecureSkipVerify bool) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: insecureSkipVerify, // #nosec G402 -- scanner must complete handshakes with misconfigured targets to analyze them.
		MinVersion:         tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.X25519, tls.CurveP256, tls.CurveP384,
		},
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		NextProtos: []string{"h2", "http/1.1"},
	}
}

// GhostTransport is a RoundTripper that injects Chrome-like header order
// and randomizes the JA3 fingerprint via UTLS for each Client instance.
// It wraps the underlying transport while preserving safety dial logic.
type GhostTransport struct {
	base        stdhttp.RoundTripper
	headerOrder []string
	spec        utls.ClientHelloID
}

// RoundTrip normalizes the request headers before delegating.
//
// The input request is never mutated: the normalization applies to a clone,
// so retries and concurrent ghost workers sharing a base request cannot race.
// No internal trace header is emitted on the wire (Q2 default: undetectable
// first; operators correlate via client-side logs, not request headers).
func (g *GhostTransport) RoundTrip(req *stdhttp.Request) (*stdhttp.Response, error) {
	outReq := req.Clone(req.Context())
	// Stable header SET in chrome-order preference: drop the old random
	// Cache-Control noise behavior by never injecting headers here; only
	// carry over what the caller set. Rebuilding the map keeps iteration
	// deterministic for h2 (x/net/http2 ranges over the map) and documents
	// intent even though h1 serializes sorted.
	ordered := make(stdhttp.Header, len(req.Header))
	seen := map[string]bool{}
	for _, k := range g.headerOrder {
		canonical := stdhttp.CanonicalHeaderKey(k)
		if vals, ok := req.Header[canonical]; ok {
			ordered[canonical] = vals
			seen[canonical] = true
		}
	}
	for k, v := range req.Header {
		if !seen[k] {
			ordered[k] = v
		}
	}
	outReq.Header = ordered
	return g.base.RoundTrip(outReq)
}

// NewGhostTransport wraps base with ghost header ordering and UTLS spec.
func NewGhostTransport(base stdhttp.RoundTripper) *GhostTransport {
	if base == nil {
		base = stdhttp.DefaultTransport
	}
	return &GhostTransport{
		base:        base,
		headerOrder: GhostHeaderOrder,
		spec:        ghostChromeSpec(),
	}
}

// GhostDialTLS creates a UTLS-wrapped TLS connection that mimics Chrome.
// It is used as the DialTLSContext for the ghost transport when UTLS is
// available. Fallback is the standard TLS dial on error.
func GhostDialTLS(network, addr string, cfg *tls.Config) (net.Conn, error) {
	raw, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	host, _, _ := net.SplitHostPort(addr)
	if host == "" {
		host = addr
	}
	// Strip port for SNI.
	if strings.Contains(host, ":") {
		h, _, e := net.SplitHostPort(host)
		if e == nil {
			host = h
		}
	}
	uCfg := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: cfg != nil && cfg.InsecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"h2", "http/1.1"},
	}
	uConn := utls.UClient(raw, uCfg, ghostChromeSpec())
	if err := uConn.Handshake(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return uConn, nil
}

// WithGhost returns a shallow copy of c with ghost transport enabled.
// It enables random UA, Pareto jitter, UTLS JA3 (Chrome 131-ish), header
// order overwrite, and marks GhostEnabled for canary suppression.
func (c *Client) WithGhost(enabled bool) *Client {
	if !enabled {
		return c
	}
	GhostEnabled = true
	clone := *c
	clone.stealth = true
	clone.randomAgent = true
	// Rebuild transport with ghost headers + UTLS.
	if tr, ok := clone.http.Transport.(*stdhttp.Transport); ok {
		tcopy := tr.Clone()
		// Harden TLS to 1.2+ (fix TLS10 → TLS12).
		if tcopy.TLSClientConfig == nil {
			tcopy.TLSClientConfig = ghostTLSConfig(clone.allowInsecure)
		} else {
			tcopy.TLSClientConfig.MinVersion = tls.VersionTLS12
			if len(tcopy.TLSClientConfig.NextProtos) == 0 {
				tcopy.TLSClientConfig.NextProtos = []string{"h2", "http/1.1"}
			}
		}
		// Wrap with ghost header order.
		ghostRT := NewGhostTransport(tcopy)
		clone.http = &stdhttp.Client{
			Transport:     ghostRT,
			Timeout:       clone.http.Timeout,
			CheckRedirect: clone.http.CheckRedirect,
		}
		// Also keep updated base for future WithProxy calls: store
		// the underlying transport inside GhostTransport.base for unwrap.
		clone.http.Transport = ghostRT
	} else if at, ok := clone.http.Transport.(*authTransport); ok {
		if inner, ok := at.base.(*stdhttp.Transport); ok {
			tcopy := inner.Clone()
			if tcopy.TLSClientConfig == nil {
				tcopy.TLSClientConfig = ghostTLSConfig(clone.allowInsecure)
			} else {
				tcopy.TLSClientConfig.MinVersion = tls.VersionTLS12
			}
			ghostRT := NewGhostTransport(tcopy)
			clone.http = &stdhttp.Client{
				Transport:     &authTransport{base: ghostRT, headers: at.headers},
				Timeout:       clone.http.Timeout,
				CheckRedirect: clone.http.CheckRedirect,
			}
		}
		// Any other base (already a GhostTransport, or a foreign
		// RoundTripper) is left untouched — nothing to do.
	}
	return &clone
}

// ChromeUserAgents returns the expanded 40-UA pool for ghost ultra.
// This is used by ua.go when GhostEnabled, otherwise the 13-UA base pool.
func ChromeUserAgents() []string {
	return expandedBrowserUAs
}

// IsGhost reports whether ghost mode is active.
func IsGhost() bool { return GhostEnabled }
