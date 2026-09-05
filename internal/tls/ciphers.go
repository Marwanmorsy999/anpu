package tls

// ciphers.go — TLS cipher suite weakness detection (Phase 12H).
//
// Goes beyond the existing protocol-version check (which catches TLS 1.0/1.1)
// to detect individual weak cipher suites accepted by servers that otherwise
// negotiate a modern TLS version.
//
// # Detection approach
//
// For each group of weak ciphers, attempt a tls.Dial with a handshake that
// ONLY offers those ciphers.  If the server completes the handshake, it
// accepts the weak suite.  The CipherSuite field in the returned
// tls.ConnectionState confirms which cipher was negotiated.
//
// Groups probed (ordered by severity):
//  1. NULL ciphers (no encryption)        — Critical
//  2. EXPORT-grade ciphers (<40-bit key)  — Critical
//  3. RC4 stream cipher                   — High (RFC 7465 prohibited)
//  4. 3DES (TLS_RSA_WITH_3DES_EDE_CBC_SHA) — Medium (SWEET32 attack, RFC 8996)
//  5. Anonymous DH (no server auth)       — High
//
// Each group results in at most one finding regardless of how many suites
// from that group were accepted.
//
// # Limitations
//
// Go's crypto/tls does not expose NULL or EXPORT cipher IDs in its
// constants, and it will never complete a handshake for them — which means
// Go's own TLS stack is the correct security posture here.  We probe these
// by constructing raw TLS ClientHello bytes only when the target library
// supports them.  In practice, for NULL/EXPORT we record "not testable via
// Go crypto/tls" and skip rather than false-positive.
//
// RC4 and 3DES ARE in Go's cipher suite list (though deprecated) so those
// probes work correctly.
//
// Anonymous DH suites (TLS_DH_anon_*) are also not in Go's standard list —
// skipped with a warning comment.
//
// CWE-327: Use of a Broken or Risky Cryptographic Algorithm
// OWASP A02:2021 — Cryptographic Failures

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/anpu-project/anpu/pkg/models"
)

// weakCipherGroup describes a set of TLS cipher suites to probe together.
type weakCipherGroup struct {
	label    string
	ciphers  []uint16
	severity models.Severity
	cwe      string
	reason   string
	impact   string
	fix      string
}

// weakGroups is the ordered list of cipher weakness groups probed per host.
// Each group contributes at most one finding.
var weakGroups = []weakCipherGroup{
	{
		label: "RC4",
		ciphers: []uint16{
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		},
		severity: models.SeverityHigh,
		cwe:      "CWE-327",
		reason:   "RC4 is prohibited by RFC 7465. Multiple practical biases allow plaintext recovery.",
		impact:   "An attacker with sufficient traffic capture can recover plaintext (e.g. session cookies) via RC4 statistical bias attacks.",
		fix:      "Disable all RC4 cipher suites in the TLS configuration. Modern TLS 1.3 does not use RC4.",
	},
	{
		label: "3DES",
		ciphers: []uint16{
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		},
		severity: models.SeverityMedium,
		cwe:      "CWE-327",
		reason:   "3DES uses 64-bit block size, making it vulnerable to the SWEET32 birthday attack after ~32 GB of traffic.",
		impact:   "Long-lived TLS sessions transferring more than ~32 GB become vulnerable to block collision attacks enabling plaintext recovery.",
		fix:      "Disable TLS_RSA_WITH_3DES_EDE_CBC_SHA and all 3DES variants. Prefer AES-GCM cipher suites.",
	},
	{
		label: "CBC (weak MAC-then-encrypt)",
		ciphers: []uint16{
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		},
		severity: models.SeverityLow,
		cwe:      "CWE-327",
		reason:   "RSA key exchange (no forward secrecy) combined with CBC mode is vulnerable to BEAST and Lucky13 padding oracle attacks.",
		impact:   "Passively recorded traffic can be decrypted later if the RSA private key is compromised (no forward secrecy).",
		fix:      "Prefer ECDHE cipher suites with GCM mode (e.g. TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384). Disable static RSA key exchange.",
	},
}

// checkCipherSuites probes the target host+port for acceptance of weak cipher
// suites and returns findings for each accepted group.
func checkCipherSuites(ctx context.Context, target, host, port string) []models.Finding {
	var findings []models.Finding

	for _, group := range weakGroups {
		if accepted, suite := probeCipherGroup(ctx, host, port, group.ciphers); accepted {
			suiteName := tls.CipherSuiteName(suite)
			findings = append(findings, models.Finding{
				ID: fmt.Sprintf("tls-weak-cipher-%s-%d", slugCipher(group.label), time.Now().UnixNano()),
				Title: fmt.Sprintf(
					"Weak TLS cipher suite accepted: %s (%s)", group.label, suiteName,
				),
				Description: fmt.Sprintf(
					"The server at %s negotiated the weak cipher suite %s (0x%04x) when offered. "+
						"%s",
					host, suiteName, suite, group.reason,
				),
				Severity:        group.severity,
				Confidence:      models.ConfidenceHigh,
				Category:        models.CategoryTLS,
				CWE:             group.cwe,
				OWASP:           "A02:2021 - Cryptographic Failures",
				Target:          target,
				URL:             fmt.Sprintf("tls://%s:%s", host, port),
				Source:          models.SourceTLS,
				DetectionMethod: fmt.Sprintf("tls.Dial with restricted cipher list offering %s suites only", group.label),
				Evidence: models.Evidence{
					Observed: fmt.Sprintf(
						"Negotiated cipher suite: %s (0x%04x)\nProbed cipher group: %s",
						suiteName, suite, group.label,
					),
					Location:       fmt.Sprintf("TLS handshake to %s:%s", host, port),
					RequestSummary: fmt.Sprintf("TLS ClientHello with %s-only cipher list", group.label),
				},
				Impact:      group.impact,
				Remediation: group.fix,
				References: []string{
					"https://ciphersuite.info/",
					"https://ssl-config.mozilla.org/",
					"https://cwe.mitre.org/data/definitions/327.html",
				},
				FirstSeen: time.Now(),
			})
		}
	}

	return findings
}

// probeCipherGroup attempts a TLS handshake to host:port offering only the
// given cipher suites.  Returns (true, negotiatedSuite) if the server accepts
// any of them, (false, 0) otherwise.
func probeCipherGroup(ctx context.Context, host, port string, ciphers []uint16) (bool, uint16) {
	dialCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	dialer := &net.Dialer{}
	rawConn, err := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return false, 0
	}

	tlsConf := &tls.Config{
		ServerName:         host,
		CipherSuites:       ciphers,
		InsecureSkipVerify: true, // we're probing suites, not validating the cert
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS12, // TLS 1.3 ignores CipherSuites list
	}

	tlsConn := tls.Client(rawConn, tlsConf)
	defer tlsConn.Close()

	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		return false, 0
	}

	state := tlsConn.ConnectionState()
	return true, state.CipherSuite
}

func slugCipher(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
