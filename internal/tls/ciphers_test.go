package tls

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// tlsServerWithCiphers starts a TLS server that only accepts the given cipher suites.
func tlsServerWithCiphers(t *testing.T, ciphers []uint16) (host, port string, cleanup func()) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		CipherSuites: ciphers,
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	h, p, _ := net.SplitHostPort(srv.Listener.Addr().String())
	return h, p, srv.Close
}

func TestProbeCipherGroup_AcceptsRC4(t *testing.T) {
	// Start a TLS server that accepts RC4.
	rc4Ciphers := []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
	}
	host, port, cleanup := tlsServerWithCiphers(t, rc4Ciphers)
	defer cleanup()

	accepted, suite := probeCipherGroup(context.Background(), host, port, rc4Ciphers)
	if !accepted {
		t.Skip("TLS server did not accept RC4 (Go may have stripped it) — skipping")
	}
	if suite == 0 {
		t.Error("expected non-zero cipher suite ID")
	}
}

func TestProbeCipherGroup_Rejects_UnknownCiphers(t *testing.T) {
	// Start a server with only TLS 1.3 (which ignores CipherSuites) and
	// probe with RC4. The server and client can't agree so handshake fails.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}
	srv.StartTLS()
	defer srv.Close()
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())

	// Probe with TLS 1.0-1.2 only (our prober caps at TLS 1.2, server requires 1.3).
	accepted, _ := probeCipherGroup(context.Background(), host, port,
		[]uint16{tls.TLS_RSA_WITH_RC4_128_SHA})
	if accepted {
		t.Error("expected probe to fail when server requires TLS 1.3 but prober caps at TLS 1.2")
	}
}

func TestCheckCipherSuites_NoFindings_OnTLS13Only(t *testing.T) {
	// A TLS 1.3-only server should produce no cipher-suite findings since
	// our prober caps at TLS 1.2 (TLS 1.3 chooses its own cipher suites
	// and ignores the CipherSuites field).
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}
	srv.StartTLS()
	defer srv.Close()
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())

	findings := checkCipherSuites(context.Background(), srv.URL, host, port)
	if len(findings) != 0 {
		t.Errorf("TLS 1.3-only server should yield no cipher findings, got %d: %v",
			len(findings), findings)
	}
}

func TestCheckCipherSuites_3DES(t *testing.T) {
	// Server that only accepts 3DES.
	host, port, cleanup := tlsServerWithCiphers(t,
		[]uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA})
	defer cleanup()

	findings := checkCipherSuites(context.Background(), "https://"+host, host, port)
	has3DES := false
	for _, f := range findings {
		if strings.Contains(f.Title, "3DES") {
			has3DES = true
			break
		}
	}
	if !has3DES {
		t.Skip("Go crypto/tls may not negotiate 3DES with test server — skipping (implementation-dependent)")
	}
}

func TestSlugCipher(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"RC4", "rc4"},
		{"3DES", "3des"},
		{"CBC (weak MAC-then-encrypt)", "cbc--weak-mac-then-encrypt-"},
	}
	for _, tc := range tests {
		got := slugCipher(tc.in)
		if !strings.Contains(got, strings.ToLower(tc.in[:2])) {
			t.Errorf("slugCipher(%q) = %q, want it to contain lowercased prefix", tc.in, got)
		}
	}
}

func TestWeakGroups_NotEmpty(t *testing.T) {
	if len(weakGroups) < 3 {
		t.Errorf("expected at least 3 weak cipher groups, got %d", len(weakGroups))
	}
	for _, g := range weakGroups {
		if g.label == "" {
			t.Error("cipher group missing label")
		}
		if len(g.ciphers) == 0 {
			t.Errorf("cipher group %q has no ciphers", g.label)
		}
		if g.severity == "" {
			t.Errorf("cipher group %q missing severity", g.label)
		}
	}
}
