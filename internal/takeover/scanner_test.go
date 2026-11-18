package takeover

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// fakeResolver injects CNAME / IP fixtures so tests never touch real DNS.
type fakeResolver struct {
	cname string
	ips   []net.IPAddr
}

func (f *fakeResolver) LookupCNAME(_ context.Context, _ string) (string, error) {
	if f.cname == "" {
		return "", &net.DNSError{Err: "no such host", IsNotFound: true}
	}
	return f.cname, nil
}

func (f *fakeResolver) LookupIPAddr(_ context.Context, _ string) ([]net.IPAddr, error) {
	return f.ips, nil
}

func testContext(srvURL string) *scanner.ScanContext {
	u, _ := url.Parse(srvURL)
	return &scanner.ScanContext{
		Target:     &scanner.ValidatedTarget{Raw: srvURL, URL: u, Host: u.Hostname()},
		Subdomains: []string{},
	}
}

// Regression (v0.5.7 P0-1): a hostile/mis-resolved subdomain must be
// refused at the dial layer. The scanner previously built its own raw
// http.Client with no IP validation, so a CNAME fingerprint match whose
// host resolved to loopback/internal would be fetched — classic SSRF via
// DNS. Here the "subdomain" resolves to loopback where a fingerprint-
// serving fixture listens; the guarded client must refuse to connect,
// surface a warning, and never deliver the fingerprint body.
func TestHostileMisResolvedSubdomainRefusedAtDialLayer(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		// GitHub Pages unclaimed-resource body: with the old raw client
		// this body would complete the two-signal takeover match.
		_, _ = w.Write([]byte("There isn't a GitHub Pages site here."))
	}))
	defer srv.Close()
	srvURL := srv.URL                    // http://127.0.0.1:<port>
	host := srv.Listener.Addr().String() // 127.0.0.1:<port> — the mis-resolved subdomain

	sc := testContext(srvURL)
	sc.Subdomains = []string{host}

	s := New(anpuhttp.NewClient()) // guarded client: local network NOT allowed
	s.resolver = &fakeResolver{cname: "victim.github.io.", ips: []net.IPAddr{
		{IP: net.ParseIP("127.0.0.1")},
	}}

	res, err := s.Run(context.Background(), sc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if n := atomic.LoadInt64(&hits); n != 0 {
		t.Fatalf("guarded client must refuse loopback at dial layer; fixture got %d requests", n)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("refused dial must not yield findings, got %d", len(res.Findings))
	}
	if len(res.Warnings) == 0 {
		t.Fatal("refused dial must surface a warning, got none")
	}
}

// Positive control for the dial-guard test above: with the local-network
// test override enabled, the exact same fixture must still be fingerprinted
// and reported — proving the guarded client did not break detection, and
// that the refusal in the previous test comes from the dial guard alone.
func TestGuardedClientStillDetectsTakeoverOnLocalFixture(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("There isn't a GitHub Pages site here."))
	}))
	defer srv.Close()
	host := srv.Listener.Addr().String()

	sc := testContext(srv.URL)
	sc.Subdomains = []string{host}

	s := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)) // test fixture override
	s.resolver = &fakeResolver{cname: "victim.github.io.", ips: []net.IPAddr{
		{IP: net.ParseIP("127.0.0.1")},
	}}

	res, err := s.Run(context.Background(), sc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 takeover finding on local fixture, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Severity != models.SeverityHigh {
		t.Fatalf("GitHub Pages takeover should be high severity, got %v", f.Severity)
	}
}

// CNAME matches a provider but the body carries no dangling marker —
// no finding (two-signal requirement preserved through the guarded client).
func TestCNAMEMatchWithoutBodyMarkerStaysSilent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>ordinary site, nothing unclaimed here</body></html>"))
	}))
	defer srv.Close()
	host := srv.Listener.Addr().String()

	sc := testContext(srv.URL)
	sc.Subdomains = []string{host}

	s := New(anpuhttp.NewClientWithLocalNetworkAllowed(true))
	s.resolver = &fakeResolver{cname: "victim.github.io."}

	res, err := s.Run(context.Background(), sc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("CNAME match without body marker must stay silent, got %d findings", len(res.Findings))
	}
}

// Dangling-CNAME path: an unresolvable, non-fingerprinted CNAME target
// must still produce the dangling finding (NXDOMAIN path untouched by the
// client swap).
func TestDanglingCNAMENonFingerprintedStillReported(t *testing.T) {
	host := "blog.example.com"

	sc := testContext("https://example.com")
	sc.Subdomains = []string{host}

	// The dangling check requires a NotFound DNS error from LookupIPAddr;
	// nxResolver simulates a CNAME whose target is NXDOMAIN.
	s := New(anpuhttp.NewClient())
	s.resolver = &nxResolver{}

	res, err := s.Run(context.Background(), sc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 dangling CNAME finding, got %d", len(res.Findings))
	}
}

// nxResolver simulates a CNAME that exists but whose target is NXDOMAIN.
type nxResolver struct{}

func (*nxResolver) LookupCNAME(_ context.Context, _ string) (string, error) {
	return "dead-host.invalid.", nil
}

func (*nxResolver) LookupIPAddr(_ context.Context, _ string) ([]net.IPAddr, error) {
	return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
}
