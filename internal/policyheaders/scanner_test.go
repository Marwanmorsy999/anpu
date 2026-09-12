package policyheaders

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
)

func policyClient() *anpuhttp.Client {
	return anpuhttp.NewClientWithLocalNetworkAllowed(true)
}

func policyContext(srv string) *scanner.ScanContext {
	u, _ := url.Parse(srv)
	host := ""
	if u != nil {
		host = u.Hostname()
	}
	return &scanner.ScanContext{Target: &scanner.ValidatedTarget{Raw: srv, URL: u, Host: host}}
}

// Missing HSTS is owned by the Headers posture finding — policyheaders
// must stay silent so the row is not duplicated.
func TestMissingHSTSIsSilent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><body>hi</body></html>"))
	}))
	defer srv.Close()
	res, err := New(policyClient()).Run(context.Background(), policyContext(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range res.Findings {
		if f.ID == "policyheaders-hsts-missing" || f.ID == "policyheaders-coop-missing" ||
			f.ID == "policyheaders-coep-missing" || f.ID == "policyheaders-corp-missing" {
			t.Fatalf("presence gaps belong to posture, got %q", f.ID)
		}
	}
	if len(res.Findings) != 0 {
		t.Fatalf("bare response must yield nothing here, got %d (%q)", len(res.Findings), res.Findings[0].ID)
	}
}

// Present-but-not-ready HSTS still earns its readiness row (pure parse:
// the live path needs HTTPS, which httptest TLS cannot provide here).
func TestPreloadReadinessRow(t *testing.T) {
	rd := parseHSTS("max-age=86400")
	if !rd.present || rd.preloadReady {
		t.Fatalf("weak max-age must be present and not ready: %+v", rd)
	}
	if len(rd.preloadDeficits) == 0 {
		t.Fatal("must name the deficits")
	}
	rd = parseHSTS("max-age=31536000; includeSubDomains; preload")
	if !rd.preloadReady {
		t.Fatalf("full HSTS must be ready: %+v", rd)
	}
}
