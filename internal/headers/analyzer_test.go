package headers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

func init() {
	scanner.AllowLocalNetwork = true // httptest servers bind to 127.0.0.1
}

func newTestContext(t *testing.T, srv *httptest.Server) *scanner.ScanContext {
	t.Helper()
	vt, err := scanner.ValidateTarget(srv.URL)
	if err != nil {
		t.Fatalf("validating test target: %v", err)
	}
	return &scanner.ScanContext{Target: vt, Config: models.ScanConfig{Profile: models.ProfileSafe}}
}

func TestHeadersAnalyzer_MissingCSP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	a := New(anpuhttp.NewClientWithLocalNetworkAllowed(true))
	res, err := a.Run(context.Background(), newTestContext(t, srv))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasFindingID(res.Findings, "headers-missing-csp") {
		t.Error("expected headers-missing-csp finding")
	}
}

func TestHeadersAnalyzer_CSPPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	a := New(anpuhttp.NewClientWithLocalNetworkAllowed(true))
	res, err := a.Run(context.Background(), newTestContext(t, srv))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasFindingID(res.Findings, "headers-missing-csp") {
		t.Error("did not expect headers-missing-csp finding when CSP is set")
	}
}

func TestHeadersAnalyzer_ServerVersionDisclosure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	a := New(anpuhttp.NewClientWithLocalNetworkAllowed(true))
	res, err := a.Run(context.Background(), newTestContext(t, srv))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasFindingID(res.Findings, "headers-server-disclosure") {
		t.Error("expected headers-server-disclosure finding")
	}
}

func TestHeadersAnalyzer_NeverFabricatesEvidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	a := New(anpuhttp.NewClientWithLocalNetworkAllowed(true))
	res, err := a.Run(context.Background(), newTestContext(t, srv))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range res.Findings {
		if f.Evidence.Unavailable && f.Evidence.Observed != "" {
			t.Errorf("finding %s marked Unavailable but has Observed content: %q", f.ID, f.Evidence.Observed)
		}
	}
}

func hasFindingID(fs []models.Finding, id string) bool {
	for _, f := range fs {
		if f.ID == id {
			return true
		}
	}
	return false
}
