package cors

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

func hasFindingID(fs []models.Finding, id string) bool {
	for _, f := range fs {
		if f.ID == id {
			return true
		}
	}
	return false
}

func TestCORS_NoHeaders_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	s := New(anpuhttp.NewClientWithLocalNetworkAllowed(true))
	res, err := s.Run(context.Background(), newTestContext(t, srv))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected no findings when no CORS headers are set, got %d", len(res.Findings))
	}
}

func TestCORS_WildcardWithCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	s := New(anpuhttp.NewClientWithLocalNetworkAllowed(true))
	res, err := s.Run(context.Background(), newTestContext(t, srv))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasFindingID(res.Findings, "cors-wildcard-cors-combined-with-credentials") {
		t.Errorf("expected wildcard+credentials finding, got: %+v", res.Findings)
	}
}

func TestCORS_WildcardOnly_LowSeverity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	s := New(anpuhttp.NewClientWithLocalNetworkAllowed(true))
	res, err := s.Run(context.Background(), newTestContext(t, srv))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range res.Findings {
		if f.ID == "cors-cors-allows-any-origin-no-credentials" {
			if f.Severity != models.SeverityLow {
				t.Errorf("expected low severity for bare wildcard, got %s", f.Severity)
			}
			return
		}
	}
	t.Errorf("expected wildcard-only finding, got: %+v", res.Findings)
}

func TestCORS_ReflectsArbitraryOriginWithCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	s := New(anpuhttp.NewClientWithLocalNetworkAllowed(true))
	res, err := s.Run(context.Background(), newTestContext(t, srv))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range res.Findings {
		if f.ID == "cors-cors-reflects-arbitrary-origins-with-credentials" {
			found = true
			if f.Severity != models.SeverityHigh {
				t.Errorf("expected high severity for reflected origin + credentials, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("expected origin-reflection-with-credentials finding, got: %+v", res.Findings)
	}
}

func TestCORS_Name(t *testing.T) {
	s := New(anpuhttp.NewClientWithLocalNetworkAllowed(true))
	if s.Name() != "cors" {
		t.Errorf("expected name 'cors', got %q", s.Name())
	}
}
