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

func init() { scanner.AllowLocalNetwork = true }

func newTestContext(t *testing.T, srv *httptest.Server) *scanner.ScanContext {
	t.Helper()
	vt, err := scanner.ValidateTarget(srv.URL)
	if err != nil {
		t.Fatalf("validating test target: %v", err)
	}
	return &scanner.ScanContext{Target: vt, Config: models.ScanConfig{Profile: models.ProfileSafe}}
}

func TestCORS_NoHeaders_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res, err := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Run(context.Background(), newTestContext(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings, got %+v", res.Findings)
	}
}

func TestCORS_WildcardWithCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}))
	defer srv.Close()

	res, err := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Run(context.Background(), newTestContext(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range res.Findings {
		if f.Severity == models.SeverityMedium && f.Title == "CORS wildcard combined with credentials" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected wildcard+credentials finding, got %+v", res.Findings)
	}
}

func TestCORS_WildcardOnly_LowSeverity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res, err := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Run(context.Background(), newTestContext(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if f.Severity == models.SeverityLow && f.Title == "CORS allows any origin (no credentials)" {
			return
		}
	}
	t.Fatalf("expected wildcard-only low-severity finding, got %+v", res.Findings)
}

func TestCORS_ReflectsArbitraryOriginWithCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res, err := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Run(context.Background(), newTestContext(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range res.Findings {
		if f.Severity == models.SeverityHigh && f.Title == "CORS reflects arbitrary origins with credentials" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected reflection finding, got %+v", res.Findings)
	}
}

func TestCORS_Name(t *testing.T) {
	if got := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Name(); got != "cors" {
		t.Fatalf("got %q", got)
	}
}
