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

func testContext(t *testing.T, srv *httptest.Server) *scanner.ScanContext {
	t.Helper()
	vt, err := scanner.ValidateTarget(srv.URL)
	if err != nil {
		t.Fatalf("validate target: %v", err)
	}
	return &scanner.ScanContext{Target: vt, Config: models.ScanConfig{Profile: models.ProfileSafe}}
}

func findingID(fs []models.Finding, id string) *models.Finding {
	for i := range fs {
		if fs[i].ID == id {
			return &fs[i]
		}
	}
	return nil
}

func TestCORS_NoHeaders_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer srv.Close()
	res, err := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Run(context.Background(), testContext(t, srv))
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
	res, err := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Run(context.Background(), testContext(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	f := findingID(res.Findings, "cors-wildcard-cors-combined-with-credentials")
	if f == nil {
		t.Fatalf("expected wildcard+credentials finding, got %+v", res.Findings)
	}
	if f.Severity != models.SeverityMedium {
		t.Fatalf("expected medium severity, got %s", f.Severity)
	}
}

func TestCORS_WildcardOnly_LowSeverity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Access-Control-Allow-Origin", "*") }))
	defer srv.Close()
	res, err := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Run(context.Background(), testContext(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	f := findingID(res.Findings, "cors-cors-allows-any-origin-no-credentials")
	if f == nil {
		t.Fatalf("expected wildcard finding, got %+v", res.Findings)
	}
	if f.Severity != models.SeverityLow {
		t.Fatalf("expected low severity, got %s", f.Severity)
	}
}

func TestCORS_ReflectsArbitraryOriginWithCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
	}))
	defer srv.Close()
	res, err := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Run(context.Background(), testContext(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	f := findingID(res.Findings, "cors-cors-reflects-arbitrary-origins-with-credentials")
	if f == nil {
		t.Fatalf("expected reflection finding, got %+v", res.Findings)
	}
	if f.Severity != models.SeverityHigh {
		t.Fatalf("expected high severity, got %s", f.Severity)
	}
}

func TestCORS_Name(t *testing.T) {
	if got := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Name(); got != "cors" {
		t.Fatalf("got %q", got)
	}
}
