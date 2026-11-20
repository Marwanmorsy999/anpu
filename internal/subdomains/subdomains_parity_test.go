package subdomains

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// TestFetchCappedBudgetParity asserts that every HTTP request issued by
// the subdomains passive fetch path is charged exactly once to the shared
// ledger (httptest hits == Ledger.Count(stage)), mirroring the
// redirectpack/oauthpack parity tests.
func TestFetchCappedBudgetParity(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()

	client := anpuhttp.NewClientWithLocalNetworkAllowed(true)
	ledger := anpuhttp.NewLedger(100000)
	ledger.SetCap("Subdomains", 1000)
	s := New(client)
	s.scanCtx = &scanner.ScanContext{
		Target:     &scanner.ValidatedTarget{Raw: srv.URL, Host: "127.0.0.1"},
		Ledger:     ledger,
		StageLabel: "Subdomains",
		Config:     models.ScanConfig{Target: srv.URL, Profile: models.ProfileAdvanced},
	}

	for i := 0; i < 5; i++ {
		if _, _, err := s.fetchCapped(context.Background(), srv.URL, 1<<20); err != nil {
			t.Fatalf("fetchCapped: %v", err)
		}
	}
	if int64(ledger.Count("Subdomains")) != hits {
		t.Fatalf("budget parity: hits=%d ledger=%d", hits, ledger.Count("Subdomains"))
	}
}

// TestQueryCTLogsOverrideParity drives queryCTLogs end-to-end through the
// configurable CT-log base URL against httptest, asserting every HTTP hit
// is charged to the ledger.
func TestQueryCTLogsOverrideParity(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`[{"name_value":"a.example.com\nb.example.com"}]`))
	}))
	defer srv.Close()

	client := anpuhttp.NewClientWithLocalNetworkAllowed(true)
	ledger := anpuhttp.NewLedger(100000)
	ledger.SetCap("Subdomains", 1000)
	s := New(client)
	s.scanCtx = &scanner.ScanContext{
		Target:     &scanner.ValidatedTarget{Raw: srv.URL, Host: "127.0.0.1"},
		Ledger:     ledger,
		StageLabel: "Subdomains",
		Config: models.ScanConfig{
			Target:       srv.URL,
			Profile:      models.ProfileAdvanced,
			CTLogBaseURL: srv.URL,
		},
	}

	names, warn := s.queryCTLogs(context.Background(), "example.com")
	if warn != "" {
		t.Fatalf("queryCTLogs warn: %s", warn)
	}
	if len(names) != 2 {
		t.Fatalf("expected 2 names, got %v", names)
	}
	if int64(ledger.Count("Subdomains")) != hits {
		t.Fatalf("budget parity: hits=%d ledger=%d", hits, ledger.Count("Subdomains"))
	}
}

// TestCTLogBaseURLValidation asserts malformed overrides fall back to the
// default rather than redirecting to an unintended host.
func TestCTLogBaseURLValidation(t *testing.T) {
	sc := &scanner.ScanContext{Config: models.ScanConfig{CTLogBaseURL: "ftp://bad"}}
	if got := ctlogBaseURL(sc); got != DefaultCTLogBaseURL {
		t.Fatalf("malformed override must fall back to default, got %q", got)
	}
	sc = &scanner.ScanContext{Config: models.ScanConfig{CTLogBaseURL: "https://ct.example/"}}
	if got := ctlogBaseURL(sc); got != "https://ct.example" {
		t.Fatalf("expected trailing-slash trim, got %q", got)
	}
}
