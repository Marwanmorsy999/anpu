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
