package exposedconfig

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

// TestExposedConfigBudgetParity asserts that every HTTP request the stage
// issues is charged to the shared ledger (httptest hit count ==
// Ledger.Count(stage)), which is the invariant the budget migration must
// preserve. Regression guard for the double-charge that caused the
// exposed-env bench signal to miss.
func TestExposedConfigBudgetParity(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		if r.URL.Path == "/.env" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7FAKEKEY12\nDATABASE_URL=postgres://x\n"))
			return
		}
		if r.URL.Path == "/" {
			_, _ = w.Write([]byte("<html><body>home</body></html>"))
			return
		}
		w.WriteHeader(404)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := anpuhttp.NewClientWithLocalNetworkAllowed(true)
	ledger := anpuhttp.NewLedger(100000)
	ledger.SetCap("ExposedConfig", 100)
	sc := &scanner.ScanContext{
		Target:     &scanner.ValidatedTarget{Raw: srv.URL, Host: "127.0.0.1"},
		Ledger:     ledger,
		StageLabel: "ExposedConfig",
		Config:     models.ScanConfig{Target: srv.URL, Profile: models.ProfileAdvanced},
	}

	s := New(client)
	res, err := s.Run(context.Background(), sc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatalf("expected an exposed-env finding, got none")
	}
	got := ledger.Count("ExposedConfig")
	if int64(got) != hits {
		t.Fatalf("budget parity violated: httptest hits=%d, Ledger.Count(ExposedConfig)=%d", hits, got)
	}
}
