package vhost

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

func TestVHostBudgetParity(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<html><body>vhost</body></html>"))
	}))
	defer srv.Close()

	client := anpuhttp.NewClientWithLocalNetworkAllowed(true)
	ledger := anpuhttp.NewLedger(100000)
	ledger.SetCap("VHost", 1000)
	sc := &scanner.ScanContext{
		Target:     &scanner.ValidatedTarget{Raw: srv.URL, Host: "vhostfixture.example"},
		Ledger:     ledger,
		StageLabel: "VHost",
		Config:     models.ScanConfig{Target: srv.URL, Profile: models.ProfileAdvanced},
	}
	s := New(client)
	_, err := s.Run(context.Background(), sc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if int64(ledger.Count("VHost")) != hits {
		t.Fatalf("budget parity: hits=%d ledger=%d", hits, ledger.Count("VHost"))
	}
	if hits < 2 {
		t.Fatalf("expected both base and per-candidate paths to be driven, hits=%d", hits)
	}
}
