package saml

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

func TestSAMLMetadataBudgetParity(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	client := anpuhttp.NewClientWithLocalNetworkAllowed(true)
	ledger := anpuhttp.NewLedger(100000)
	ledger.SetCap("SAMLMetadata", 1000)
	sc := &scanner.ScanContext{
		Target:     &scanner.ValidatedTarget{Raw: srv.URL, Host: "127.0.0.1"},
		Ledger:     ledger,
		StageLabel: "SAMLMetadata",
		Config:     models.ScanConfig{Target: srv.URL, Profile: models.ProfileAdvanced},
	}
	s := New(client)
	_, err := s.Run(context.Background(), sc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if int64(ledger.Count("SAMLMetadata")) != hits {
		t.Fatalf("budget parity: hits=%d ledger=%d", hits, ledger.Count("SAMLMetadata"))
	}
	if hits == 0 {
		t.Fatal("expected saml to issue requests in fixture")
	}
}
