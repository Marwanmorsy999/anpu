package graphqlfp

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

// TestGraphQLFPBudgetParity drives both graphqlfp charging paths (POST and
// GET fallback) against an httptest fixture and asserts every HTTP hit is
// charged to the ledger.
func TestGraphQLFPBudgetParity(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(200)
		if r.Method == http.MethodPost {
			// POST returns non-GraphQL, forcing the GET fallback path.
			_, _ = w.Write([]byte("not found"))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"__typename":"Query"}}`))
	}))
	defer srv.Close()

	client := anpuhttp.NewClientWithLocalNetworkAllowed(true)
	ledger := anpuhttp.NewLedger(100000)
	ledger.SetCap("GraphQLFP", 1000)
	sc := &scanner.ScanContext{
		Target:     &scanner.ValidatedTarget{Raw: srv.URL, Host: "127.0.0.1"},
		Ledger:     ledger,
		StageLabel: "GraphQLFP",
		Config:     models.ScanConfig{Target: srv.URL, Profile: models.ProfileAdvanced},
	}
	s := New(client)
	_, err := s.Run(context.Background(), sc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if int64(ledger.Count("GraphQLFP")) != hits {
		t.Fatalf("budget parity: hits=%d ledger=%d", hits, ledger.Count("GraphQLFP"))
	}
	if hits < 2 {
		t.Fatalf("expected both POST and GET paths to be driven, hits=%d", hits)
	}
}
