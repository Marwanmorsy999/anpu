package scanner

import (
	"context"
	"sync"
	"testing"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// budgetTestScanner charges the ledger N times (one per "request")
// and returns a finding. Used for budget tests.
type budgetTestScanner struct {
	requests int
}

func (b *budgetTestScanner) Name() string                     { return "budgettest" }
func (b *budgetTestScanner) Available(_ context.Context) bool { return true }
func (b *budgetTestScanner) Run(ctx context.Context, sc *ScanContext) (StageResult, error) {
	budgetExhausted := false
	defer func() {
		// warnings are appended by the test, not here
		_ = budgetExhausted
	}()
	for i := 0; i < b.requests; i++ {
		if err := ChargeBudget(sc); err != nil {
			budgetExhausted = true
			return StageResult{Warnings: []string{BudgetExhaustedWarning(sc)}}, nil
		}
		// Simulate an HTTP request (charge already done above)
	}
	return StageResult{Findings: []models.Finding{{ID: "budget-test", Title: "budget test finding"}}}, nil
}

// budgetTestCtx builds a ScanContext pointing at srv with a Ledger
// whose cap for the given stage is `cap` (0 = uncapped).
func budgetTestCtx(stage string, cap int) *ScanContext {
	ledger := anpuhttp.NewLedger(10000)
	if cap > 0 {
		ledger.SetCap(stage, cap)
	}
	return &ScanContext{
		Target:     &ValidatedTarget{Raw: "http://example.com", Host: "example.com"},
		Ledger:     ledger,
		StageLabel: stage,
	}
}

// TestBudgetForcedTruncation: a tiny SetCap stops a stage with a warning
// while another stage (with a generous cap) completes.
func TestBudgetForcedTruncation(t *testing.T) {
	client := anpuhttp.NewClientWithLocalNetworkAllowed(true)
	_ = client

	// Stage "truncated" has cap=1, makes 5 requests -> should stop with warning.
	sc := budgetTestCtx("truncated", 1)
	sc.Config = models.ScanConfig{Target: "http://example.com", Profile: models.ProfileSafe}
	res, err := (&budgetTestScanner{requests: 5}).Run(context.Background(), sc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	found := false
	for _, w := range res.Warnings {
		if containsStr(w, "budget exhausted") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected budget-exhausted warning, got warnings: %v", res.Warnings)
	}
	if sc.Ledger.Count("truncated") != 1 {
		t.Fatalf("expected 1 charged request with cap=1, got %d", sc.Ledger.Count("truncated"))
	}

	// Stage "ok" has generous cap, makes 3 requests -> should complete.
	sc2 := budgetTestCtx("ok", 100)
	sc2.Config = models.ScanConfig{Target: "http://example.com", Profile: models.ProfileSafe}
	res2, err := (&budgetTestScanner{requests: 3}).Run(context.Background(), sc2)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, w := range res2.Warnings {
		if containsStr(w, "budget exhausted") {
			t.Fatalf("unexpected budget warning on generous stage: %q", w)
		}
	}
	if sc2.Ledger.Count("ok") != 3 {
		t.Fatalf("expected 3 charged requests, got %d", sc2.Ledger.Count("ok"))
	}
}

// TestBudgetBillingAccuracy: every request is charged exactly once.
func TestBudgetBillingAccuracy(t *testing.T) {
	sc := budgetTestCtx("billing", 0) // uncapped
	sc.Config = models.ScanConfig{Target: "http://example.com", Profile: models.ProfileSafe}
	res, err := (&budgetTestScanner{requests: 7}).Run(context.Background(), sc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	_ = res
	if got := sc.Ledger.Count("billing"); got != 7 {
		t.Fatalf("ledger count %d != expected 7", got)
	}
}

// TestBudgetNoWarningsOnNormalScan: a scan with generous caps emits no
// budget warnings.
func TestBudgetNoWarningsOnNormalScan(t *testing.T) {
	sc := budgetTestCtx("normal", 100)
	sc.Config = models.ScanConfig{Target: "http://example.com", Profile: models.ProfileSafe}
	res, err := (&budgetTestScanner{requests: 3}).Run(context.Background(), sc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, w := range res.Warnings {
		if containsStr(w, "budget exhausted") {
			t.Fatalf("unexpected budget warning: %q", w)
		}
	}
}

// TestBudgetConcurrentRecord: concurrent Record calls stay under caps.
// (Also covered by TestLedgerConcurrentRecordStaysUnderCap in the http package.)
func TestBudgetConcurrentRecord(t *testing.T) {
	ledger := anpuhttp.NewLedger(1000)
	ledger.SetCap("stage", 50)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sc := &ScanContext{Ledger: ledger, StageLabel: "stage"}
			for i := 0; i < 20; i++ {
				ChargeBudget(sc) // ignore error
			}
		}()
	}
	wg.Wait()
	if got := ledger.Count("stage"); got > 50 {
		t.Fatalf("stage count %d exceeds cap 50", got)
	}
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
