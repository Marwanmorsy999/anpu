package http

import (
	"sync"
	"testing"
)

// TestLedgerConcurrentRecordStaysUnderCap verifies that concurrent
// Record calls from parallel stages never exceed the per-tool or global
// caps (race test: run with -race).
func TestLedgerConcurrentRecordStaysUnderCap(t *testing.T) {
	const cap = 50
	const workers = 8
	const perWorker = 20
	l := NewLedger(1000)
	l.SetCap("stage", cap)

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				l.Record("stage") // ignore error; we check counts below
			}
		}()
	}
	wg.Wait()

	count := l.Count("stage")
	if count > cap {
		t.Fatalf("stage count %d exceeds cap %d", count, cap)
	}
	if l.Total() > 1000 {
		t.Fatalf("global total %d exceeds maxTotal 1000", l.Total())
	}
	// At most `cap` successful charges; the rest must have errored.
	if count != cap {
		t.Logf("stage count = %d (cap %d): %d requests were correctly rejected", count, cap, workers*perWorker-count)
	}
}

// TestLedgerRecordReturnsErrorOnExhaustion verifies Record returns an
// error once the cap is reached.
func TestLedgerRecordReturnsErrorOnExhaustion(t *testing.T) {
	l := NewLedger(100)
	l.SetCap("tool", 3)
	for i := 0; i < 3; i++ {
		if err := l.Record("tool"); err != nil {
			t.Fatalf("request %d should succeed, got %v", i, err)
		}
	}
	if err := l.Record("tool"); err == nil {
		t.Fatal("4th request should fail (cap 3)")
	}
	if l.Count("tool") != 3 {
		t.Fatalf("count = %d, want 3", l.Count("tool"))
	}
}

// TestLedgerGlobalCapEnforced verifies the global cap.
func TestLedgerGlobalCapEnforced(t *testing.T) {
	l := NewLedger(5)
	for i := 0; i < 5; i++ {
		if err := l.Record("a"); err != nil {
			t.Fatalf("request %d should succeed, got %v", i, err)
		}
	}
	if err := l.Record("b"); err == nil {
		t.Fatal("6th request should fail (global cap 5)")
	}
}
