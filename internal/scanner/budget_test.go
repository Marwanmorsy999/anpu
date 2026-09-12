package scanner

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Marwanmorsy999/anpu/pkg/models"
)

type stubScanner struct {
	sleep time.Duration
}

func (s stubScanner) Name() string                     { return "stub" }
func (s stubScanner) Available(_ context.Context) bool { return true }
func (s stubScanner) Run(ctx context.Context, sc *ScanContext) (StageResult, error) {
	if s.sleep > 0 {
		select {
		case <-ctx.Done():
			return StageResult{}, ctx.Err()
		case <-time.After(s.sleep):
		}
	}
	return StageResult{}, nil
}

func budgetTarget() *ValidatedTarget {
	return &ValidatedTarget{Raw: "https://example.com", Host: "example.com"}
}

func budgetCfg(budget time.Duration) models.ScanConfig {
	return models.ScanConfig{Target: "https://example.com", Profile: models.ProfileSafe, Budget: budget, SkipPreCheck: true}
}

func budgetPipeline() *Pipeline {
	mk := func(label string, phase Phase, sleep time.Duration) Stage {
		return Stage{Label: label, Enabled: true, Scanner: stubScanner{sleep: sleep}, Phase: phase}
	}
	return &Pipeline{Stages: []Stage{
		mk("A1", PhaseFoundation, 0),
		mk("A2", PhaseFoundation, 60*time.Millisecond),
		mk("B1", PhaseDiscovery, 0),
		mk("C1", PhaseTargeted, 0),
	}}
}

func runBudgetPipe(t *testing.T, budget time.Duration) (*models.ScanSummary, []StageProgress) {
	t.Helper()
	var prog []StageProgress
	summary, err := budgetPipeline().Run(
		context.Background(), budgetTarget(), budgetCfg(budget),
		func(fs []models.Finding) []models.Finding { return fs },
		func(fs []models.Finding) []models.Finding { return fs },
		func(fs []models.Finding) float64 { return 0 },
		nil,
		func(p StageProgress) { prog = append(prog, p) },
	)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return summary, prog
}

// No budget: everything runs.
func TestBudgetUncappedRunsAll(t *testing.T) {
	summary, prog := runBudgetPipe(t, 0)
	if len(prog) != 4 {
		t.Fatalf("all 4 stages must report, got %d", len(prog))
	}
	for _, w := range summary.Warnings {
		if strings.HasPrefix(w, "budget:") {
			t.Fatalf("no budget warning expected: %q", w)
		}
	}
}

// A budget blown mid-queue stops between stages with per-phase coverage.
// A1+A2 (foundation) run inside 30ms; the 60ms A2 sleep blows the rest.
func TestBudgetStopsQueueWithCoverage(t *testing.T) {
	summary, prog := runBudgetPipe(t, 30*time.Millisecond)
	if len(prog) != 4 {
		t.Fatalf("all 4 stages must report (done or skipped), got %d", len(prog))
	}
	done, skipped := 0, 0
	for _, p := range prog {
		if p.Done {
			done++
		}
		if p.Skipped {
			skipped++
			if !strings.HasPrefix(p.Reason, "over scan budget") {
				t.Fatalf("skip reason must name the budget, got %q", p.Reason)
			}
		}
	}
	if done == 0 || skipped == 0 {
		t.Fatalf("need both done and budget-skipped stages, done=%d skipped=%d", done, skipped)
	}
	found := false
	for _, w := range summary.Warnings {
		if !strings.HasPrefix(w, "budget:") {
			continue
		}
		found = true
		for _, want := range []string{"foundation", "discovery", "coverage"} {
			if !strings.Contains(w, want) {
				t.Fatalf("coverage must mention %q: %q", want, w)
			}
		}
	}
	if !found {
		t.Fatal("budget coverage warning missing")
	}
}
