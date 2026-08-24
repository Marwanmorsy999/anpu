package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/anpu-project/anpu/pkg/models"
)

// stubScanner is a minimal Scanner used to exercise the Pipeline without
// depending on the analyzer packages (which would create an import
// cycle back into this package).
type stubScanner struct {
	name      string
	available bool
	result    StageResult
	err       error
}

func (s *stubScanner) Name() string                       { return s.name }
func (s *stubScanner) Available(ctx context.Context) bool { return s.available }
func (s *stubScanner) Run(ctx context.Context, sc *ScanContext) (StageResult, error) {
	return s.result, s.err
}

func TestPipeline_RunsEnabledStagesAndSkipsDisabled(t *testing.T) {
	orig := AllowLocalNetwork
	AllowLocalNetwork = true
	defer func() { AllowLocalNetwork = orig }()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	target, err := ValidateTarget(srv.URL)
	if err != nil {
		t.Fatalf("validating target: %v", err)
	}

	ran := map[string]bool{}
	makeStage := func(label string, enabled bool) Stage {
		return Stage{
			Label:   label,
			Enabled: enabled,
			Scanner: &stubScanner{
				name:      label,
				available: true,
				result: StageResult{Findings: []models.Finding{{
					ID: label, Title: label, Category: models.CategoryOther,
					Severity: models.SeverityInfo, Confidence: models.ConfidenceHigh,
					Target: srv.URL,
				}}},
			},
		}
	}

	pipeline := &Pipeline{Stages: []Stage{makeStage("stage-a", true), makeStage("stage-b", false)}}

	noopDedup := func(fs []models.Finding) []models.Finding { return fs }
	noopScore := func(fs []models.Finding) []models.Finding { return fs }
	zeroAgg := func(fs []models.Finding) float64 { return 0 }

	summary, err := pipeline.Run(context.Background(), target, models.ScanConfig{Profile: models.ProfileSafe}, noopDedup, noopScore, zeroAgg, func(p StageProgress) {
		if p.Done {
			ran[p.StageName] = true
		}
	})
	if err != nil {
		t.Fatalf("unexpected pipeline error: %v", err)
	}

	if !ran["stage-a"] {
		t.Error("expected enabled stage-a to run")
	}
	if ran["stage-b"] {
		t.Error("did not expect disabled stage-b to run")
	}
	if len(summary.Findings) != 1 {
		t.Errorf("expected 1 finding from the single enabled stage, got %d", len(summary.Findings))
	}
	if summary.Status != "completed" {
		t.Errorf("expected status completed, got %s", summary.Status)
	}
}

func TestPipeline_StageErrorDoesNotAbortScan(t *testing.T) {
	orig := AllowLocalNetwork
	AllowLocalNetwork = true
	defer func() { AllowLocalNetwork = orig }()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	target, _ := ValidateTarget(srv.URL)

	failing := Stage{Label: "failing", Enabled: true, Scanner: &stubScanner{name: "failing", available: true, err: context.DeadlineExceeded}}
	ok := Stage{Label: "ok", Enabled: true, Scanner: &stubScanner{name: "ok", available: true, result: StageResult{
		Findings: []models.Finding{{ID: "ok-finding", Category: models.CategoryOther, Severity: models.SeverityInfo, Confidence: models.ConfidenceHigh, Target: srv.URL}},
	}}}

	pipeline := &Pipeline{Stages: []Stage{failing, ok}}
	noop := func(fs []models.Finding) []models.Finding { return fs }
	zeroAgg := func(fs []models.Finding) float64 { return 0 }

	summary, err := pipeline.Run(context.Background(), target, models.ScanConfig{Profile: models.ProfileSafe}, noop, noop, zeroAgg, nil)
	if err != nil {
		t.Fatalf("pipeline should not hard-fail on a single stage error: %v", err)
	}
	if len(summary.Warnings) == 0 {
		t.Error("expected the failing stage's error to be recorded as a warning")
	}
	if len(summary.Findings) != 1 {
		t.Errorf("expected the successful stage's finding to still be present, got %d findings", len(summary.Findings))
	}
}
