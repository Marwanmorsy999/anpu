package scoring

import (
	"strings"
	"testing"

	"github.com/Marwanmorsy999/anpu/pkg/models"
)

func TestScoreFindingInfoIsZero(t *testing.T) {
	f := ScoreFinding(models.Finding{Severity: models.SeverityInfo, Confidence: models.ConfidenceHigh, Category: models.CategoryHeaders})
	if f.RiskScore != 0 {
		t.Fatalf("info must score 0, got %.1f", f.RiskScore)
	}
	if !strings.Contains(f.ScoreExplanation, "informational") {
		t.Fatalf("info explanation missing: %q", f.ScoreExplanation)
	}
}

func TestScoreFindingHighHighBeatsLowConfCritical(t *testing.T) {
	hi := ScoreFinding(models.Finding{Severity: models.SeverityHigh, Confidence: models.ConfidenceHigh, Category: models.CategoryHeaders})
	lo := ScoreFinding(models.Finding{Severity: models.SeverityCritical, Confidence: models.ConfidenceLow, Category: models.CategoryHeaders})
	// Documented math: high/high headers 7.0*0.90+0.1 = 6.4;
	// critical/low headers round(9.0*0.55+0.1) = 5.1.
	if hi.RiskScore != 6.4 {
		t.Fatalf("high/high headers expected 6.4, got %.1f (%s)", hi.RiskScore, hi.ScoreExplanation)
	}
	if lo.RiskScore != 5.1 {
		t.Fatalf("critical/low headers expected 5.1, got %.1f (%s)", lo.RiskScore, lo.ScoreExplanation)
	}
	if hi.RiskScore <= lo.RiskScore {
		t.Fatalf("high/high (%.1f) must outrank low-confidence critical (%.1f)", hi.RiskScore, lo.RiskScore)
	}
	if !strings.Contains(hi.ScoreExplanation, "base=7.0") {
		t.Fatalf("explanation must show base: %q", hi.ScoreExplanation)
	}
}

func TestCorroborationBonusCapped(t *testing.T) {
	base := models.Finding{Severity: models.SeverityMedium, Confidence: models.ConfidenceMedium, Category: models.CategoryHeaders}
	single := ScoreFinding(base)
	multi := base
	multi.MergedFrom = make([]models.SourceRef, 10)
	multi = ScoreFinding(multi)
	if multi.RiskScore-single.RiskScore > 0.5001 {
		t.Fatalf("corroboration bonus must cap at 0.5: single=%.1f multi=%.1f", single.RiskScore, multi.RiskScore)
	}
}

func TestAggregateScoreVolumeAndInfo(t *testing.T) {
	if got := AggregateScore(nil); got != 0 {
		t.Fatalf("empty must be 0, got %.1f", got)
	}
	infos := []models.Finding{{Severity: models.SeverityInfo, RiskScore: 0}}
	if got := AggregateScore(infos); got != 0 {
		t.Fatalf("info-only must be 0, got %.1f", got)
	}
	many := []models.Finding{}
	for i := 0; i < 20; i++ {
		many = append(many, models.Finding{Severity: models.SeverityMedium, Confidence: models.ConfidenceHigh, RiskScore: 3.5})
	}
	if got := AggregateScore(many); got != 5.0 {
		t.Fatalf("volume bonus must cap at 1.5 over max 3.5 = 5.0, got %.1f", got)
	}
}

// ScoreAll scores every finding in place and returns the slice.
func TestScoreAllScoresInPlace(t *testing.T) {
	fs := []models.Finding{
		{Severity: models.SeverityInfo, Confidence: models.ConfidenceHigh, Category: models.CategoryHeaders},
		{Severity: models.SeverityHigh, Confidence: models.ConfidenceHigh, Category: models.CategoryHeaders},
	}
	out := ScoreAll(fs)
	if len(out) != 2 {
		t.Fatalf("expected 2 scored findings, got %d", len(out))
	}
	if out[0].RiskScore != 0 || out[1].RiskScore != 6.4 {
		t.Fatalf("ScoreAll mismatch: info=%.1f high=%.1f", out[0].RiskScore, out[1].RiskScore)
	}
	if out[1].ScoreExplanation == "" {
		t.Fatal("scored finding must carry an explanation")
	}
}

// Unknown severity/confidence fall back to documented defaults instead of
// panicking or scoring zero: base=1.0, multiplier=0.5.
func TestScoreFindingUnknownSeverityConfidence(t *testing.T) {
	f := ScoreFinding(models.Finding{Severity: "bogus", Confidence: "bogus", Category: models.CategoryOther})
	if f.RiskScore != 0.5 {
		t.Fatalf("fallback expected 0.5 (1.0*0.5+0.0), got %.1f (%s)", f.RiskScore, f.ScoreExplanation)
	}
	if !strings.Contains(f.ScoreExplanation, "base=1.0") {
		t.Fatalf("explanation must show fallback base: %q", f.ScoreExplanation)
	}
}

// Scores clamp at 10: critical/confirmed vuln with corroboration would
// otherwise reach 9.0*1.0+1.0+0.5 = 10.5.
func TestScoreFindingClampsAtTen(t *testing.T) {
	f := models.Finding{
		Severity: models.SeverityCritical, Confidence: models.ConfidenceConfirmed,
		Category:   models.CategoryVulnerability,
		MergedFrom: make([]models.SourceRef, 10),
	}
	if got := ScoreFinding(f); got.RiskScore != 10.0 {
		t.Fatalf("expected clamp at 10.0, got %.1f (%s)", got.RiskScore, got.ScoreExplanation)
	}
}

// Unconfirmed differentials (low confidence, no corroboration) must not
// drive the grade numerator — only a capped posture penalty.
func TestAggregateUnconfirmedIsPostureOnly(t *testing.T) {
	diffs := []models.Finding{}
	for i := 0; i < 20; i++ {
		diffs = append(diffs, models.Finding{Severity: models.SeverityMedium, Confidence: models.ConfidenceLow, RiskScore: 3.5})
	}
	if got := AggregateScore(diffs); got != 1.0 {
		t.Fatalf("20 unconfirmed must cap at posture 1.0, got %.1f", got)
	}
	single := []models.Finding{{Severity: models.SeverityHigh, Confidence: models.ConfidenceLow, RiskScore: 5.0}}
	if got := AggregateScore(single); got != 0.1 {
		t.Fatalf("one unconfirmed high must be posture 0.1, got %.1f", got)
	}
}

// Needs-review findings (single-technique, disputed sources) stay out of
// the numerator even at high confidence.
func TestAggregateNeedsReviewExcluded(t *testing.T) {
	fs := []models.Finding{{
		Severity: models.SeverityHigh, Confidence: models.ConfidenceHigh, RiskScore: 6.4,
		EvidenceBundle: &models.EvidenceBundle{NeedsReview: true, Technique: "single-technique"},
	}}
	if got := AggregateScore(fs); got != 0.1 {
		t.Fatalf("needs-review must be posture-only, got %.1f", got)
	}
}

// Multi-source agreement counts as confirmed even without high confidence.
func TestAggregateMergedCountsConfirmed(t *testing.T) {
	fs := []models.Finding{{
		Severity: models.SeverityMedium, Confidence: models.ConfidenceMedium, RiskScore: 3.5,
		MergedFrom: make([]models.SourceRef, 2),
	}}
	if got := AggregateScore(fs); got != 3.7 {
		t.Fatalf("merged medium must drive numerator (3.5+0.15=3.65→3.7), got %.1f", got)
	}
}
