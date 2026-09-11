package scoring

import (
	"strings"
	"testing"

	"github.com/anpu-project/anpu/pkg/models"
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
	if !(hi.RiskScore < lo.RiskScore || hi.RiskScore > 0) {
		t.Fatalf("unexpected scores hi=%.1f lo=%.1f", hi.RiskScore, lo.RiskScore)
	}
	// Documented math: 7.0*0.90+0.1 = 6.4 for high/high headers.
	if hi.RiskScore != 6.4 {
		t.Fatalf("high/high headers expected 6.4, got %.1f (%s)", hi.RiskScore, hi.ScoreExplanation)
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
		many = append(many, models.Finding{Severity: models.SeverityMedium, RiskScore: 3.5})
	}
	if got := AggregateScore(many); got != 5.0 {
		t.Fatalf("volume bonus must cap at 1.5 over max 3.5 = 5.0, got %.1f", got)
	}
}
