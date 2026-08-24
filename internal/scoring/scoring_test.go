package scoring

import (
	"testing"

	"github.com/anpu-project/anpu/pkg/models"
)

func TestScoreFinding_HigherSeverityScoresHigher(t *testing.T) {
	low := ScoreFinding(models.Finding{Severity: models.SeverityLow, Confidence: models.ConfidenceHigh, Category: models.CategoryHeaders})
	high := ScoreFinding(models.Finding{Severity: models.SeverityHigh, Confidence: models.ConfidenceHigh, Category: models.CategoryHeaders})
	if !(high.RiskScore > low.RiskScore) {
		t.Errorf("expected high severity score (%.1f) > low severity score (%.1f)", high.RiskScore, low.RiskScore)
	}
}

func TestScoreFinding_LowerConfidenceScoresLower(t *testing.T) {
	confirmed := ScoreFinding(models.Finding{Severity: models.SeverityCritical, Confidence: models.ConfidenceConfirmed, Category: models.CategoryVulnerability})
	lowConf := ScoreFinding(models.Finding{Severity: models.SeverityCritical, Confidence: models.ConfidenceLow, Category: models.CategoryVulnerability})
	if !(confirmed.RiskScore > lowConf.RiskScore) {
		t.Errorf("expected confirmed-confidence score (%.1f) > low-confidence score (%.1f) for same severity", confirmed.RiskScore, lowConf.RiskScore)
	}
}

func TestScoreFinding_NeverExceedsTen(t *testing.T) {
	f := ScoreFinding(models.Finding{
		Severity: models.SeverityCritical, Confidence: models.ConfidenceConfirmed,
		Category:   models.CategoryVulnerability,
		MergedFrom: []models.SourceRef{{}, {}, {}, {}, {}},
	})
	if f.RiskScore > 10.0 {
		t.Errorf("expected score clamped to 10.0, got %.1f", f.RiskScore)
	}
}

func TestScoreFinding_ExplanationIsPopulated(t *testing.T) {
	f := ScoreFinding(models.Finding{Severity: models.SeverityMedium, Confidence: models.ConfidenceMedium, Category: models.CategoryCookies})
	if f.ScoreExplanation == "" {
		t.Error("expected a non-empty score explanation")
	}
}

func TestAggregateScore_DominatedByWorstFinding(t *testing.T) {
	fs := ScoreAll([]models.Finding{
		{Severity: models.SeverityCritical, Confidence: models.ConfidenceConfirmed, Category: models.CategoryVulnerability},
		{Severity: models.SeverityInfo, Confidence: models.ConfidenceLow, Category: models.CategoryHeaders},
	})
	agg := AggregateScore(fs)
	if agg < 8.0 {
		t.Errorf("expected aggregate score to be dominated by the critical finding, got %.1f", agg)
	}
}

func TestAggregateScore_EmptyIsZero(t *testing.T) {
	if AggregateScore(nil) != 0 {
		t.Error("expected aggregate score of 0 for no findings")
	}
}

func TestAggregateScore_VolumeIncreasesScore(t *testing.T) {
	one := ScoreAll([]models.Finding{{Severity: models.SeverityHigh, Confidence: models.ConfidenceHigh, Category: models.CategoryHeaders}})
	many := ScoreAll([]models.Finding{
		{Severity: models.SeverityHigh, Confidence: models.ConfidenceHigh, Category: models.CategoryHeaders},
		{Severity: models.SeverityMedium, Confidence: models.ConfidenceHigh, Category: models.CategoryHeaders},
		{Severity: models.SeverityMedium, Confidence: models.ConfidenceHigh, Category: models.CategoryHeaders},
		{Severity: models.SeverityMedium, Confidence: models.ConfidenceHigh, Category: models.CategoryHeaders},
	})
	if !(AggregateScore(many) > AggregateScore(one)) {
		t.Errorf("expected more medium+ findings to raise the aggregate score: one=%.1f many=%.1f", AggregateScore(one), AggregateScore(many))
	}
}
