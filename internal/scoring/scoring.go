// Package scoring implements ANPU's transparent, deterministic risk
// scoring. Scores are computed from documented, fixed weights applied to
// severity, confidence, exposure, exploitability, and affected surface —
// never from an opaque or AI-generated number. Every scored finding
// carries a ScoreExplanation describing exactly how its score was
// derived, and the aggregate scan score is likewise explainable.
package scoring

import (
	"fmt"
	"math"

	"github.com/anpu-project/anpu/pkg/models"
)

// severityBase maps security severity to its base score contribution (0-10 scale).
// Informational observations are intentionally score-neutral: they describe
// attack-surface facts, not security risk by themselves.
var severityBase = map[models.Severity]float64{
	models.SeverityCritical: 9.0,
	models.SeverityHigh:     7.0,
	models.SeverityMedium:   4.5,
	models.SeverityLow:      2.0,
	models.SeverityInfo:     0.0,
}

// confidenceMultiplier discounts the score for less-certain findings.
// A "low confidence critical" should not outrank a "confirmed high".
var confidenceMultiplier = map[models.Confidence]float64{
	models.ConfidenceConfirmed: 1.00,
	models.ConfidenceHigh:      0.90,
	models.ConfidenceMedium:    0.75,
	models.ConfidenceLow:       0.55,
}

// categoryWeight adds a small score bonus for findings based on their category.
var categoryWeight = map[models.Category]float64{
	models.CategoryVulnerability:  1.0, // confirmed/near-confirmed vuln from a real scanner (Nuclei/ZAP)
	models.CategoryAuthentication: 0.7,
	models.CategoryTLS:            0.5,
	models.CategoryEndpoint:       0.3,
	models.CategoryConfiguration:  0.3,
	models.CategoryCookies:        0.2,
	models.CategoryHeaders:        0.1,
	models.CategoryTechnology:     0.1,
	models.CategoryExposure:       0.2,
	models.CategoryOther:          0.0,
}

// ScoreFinding computes a finding's RiskScore (0-10, clamped) and a
// human-readable explanation of how that score was derived. It mutates
// and returns the passed finding for convenience.
func ScoreFinding(f models.Finding) models.Finding {
	if f.Severity == models.SeverityInfo {
		f.RiskScore = 0
		f.ScoreExplanation = "severity=info — informational observation; excluded from security risk scoring"
		return f
	}

	base, ok := severityBase[f.Severity]
	if !ok {
		base = 1.0
	}
	confMult, ok := confidenceMultiplier[f.Confidence]
	if !ok {
		confMult = 0.5
	}
	weight := categoryWeight[f.Category]

	// Merged findings (confirmed by multiple independent scanners) get a
	// small corroboration bonus, since independent agreement increases
	// real-world certainty beyond what a single tool's confidence label
	// captures.
	corroboration := 0.0
	if len(f.MergedFrom) > 1 {
		corroboration = math.Min(0.5, 0.15*float64(len(f.MergedFrom)-1))
	}

	raw := base*confMult + weight + corroboration
	score := math.Round(math.Min(raw, 10.0)*10) / 10
	if score < 0 {
		score = 0
	}

	f.RiskScore = score
	f.ScoreExplanation = fmt.Sprintf(
		"base=%.1f (severity=%s) × confidence_multiplier=%.2f (confidence=%s) + exposure_weight=%.2f (category=%s) + corroboration_bonus=%.2f (%d independent source(s)) = %.1f/10",
		base, f.Severity, confMult, f.Confidence, weight, f.Category, corroboration, maxInt(1, len(f.MergedFrom)), score,
	)
	return f
}

// ScoreAll scores every finding in place and returns the slice.
func ScoreAll(fs []models.Finding) []models.Finding {
	for i := range fs {
		fs[i] = ScoreFinding(fs[i])
	}
	return fs
}

// AggregateScore computes the overall scan risk score (0-10) from a set
// of already-scored findings. It is dominated by the single worst finding
// but factors in the overall volume of medium+ severity issues, so that
// "one high" and "one high plus twenty mediums" don't score identically.
// Informational observations never affect the aggregate score.
func AggregateScore(fs []models.Finding) float64 {
	if len(fs) == 0 {
		return 0
	}
	var maxScore float64
	var volumeBonus float64
	for _, f := range fs {
		if f.RiskScore > maxScore {
			maxScore = f.RiskScore
		}
		if f.Severity.Rank() >= models.SeverityMedium.Rank() {
			volumeBonus += 0.15
		}
	}
	volumeBonus = math.Min(volumeBonus, 1.5)
	total := math.Min(maxScore+volumeBonus, 10.0)
	return math.Round(total*10) / 10
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
