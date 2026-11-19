package scoring

import (
	"testing"

	"github.com/Marwanmorsy999/anpu/pkg/models"
)

func BenchmarkAggregateScore(b *testing.B) {
	findings := make([]models.Finding, 0, 64)
	for i := 0; i < 64; i++ {
		findings = append(findings, models.Finding{
			Severity:   models.SeverityHigh,
			Confidence: models.ConfidenceHigh,
			Title:      "bench finding",
		})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = AggregateScore(findings)
	}
}

func BenchmarkScoreAll(b *testing.B) {
	findings := make([]models.Finding, 64)
	for i := range findings {
		findings[i] = models.Finding{
			Severity:   models.SeverityMedium,
			Confidence: models.ConfidenceMedium,
			Title:      "bench finding",
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ScoreAll(findings)
	}
}
