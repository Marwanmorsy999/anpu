package diff

import (
	"testing"

	"github.com/Marwanmorsy999/anpu/pkg/models"
)

func BenchmarkCompare(b *testing.B) {
	before := &models.ScanSummary{RiskScore: 5.0}
	after := &models.ScanSummary{RiskScore: 7.2}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Compare(before, after)
	}
}
