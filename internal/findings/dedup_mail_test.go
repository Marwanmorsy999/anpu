package findings

import (
	"testing"

	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// Mail-posture findings from dnsintel and emailauth share canonical
// titles + CWE-345 so the pipeline merges same-root-cause rows instead
// of printing one row per stage.
func TestMailPostureMergesAcrossStages(t *testing.T) {
	dns := models.Finding{
		ID: "dns-spf-missing", Title: "No SPF record for example.com",
		Category: models.CategoryConfiguration, CWE: "CWE-345",
		Target: "https://example.com", Severity: models.SeverityMedium,
		Confidence: models.ConfidenceHigh, Source: "custom-analyzer",
	}
	mail := models.Finding{
		ID: "emailauth-missing-spf", Title: "No SPF record for example.com",
		Category: models.CategoryConfiguration, CWE: "CWE-345",
		Target: "https://example.com", Severity: models.SeverityLow,
		Confidence: models.ConfidenceHigh, Source: "custom-analyzer",
	}
	out := Deduplicate([]models.Finding{dns, mail})
	if len(out) != 1 {
		t.Fatalf("same root cause must merge to one row, got %d", len(out))
	}
	if out[0].Severity != models.SeverityMedium {
		t.Fatalf("merge must keep max severity, got %s", out[0].Severity)
	}
	if len(out[0].MergedFrom) != 2 {
		t.Fatalf("both sources must be preserved, got %d", len(out[0].MergedFrom))
	}
}
