package findings

import (
	"testing"

	"github.com/anpu-project/anpu/pkg/models"
)

func TestDeduplicate_MergesSameIssueFromDifferentSources(t *testing.T) {
	in := []models.Finding{
		{
			Title: "Missing CSP header", Category: models.CategoryHeaders,
			Target: "https://example.com", URL: "https://example.com/",
			Severity: models.SeverityLow, Confidence: models.ConfidenceMedium,
			Source: models.SourceHeaders,
		},
		{
			Title: "Missing CSP header", Category: models.CategoryHeaders,
			Target: "https://example.com", URL: "https://example.com/",
			Severity: models.SeverityMedium, Confidence: models.ConfidenceHigh,
			Source: models.SourceNuclei,
		},
	}

	out := Deduplicate(in)
	if len(out) != 1 {
		t.Fatalf("expected 1 merged finding, got %d", len(out))
	}
	merged := out[0]
	if merged.Severity != models.SeverityMedium {
		t.Errorf("expected merged severity to be the higher of the two (medium), got %s", merged.Severity)
	}
	if merged.Confidence != models.ConfidenceHigh {
		t.Errorf("expected merged confidence to be the higher of the two (high), got %s", merged.Confidence)
	}
	if len(merged.MergedFrom) != 2 {
		t.Errorf("expected 2 source refs preserved, got %d", len(merged.MergedFrom))
	}
	if merged.Source != models.SourceAggregation {
		t.Errorf("expected merged Source to be anpu-dedup, got %s", merged.Source)
	}
}

func TestDeduplicate_DoesNotMergeDifferentIssues(t *testing.T) {
	in := []models.Finding{
		{Title: "Missing CSP header", Category: models.CategoryHeaders, Target: "https://example.com", URL: "https://example.com/", Severity: models.SeverityLow, Confidence: models.ConfidenceMedium},
		{Title: "Missing HSTS header", Category: models.CategoryHeaders, Target: "https://example.com", URL: "https://example.com/", Severity: models.SeverityMedium, Confidence: models.ConfidenceMedium},
	}
	out := Deduplicate(in)
	if len(out) != 2 {
		t.Fatalf("expected 2 distinct findings, got %d", len(out))
	}
}

func TestDeduplicate_SingleFindingGetsOneSourceRef(t *testing.T) {
	in := []models.Finding{
		{ID: "x", Title: "Solo finding", Category: models.CategoryTLS, Target: "https://example.com", Severity: models.SeverityHigh, Confidence: models.ConfidenceHigh, Source: models.SourceTLS},
	}
	out := Deduplicate(in)
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out))
	}
	if len(out[0].MergedFrom) != 1 {
		t.Errorf("expected exactly 1 source ref for a non-merged finding, got %d", len(out[0].MergedFrom))
	}
}

func TestDeduplicate_StableIDsAreDeterministic(t *testing.T) {
	f := models.Finding{Title: "X", Category: models.CategoryTLS, Target: "https://example.com", Severity: models.SeverityHigh, Confidence: models.ConfidenceHigh}
	out1 := Deduplicate([]models.Finding{f})
	out2 := Deduplicate([]models.Finding{f})
	if out1[0].ID != out2[0].ID {
		t.Errorf("expected deterministic ID across runs, got %s vs %s", out1[0].ID, out2[0].ID)
	}
}
