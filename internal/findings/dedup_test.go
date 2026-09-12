package findings

import (
	"testing"

	"github.com/Marwanmorsy999/anpu/pkg/models"
)

func mkFinding(sev models.Severity, conf models.Confidence, src models.Source) models.Finding {
	return models.Finding{
		ID: "orig", Title: "Missing HSTS", Category: models.CategoryHeaders,
		Target: "https://example.com", URL: "https://example.com",
		Severity: sev, Confidence: conf, Source: src,
		Evidence: models.Evidence{Observed: "header absent", Location: "test"},
	}
}

// Phase 0: identical DedupKeys merge; max severity/confidence wins and
// every source is preserved in MergedFrom.
func TestDeduplicateMergesSameKey(t *testing.T) {
	in := []models.Finding{
		mkFinding(models.SeverityLow, models.ConfidenceLow, models.SourceHeaders),
		mkFinding(models.SeverityMedium, models.ConfidenceHigh, models.SourceCustom),
	}
	out := Deduplicate(in)
	if len(out) != 1 {
		t.Fatalf("expected 1 merged finding, got %d", len(out))
	}
	m := out[0]
	if m.Severity != models.SeverityMedium || m.Confidence != models.ConfidenceHigh {
		t.Fatalf("max wins violated: sev=%s conf=%s", m.Severity, m.Confidence)
	}
	if len(m.MergedFrom) != 2 {
		t.Fatalf("expected 2 MergedFrom entries, got %d", len(m.MergedFrom))
	}
	if m.Source != models.SourceAggregation {
		t.Fatalf("merged source must be %q, got %q", models.SourceAggregation, m.Source)
	}
	if m.ID == "" || m.ID == "orig" {
		t.Fatalf("merged ID must be a stable derived ID, got %q", m.ID)
	}
}

func TestDeduplicateKeepsDistinctKeys(t *testing.T) {
	a := mkFinding(models.SeverityLow, models.ConfidenceLow, models.SourceHeaders)
	b := mkFinding(models.SeverityLow, models.ConfidenceLow, models.SourceHeaders)
	b.Title = "Different title"
	out := Deduplicate([]models.Finding{a, b})
	if len(out) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(out))
	}
}

func TestDeduplicateQueryOrderUnifies(t *testing.T) {
	a := mkFinding(models.SeverityLow, models.ConfidenceLow, models.SourceHeaders)
	a.Category = models.CategoryVulnerability
	a.Title = "SQLi"
	a.URL = "https://example.com/s?b=2&a=1"
	b := a
	b.URL = "https://example.com/s?a=1&b=2"
	b.Source = models.SourceCustom
	out := Deduplicate([]models.Finding{a, b})
	if len(out) != 1 {
		t.Fatalf("query order should unify, got %d findings", len(out))
	}
	if len(out[0].MergedFrom) != 2 {
		t.Fatalf("expected 2 merged sources, got %d", len(out[0].MergedFrom))
	}
}

func TestDisagreementFlagsNeedsReview(t *testing.T) {
	hi := mkFinding(models.SeverityHigh, models.ConfidenceHigh, models.SourceNuclei)
	lo := mkFinding(models.SeverityLow, models.ConfidenceLow, models.SourceCustom)
	out := Deduplicate([]models.Finding{hi, lo})
	if len(out) != 1 {
		t.Fatalf("expected 1 merged finding, got %d", len(out))
	}
	m := out[0]
	// Max severity is kept — a real issue is never silently downgraded —
	// but the conflict must be visible.
	if m.Severity != models.SeverityHigh {
		t.Fatalf("merged must keep max severity, got %s", m.Severity)
	}
	if m.EvidenceBundle == nil || !m.EvidenceBundle.NeedsReview {
		t.Fatalf("severity span High-vs-Low must flag needs-review, got %+v", m.EvidenceBundle)
	}
	if m.EvidenceBundle.Technique != "disputed-sources" {
		t.Fatalf("technique must be disputed-sources, got %q", m.EvidenceBundle.Technique)
	}
}

func TestAgreementDoesNotFlagDispute(t *testing.T) {
	a := mkFinding(models.SeverityMedium, models.ConfidenceMedium, models.SourceHeaders)
	b := mkFinding(models.SeverityMedium, models.ConfidenceLow, models.SourceCustom)
	out := Deduplicate([]models.Finding{a, b})
	if len(out) != 1 {
		t.Fatalf("expected 1 merged finding, got %d", len(out))
	}
	if out[0].EvidenceBundle != nil {
		t.Fatalf("agreeing sources must not flag dispute, got %+v", out[0].EvidenceBundle)
	}
}

func TestStableIDDeterministic(t *testing.T) {
	a := mkFinding(models.SeverityHigh, models.ConfidenceHigh, models.SourceHeaders)
	b := a
	if stableID(a) != stableID(b) {
		t.Fatal("stableID must be deterministic")
	}
	b.Title = "other"
	if stableID(a) == stableID(b) {
		t.Fatal("stableID must change with DedupKey")
	}
}
