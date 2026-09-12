package findings

import (
	"testing"

	"github.com/Marwanmorsy999/anpu/pkg/models"
)

func nucleiFinding(id, title string) models.Finding {
	return models.Finding{
		ID: id, Title: title, Category: models.CategoryVulnerability,
		Target: "https://example.com", URL: "https://example.com/x",
		Severity: models.SeverityHigh, Confidence: models.ConfidenceHigh,
		Source: models.SourceNuclei, DetectionMethod: "Nuclei template: " + id,
		Evidence: models.Evidence{Observed: "match", Location: "test"},
	}
}

func TestCorrelationNilWithoutNuclei(t *testing.T) {
	in := []models.Finding{
		mkFinding(models.SeverityHigh, models.ConfidenceHigh, models.SourceHeaders),
	}
	if got := ComputeNucleiCorrelation(Deduplicate(in)); got != nil {
		t.Fatalf("no nuclei data must yield nil, got %+v", got)
	}
}

func TestCorrelationNilForEmbeddedOnly(t *testing.T) {
	embedded := models.Finding{
		ID: "nuclei-embedded-info", Title: "Nuclei embedded mode",
		Category: models.CategoryExposure, Target: "https://example.com",
		Severity: models.SeverityInfo, Confidence: models.ConfidenceHigh,
		Source: models.SourceNuclei, DetectionMethod: "embedded nuclei fallback (built-in)",
	}
	in := append([]models.Finding{embedded},
		mkFinding(models.SeverityHigh, models.ConfidenceHigh, models.SourceHeaders))
	if got := ComputeNucleiCorrelation(Deduplicate(in)); got != nil {
		t.Fatalf("embedded-only must yield nil, got %+v", got)
	}
}

func TestCorrelationPartitions(t *testing.T) {
	// Agreed: native + nuclei report the same issue (same dedup key).
	native := mkFinding(models.SeverityMedium, models.ConfidenceMedium, models.SourceHeaders)
	agreedNuclei := nucleiFinding("nuclei-t1", native.Title)
	agreedNuclei.Category = native.Category
	agreedNuclei.URL = native.URL
	agreedNuclei.Target = native.Target
	// Nuclei-only: distinct key.
	solo := nucleiFinding("nuclei-solo", "Solo nuclei hit")
	// Native-only: distinct key.
	lone := mkFinding(models.SeverityLow, models.ConfidenceLow, models.SourceCookies)
	lone.Title = "Lone native hit"
	got := ComputeNucleiCorrelation(Deduplicate([]models.Finding{native, agreedNuclei, solo, lone}))
	if got == nil {
		t.Fatal("real nuclei data must produce correlation")
	}
	if !got.NucleiAvailable {
		t.Fatal("NucleiAvailable must be true")
	}
	if len(got.Agreed) != 1 || len(got.NucleiOnly) != 1 || len(got.AnpuOnly) != 1 {
		t.Fatalf("partition wrong: %+v", got)
	}
	for _, id := range append(append(got.Agreed, got.NucleiOnly...), got.AnpuOnly...) {
		if id == "" || id == "orig" {
			t.Fatalf("correlation must reference stable IDs, got %q", id)
		}
	}
}

func TestCorrelationSorted(t *testing.T) {
	a := nucleiFinding("nuclei-b", "B hit")
	b := nucleiFinding("nuclei-a", "A hit")
	got := ComputeNucleiCorrelation(Deduplicate([]models.Finding{a, b}))
	if got == nil || len(got.NucleiOnly) != 2 {
		t.Fatalf("expected 2 nuclei-only, got %+v", got)
	}
	if got.NucleiOnly[0] > got.NucleiOnly[1] {
		t.Fatalf("IDs must be sorted: %v", got.NucleiOnly)
	}
}
