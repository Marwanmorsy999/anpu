package findings

import (
	"testing"

	"github.com/anpu-project/anpu/pkg/models"
)

func makeF(id string, conf models.Confidence) models.Finding {
	return models.Finding{ID: id, Confidence: conf, Severity: models.SeverityMedium}
}

func TestFilterByConfidence_NoneDisablesFilter(t *testing.T) {
	in := []models.Finding{makeF("a", models.ConfidenceLow), makeF("b", models.ConfidenceHigh)}
	kept, suppressed := FilterByConfidence(in, "")
	if len(kept) != 2 || len(suppressed) != 0 {
		t.Fatalf("expected all kept; got kept=%d suppressed=%d", len(kept), len(suppressed))
	}
	// must be same slice (no copy)
	if &kept[0] != &in[0] {
		t.Fatal("expected same slice returned when min is empty")
	}
}

func TestFilterByConfidence_LowKeepsAll(t *testing.T) {
	in := []models.Finding{
		makeF("a", models.ConfidenceLow),
		makeF("b", models.ConfidenceMedium),
		makeF("c", models.ConfidenceHigh),
		makeF("d", models.ConfidenceConfirmed),
	}
	kept, suppressed := FilterByConfidence(in, models.ConfidenceLow)
	if len(kept) != 4 || len(suppressed) != 0 {
		t.Fatalf("expected 4 kept 0 suppressed; got %d %d", len(kept), len(suppressed))
	}
}

func TestFilterByConfidence_MediumDropsLow(t *testing.T) {
	in := []models.Finding{
		makeF("low1", models.ConfidenceLow),
		makeF("med1", models.ConfidenceMedium),
		makeF("high1", models.ConfidenceHigh),
	}
	kept, suppressed := FilterByConfidence(in, models.ConfidenceMedium)
	if len(kept) != 2 {
		t.Fatalf("expected 2 kept; got %d", len(kept))
	}
	if len(suppressed) != 1 || suppressed[0].ID != "low1" {
		t.Fatalf("expected low1 suppressed; got %v", suppressed)
	}
}

func TestFilterByConfidence_HighDropsLowAndMedium(t *testing.T) {
	in := []models.Finding{
		makeF("low1", models.ConfidenceLow),
		makeF("med1", models.ConfidenceMedium),
		makeF("high1", models.ConfidenceHigh),
		makeF("conf1", models.ConfidenceConfirmed),
	}
	kept, suppressed := FilterByConfidence(in, models.ConfidenceHigh)
	if len(kept) != 2 || len(suppressed) != 2 {
		t.Fatalf("expected 2/2; got kept=%d suppressed=%d", len(kept), len(suppressed))
	}
}

func TestFilterByConfidence_ConfirmedKeepsOnlyConfirmed(t *testing.T) {
	in := []models.Finding{
		makeF("low1", models.ConfidenceLow),
		makeF("med1", models.ConfidenceMedium),
		makeF("high1", models.ConfidenceHigh),
		makeF("conf1", models.ConfidenceConfirmed),
	}
	kept, suppressed := FilterByConfidence(in, models.ConfidenceConfirmed)
	if len(kept) != 1 || kept[0].ID != "conf1" {
		t.Fatalf("expected only conf1 kept; got %v", kept)
	}
	if len(suppressed) != 3 {
		t.Fatalf("expected 3 suppressed; got %d", len(suppressed))
	}
}

func TestFilterByConfidence_EmptyInput(t *testing.T) {
	kept, suppressed := FilterByConfidence(nil, models.ConfidenceMedium)
	if kept != nil || suppressed != nil {
		t.Fatal("expected both nil for empty input")
	}
}

func TestParseMinConfidence_Valid(t *testing.T) {
	cases := []struct {
		raw  string
		want models.Confidence
	}{
		{"", ""},
		{"none", ""},
		{"low", models.ConfidenceLow},
		{"medium", models.ConfidenceMedium},
		{"high", models.ConfidenceHigh},
		{"confirmed", models.ConfidenceConfirmed},
	}
	for _, tc := range cases {
		got, err := ParseMinConfidence(tc.raw)
		if err != nil {
			t.Errorf("ParseMinConfidence(%q): unexpected error: %v", tc.raw, err)
		}
		if got != tc.want {
			t.Errorf("ParseMinConfidence(%q) = %q; want %q", tc.raw, got, tc.want)
		}
	}
}

func TestParseMinConfidence_Invalid(t *testing.T) {
	for _, bad := range []string{"info", "unknown", "HIGH", "1"} {
		_, err := ParseMinConfidence(bad)
		if err == nil {
			t.Errorf("ParseMinConfidence(%q): expected error, got nil", bad)
		}
	}
}
