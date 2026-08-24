package main

import (
	"testing"

	"github.com/anpu-project/anpu/pkg/models"
)

func TestParseFailOn(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want models.Severity
	}{
		{"none", ""}, {"high", models.SeverityHigh}, {"CRITICAL", models.SeverityCritical},
	} {
		got, err := parseFailOn(tc.raw)
		if err != nil || got != tc.want {
			t.Fatalf("parseFailOn(%q) = %q, %v; want %q", tc.raw, got, err, tc.want)
		}
	}
	if _, err := parseFailOn("info"); err == nil {
		t.Fatal("expected info threshold to be rejected")
	}
	if _, err := parseFailOn("banana"); err == nil {
		t.Fatal("expected invalid threshold to be rejected")
	}
}

func TestScanMeetsThreshold(t *testing.T) {
	s := &models.ScanSummary{Findings: []models.Finding{{Severity: models.SeverityMedium}}}
	if scanMeetsThreshold(s, models.SeverityHigh) {
		t.Fatal("medium finding should not fail high threshold")
	}
	if !scanMeetsThreshold(s, models.SeverityMedium) {
		t.Fatal("medium finding should fail medium threshold")
	}
}
