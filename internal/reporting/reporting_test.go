package reporting

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anpu-project/anpu/pkg/models"
)

func TestRiskGradeBoundaries(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{0, "A"}, {3.4, "A"}, {3.5, "B"}, {5.4, "B"}, {5.5, "C"},
		{6.9, "C"}, {7, "D"}, {7.9, "D"}, {8, "E"}, {8.9, "E"}, {9, "F"}, {10, "F"},
	}
	for _, c := range cases {
		if got := RiskGrade(c.score); got != c.want {
			t.Errorf("RiskGrade(%.1f) = %s, want %s", c.score, got, c.want)
		}
	}
}

func TestCSVRecordAndHelpers(t *testing.T) {
	f := models.Finding{Severity: models.SeverityHigh, Confidence: models.ConfidenceHigh,
		Category: models.CategoryHeaders, ID: "anpu-1", Title: "HSTS  | missing",
		URL: "https://example.com", CWE: "CWE-693", Source: models.SourceHeaders,
		DetectionMethod: "passive", Description: "line1\nline2  with   spaces",
		Evidence:   models.Evidence{Observed: "header absent"},
		References: []string{"https://a", "https://b"}}
	rec := csvRecord(f)
	if len(rec) != 12 || rec[0] != "high" || rec[3] != "anpu-1" {
		t.Fatalf("csvRecord wrong: %q", rec)
	}
	if strings.Contains(rec[9], "\n") {
		t.Fatalf("description must be one line: %q", rec[9])
	}
	if got := mdCell("a|b"); got != `a\|b` {
		t.Fatalf("mdCell must escape pipes: %q", got)
	}
	if got := mdCell(""); got != "—" {
		t.Fatalf("mdCell empty must be em dash: %q", got)
	}
}

func TestWriteHTMLSeverityOrder(t *testing.T) {
	sum := &models.ScanSummary{Target: "https://example.com",
		Findings: []models.Finding{
			{ID: "i1", Severity: models.SeverityInfo, Confidence: models.ConfidenceHigh, Title: "Info thing", Description: "d"},
			{ID: "l1", Severity: models.SeverityLow, Confidence: models.ConfidenceLow, Title: "Low thing", Description: "d"},
			{ID: "h1", Severity: models.SeverityHigh, Confidence: models.ConfidenceHigh, Title: "High thing", Description: "d"},
		}}
	path := filepath.Join(t.TempDir(), "out.html")
	if err := WriteHTML(sum, path); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	raw, _ := os.ReadFile(path)
	html := string(raw)
	hi, lo, ii := strings.Index(html, "High thing"), strings.Index(html, "Low thing"), strings.Index(html, "Info thing")
	if hi < 0 || lo < 0 || ii < 0 {
		t.Fatal("all findings must render")
	}
	if !(hi < lo && lo < ii) {
		t.Fatal("HTML findings must render worst-first")
	}
	// Caller slice order must be untouched (sorted copy, not in place).
	if sum.Findings[0].ID != "i1" {
		t.Fatal("WriteHTML must not reorder the caller's slice")
	}
}

func TestWriteCSVAndMarkdown(t *testing.T) {
	sum := &models.ScanSummary{Target: "https://example.com", Profile: "safe",
		Findings: []models.Finding{
			{ID: "b", Severity: models.SeverityLow, Confidence: models.ConfidenceLow, Title: "Low"},
			{ID: "a", Severity: models.SeverityHigh, Confidence: models.ConfidenceHigh, Title: "High"},
		}}
	dir := t.TempDir()
	csvPath := filepath.Join(dir, "out.csv")
	if err := WriteCSV(sum, csvPath); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}
	raw, _ := os.ReadFile(csvPath)
	r := csv.NewReader(strings.NewReader(string(raw)))
	rows, err := r.ReadAll()
	if err != nil || len(rows) != 3 {
		t.Fatalf("csv rows: %v %d", err, len(rows))
	}
	if rows[1][3] != "a" {
		t.Fatalf("csv must sort high first, got %v", rows[1])
	}
	mdPath := filepath.Join(dir, "out.md")
	if err := WriteMarkdown(sum, mdPath); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}
	md, _ := os.ReadFile(mdPath)
	if !strings.Contains(string(md), "## Findings") || !strings.Contains(string(md), "| high |") {
		t.Fatalf("markdown missing table:\n%s", md)
	}
}
