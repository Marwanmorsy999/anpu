package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Marwanmorsy999/anpu/pkg/models"
)

func writeJSONReport(t *testing.T, summary models.ScanSummary) string {
	t.Helper()
	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "scan.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadDiffInputJSONFile(t *testing.T) {
	path := writeJSONReport(t, models.ScanSummary{
		ID:     "scan-file-1",
		Target: "https://example.com",
		Findings: []models.Finding{{
			ID: "f1", Title: "X", Severity: models.SeverityHigh,
			Target: "https://example.com",
		}},
	})
	summary, err := loadDiffInput(path)
	if err != nil {
		t.Fatalf("loadDiffInput: %v", err)
	}
	if summary.ID != "scan-file-1" || len(summary.Findings) != 1 {
		t.Fatalf("wrong summary: %+v", summary)
	}
}

func TestLoadDiffInputRejectsLossy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan.html")
	if err := os.WriteFile(path, []byte("<html></html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDiffInput(path); err == nil {
		t.Fatal("HTML report must be rejected with a pointer to JSON")
	}
}

func TestLoadDiffInputRejectsNonReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "other.json")
	if err := os.WriteFile(path, []byte(`{"hello":"world"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDiffInput(path); err == nil {
		t.Fatal("non-report JSON must be rejected")
	}
}
