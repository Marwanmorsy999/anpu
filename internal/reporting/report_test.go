package reporting

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anpu-project/anpu/pkg/models"
)

func sampleSummary() *models.ScanSummary {
	s := &models.ScanSummary{
		ID:        "scan-test-1",
		Target:    "https://example.com",
		Profile:   models.ProfileSafe,
		StartedAt: time.Now(),
		Status:    "completed",
		Findings: []models.Finding{
			{
				ID: "f1", Title: "Missing CSP", Description: "desc",
				Severity: models.SeverityLow, Confidence: models.ConfidenceMedium,
				Category: models.CategoryHeaders, Target: "https://example.com", URL: "https://example.com/",
				Evidence: models.Evidence{Unavailable: true}, Source: models.SourceHeaders,
				RiskScore: 1.5, ScoreExplanation: "test",
			},
			{
				ID: "f2", Title: "Expired cert", Description: "desc2",
				Severity: models.SeverityHigh, Confidence: models.ConfidenceConfirmed,
				Category: models.CategoryTLS, Target: "https://example.com", URL: "https://example.com/",
				Evidence: models.Evidence{Observed: "NotAfter=2020-01-01"}, Source: models.SourceTLS,
				RiskScore: 8.1, ScoreExplanation: "test2",
			},
		},
		Technologies: []models.Technology{{Name: "nginx", Category: "web-server", Version: "1.18.0"}},
		Endpoints:    []models.Endpoint{{URL: "https://example.com/admin", Category: models.EndpointAdminLike, Sources: []string{"html-link"}}},
		RiskScore:    8.1,
	}
	s.RecomputeSeverityCounts()
	return s
}

func TestWriteJSON_RoundTrips(t *testing.T) {
	s := sampleSummary()
	path := filepath.Join(t.TempDir(), "report.json")
	if err := WriteJSON(s, path); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading written report: %v", err)
	}
	var decoded models.ScanSummary
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decoded JSON did not parse back into ScanSummary: %v", err)
	}
	if decoded.ID != s.ID || len(decoded.Findings) != len(s.Findings) {
		t.Errorf("round-tripped summary does not match original: %+v", decoded)
	}
}

func TestWriteSARIF_ProducesValidStructure(t *testing.T) {
	s := sampleSummary()
	path := filepath.Join(t.TempDir(), "report.sarif")
	if err := WriteSARIF(s, path); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading written SARIF: %v", err)
	}
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("written SARIF did not parse: %v", err)
	}
	if log.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %s", log.Version)
	}
	if len(log.Runs) != 1 || len(log.Runs[0].Results) != len(s.Findings) {
		t.Errorf("expected %d SARIF results, got structure %+v", len(s.Findings), log.Runs)
	}
}

func TestWriteHTML_ContainsKeyContent(t *testing.T) {
	s := sampleSummary()
	path := filepath.Join(t.TempDir(), "report.html")
	if err := WriteHTML(s, path); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading written HTML: %v", err)
	}
	html := string(data)

	for _, want := range []string{"ANPU", s.Target, "Missing CSP", "Expired cert", "Evidence unavailable", "NotAfter=2020-01-01"} {
		if !strings.Contains(html, want) {
			t.Errorf("expected HTML report to contain %q", want)
		}
	}
}

func TestWriteHTML_EvidenceNeverFabricated(t *testing.T) {
	s := sampleSummary()
	path := filepath.Join(t.TempDir(), "report.html")
	if err := WriteHTML(s, path); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, _ := os.ReadFile(path)
	html := string(data)
	// The finding with Unavailable=true must render the literal
	// "Evidence unavailable" marker rather than any invented content.
	if !strings.Contains(html, "Evidence unavailable") {
		t.Error("expected report to explicitly mark unavailable evidence")
	}
}
