package storage

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/anpu-project/anpu/pkg/models"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("opening test store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func sampleSummary(id string) *models.ScanSummary {
	s := &models.ScanSummary{
		ID:          id,
		Target:      "https://example.com",
		Profile:     models.ProfileSafe,
		StartedAt:   time.Now(),
		CompletedAt: time.Now(),
		Status:      "completed",
		RiskScore:   5.5,
		Findings: []models.Finding{
			{ID: "f1", Title: "Test finding", Severity: models.SeverityMedium, Confidence: models.ConfidenceHigh,
				Category: models.CategoryHeaders, Target: "https://example.com", URL: "https://example.com/",
				Evidence: models.Evidence{Observed: "X-Test: 1"}, Source: models.SourceHeaders, RiskScore: 5.5},
		},
		Technologies: []models.Technology{{Name: "nginx", Category: "web-server", Confidence: 0.8}},
		Endpoints:    []models.Endpoint{{URL: "https://example.com/admin", Category: models.EndpointAdminLike, Sources: []string{"html-link"}}},
	}
	return s
}

func TestSaveAndGetScan_RoundTrips(t *testing.T) {
	store := newTestStore(t)
	original := sampleSummary("scan-1")

	if err := store.SaveScan(original); err != nil {
		t.Fatalf("SaveScan failed: %v", err)
	}

	got, err := store.GetScan("scan-1")
	if err != nil {
		t.Fatalf("GetScan failed: %v", err)
	}
	if got.Target != original.Target {
		t.Errorf("expected target %q, got %q", original.Target, got.Target)
	}
	if len(got.Findings) != 1 || got.Findings[0].Title != "Test finding" {
		t.Errorf("expected 1 finding round-tripped, got %+v", got.Findings)
	}
	if len(got.Technologies) != 1 || got.Technologies[0].Name != "nginx" {
		t.Errorf("expected technology round-tripped, got %+v", got.Technologies)
	}
	if len(got.Endpoints) != 1 {
		t.Errorf("expected 1 endpoint round-tripped, got %+v", got.Endpoints)
	}
}

func TestGetScan_UnknownIDErrors(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.GetScan("does-not-exist"); err == nil {
		t.Error("expected error for unknown scan id")
	}
}

func TestListScans_OrderedMostRecentFirst(t *testing.T) {
	store := newTestStore(t)

	s1 := sampleSummary("scan-a")
	s1.StartedAt = time.Now().Add(-time.Hour)
	s2 := sampleSummary("scan-b")
	s2.StartedAt = time.Now()

	if err := store.SaveScan(s1); err != nil {
		t.Fatalf("saving s1: %v", err)
	}
	if err := store.SaveScan(s2); err != nil {
		t.Fatalf("saving s2: %v", err)
	}

	list, err := store.ListScans(10)
	if err != nil {
		t.Fatalf("ListScans failed: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 scans, got %d", len(list))
	}
	if list[0].ID != "scan-b" {
		t.Errorf("expected most recent scan (scan-b) first, got %s", list[0].ID)
	}
}

func TestSaveScan_OverwritesOnReplay(t *testing.T) {
	store := newTestStore(t)
	s := sampleSummary("scan-x")
	if err := store.SaveScan(s); err != nil {
		t.Fatalf("first save: %v", err)
	}
	s.RiskScore = 9.9
	s.Findings = append(s.Findings, models.Finding{ID: "f2", Title: "Second", Severity: models.SeverityLow, Confidence: models.ConfidenceLow, Category: models.CategoryCookies, Target: "https://example.com"})
	if err := store.SaveScan(s); err != nil {
		t.Fatalf("second save: %v", err)
	}

	got, err := store.GetScan("scan-x")
	if err != nil {
		t.Fatalf("GetScan: %v", err)
	}
	if got.RiskScore != 9.9 {
		t.Errorf("expected updated risk score 9.9, got %.1f", got.RiskScore)
	}
	if len(got.Findings) != 2 {
		t.Errorf("expected 2 findings after replay (no stale duplicates), got %d", len(got.Findings))
	}
}
