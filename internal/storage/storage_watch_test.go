package storage

import (
	"os"
	"testing"
	"time"

	"github.com/anpu-project/anpu/pkg/models"
)

func TestLatestScanForTarget_NoScans(t *testing.T) {
	f, err := os.CreateTemp("", "anpu-watch-*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name())

	store, err := Open(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	got, err := store.LatestScanForTarget("https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for no scans, got %v", got)
	}
}

func TestLatestScanForTarget_ReturnsLatestCompleted(t *testing.T) {
	f, err := os.CreateTemp("", "anpu-watch-*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name())

	store, err := Open(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	now := time.Now().UTC().Truncate(time.Second)
	older := makeScan("scan-1", "https://example.com", now.Add(-2*time.Hour), "completed")
	newer := makeScan("scan-2", "https://example.com", now.Add(-1*time.Hour), "completed")
	other := makeScan("scan-3", "https://other.com", now, "completed")

	for _, s := range []*models.ScanSummary{older, newer, other} {
		if err := store.SaveScan(s); err != nil {
			t.Fatalf("SaveScan: %v", err)
		}
	}

	got, err := store.LatestScanForTarget("https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected a scan, got nil")
	}
	if got.ID != "scan-2" {
		t.Errorf("expected scan-2 (newer), got %q", got.ID)
	}
}

func TestLatestScanForTarget_SkipsNonCompleted(t *testing.T) {
	f, err := os.CreateTemp("", "anpu-watch-*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name())

	store, err := Open(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	now := time.Now().UTC().Truncate(time.Second)
	completed := makeScan("scan-1", "https://example.com", now.Add(-2*time.Hour), "completed")
	failed := makeScan("scan-2", "https://example.com", now.Add(-1*time.Hour), "failed")
	running := makeScan("scan-3", "https://example.com", now, "running")

	for _, s := range []*models.ScanSummary{completed, failed, running} {
		if err := store.SaveScan(s); err != nil {
			t.Fatalf("SaveScan: %v", err)
		}
	}

	got, err := store.LatestScanForTarget("https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected a scan, got nil")
	}
	if got.ID != "scan-1" {
		t.Errorf("expected scan-1 (only completed), got %q", got.ID)
	}
}

func makeScan(id, target string, completedAt time.Time, status string) *models.ScanSummary {
	return &models.ScanSummary{
		ID:          id,
		Target:      target,
		Profile:     models.ProfileSafe,
		StartedAt:   completedAt.Add(-30 * time.Second),
		CompletedAt: completedAt,
		Status:      status,
		RiskScore:   3.0,
	}
}
