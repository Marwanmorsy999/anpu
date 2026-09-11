package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

// Phase 6: checkpoints are versioned so resume can never silently mix
// incompatible stage results across label renames or format changes.
func TestCheckpointRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cp.json")
	completed := map[string]StageResult{
		"Headers": {Warnings: []string{"w"}},
	}
	saveCheckpoint(path, "https://example.com", "safe", completed)
	cp, err := loadCheckpoint(path)
	if err != nil {
		t.Fatalf("loadCheckpoint: %v", err)
	}
	if cp.Version != CheckpointVersion || cp.Target != "https://example.com" || cp.Profile != "safe" {
		t.Fatalf("roundtrip wrong: %+v", cp)
	}
	if len(cp.Stages) != 1 || len(cp.Stages["Headers"].Warnings) != 1 {
		t.Fatalf("stages lost: %+v", cp.Stages)
	}
}

func TestCheckpointLegacyRejected(t *testing.T) {
	// Pre-version files (no version field) must restart fresh with a
	// warning, never merge silently.
	path := filepath.Join(t.TempDir(), "legacy.json")
	legacy := `{"target":"https://example.com","profile":"safe","stages":{"Headers":{}}}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCheckpoint(path); err == nil {
		t.Fatal("legacy unversioned checkpoint must be rejected")
	}
}

func TestCheckpointWrongVersionRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "future.json")
	future := `{"version":999,"target":"https://example.com","profile":"safe","stages":{}}`
	if err := os.WriteFile(path, []byte(future), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCheckpoint(path); err == nil {
		t.Fatal("future-version checkpoint must be rejected")
	}
}

func TestCheckpointMissingFile(t *testing.T) {
	if _, err := loadCheckpoint(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("missing file must error")
	}
}
