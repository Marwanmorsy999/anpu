package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/anpu-project/anpu/pkg/models"
)

// TestLiveScanExample runs the compiled CLI against https://example.com
// — IANA's domain explicitly reserved for documentation and testing —
// and asserts the full pipeline works end-to-end against a real site:
// exit code 0, a JSON report on disk, and parseable summary content.
//
// It is skipped unless ANPU_LIVE_TESTS is set, keeping `go test ./...`
// deterministic and offline-friendly for CI:
//
//	ANPU_LIVE_TESTS=1 go test -run TestLive -v ./cmd/anpu
func TestLiveScanExample(t *testing.T) {
	if os.Getenv("ANPU_LIVE_TESTS") != "1" {
		t.Skip("set ANPU_LIVE_TESTS=1 to run the live-site integration test")
	}

	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "anpu.exe")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build binary: %v\n%s", err, out)
	}

	reportDir := filepath.Join(tmpDir, "reports")
	cmd := exec.Command(binPath,
		"scan", "https://example.com",
		"--profile", "safe", // passive only: polite to the target
		"--json",
		"--html=false",
		"--output", reportDir,
	)
	cmd.Env = append(os.Environ(), "HOME="+tmpDir, "USERPROFILE="+tmpDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("live scan failed: %v\n%s", err, out)
	}

	matches, err := filepath.Glob(filepath.Join(reportDir, "example.com-*.json"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("expected exactly one JSON report in %s, got %d (glob err: %v)", reportDir, len(matches), err)
	}

	data, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("reading report: %v", err)
	}
	var summary models.ScanSummary
	if err := json.Unmarshal(data, &summary); err != nil {
		t.Fatalf("report is not valid ANPU JSON: %v", err)
	}
	if summary.Target != "https://example.com" {
		t.Errorf("report target = %q, want https://example.com", summary.Target)
	}
	if summary.Status != "completed" {
		t.Errorf("scan status = %q, want completed", summary.Status)
	}
	if summary.RiskScore < 0 || summary.RiskScore > 10 {
		t.Errorf("risk score %v out of range [0,10]", summary.RiskScore)
	}
	if summary.Findings == nil {
		t.Error("findings array missing from report")
	}
}
