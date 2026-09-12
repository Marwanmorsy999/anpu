package findings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Marwanmorsy999/anpu/pkg/models"
)

func TestFilterByConfidenceEmptyMinPassthrough(t *testing.T) {
	in := []models.Finding{
		mkFinding(models.SeverityLow, models.ConfidenceLow, models.SourceHeaders),
		mkFinding(models.SeverityHigh, models.ConfidenceHigh, models.SourceCustom),
	}
	kept, suppressed := FilterByConfidence(in, "")
	if len(kept) != 2 || len(suppressed) != 0 {
		t.Fatalf("empty min must keep all: kept=%d suppressed=%d", len(kept), len(suppressed))
	}
}

func TestFilterByConfidenceSplitsOnRank(t *testing.T) {
	in := []models.Finding{
		mkFinding(models.SeverityLow, models.ConfidenceLow, models.SourceHeaders),
		mkFinding(models.SeverityMedium, models.ConfidenceMedium, models.SourceHeaders),
		mkFinding(models.SeverityHigh, models.ConfidenceHigh, models.SourceHeaders),
	}
	kept, suppressed := FilterByConfidence(in, models.ConfidenceMedium)
	if len(kept) != 2 || len(suppressed) != 1 {
		t.Fatalf("medium min must keep 2, suppress 1: kept=%d suppressed=%d", len(kept), len(suppressed))
	}
	if suppressed[0].Confidence != models.ConfidenceLow {
		t.Fatalf("suppressed must be the low-confidence finding, got %s", suppressed[0].Confidence)
	}
}

func TestParseMinConfidence(t *testing.T) {
	for _, raw := range []string{"", "none"} {
		got, err := ParseMinConfidence(raw)
		if err != nil || got != "" {
			t.Fatalf("ParseMinConfidence(%q) must disable filter, got %q, %v", raw, got, err)
		}
	}
	got, err := ParseMinConfidence("high")
	if err != nil || got != models.ConfidenceHigh {
		t.Fatalf("ParseMinConfidence(high) = %q, %v", got, err)
	}
	if _, err := ParseMinConfidence("bogus"); err == nil {
		t.Fatal("ParseMinConfidence(bogus) must error")
	} else if !strings.Contains(err.Error(), "invalid --min-confidence") {
		t.Fatalf("error must name the flag, got %q", err.Error())
	}
}

func TestLoadRiskAcceptRoundTrip(t *testing.T) {
	doc := "accept:\n" +
		"  - id: anpu-abc123def456\n" +
		"    reason: \"WAF covers this; retest in Q3\"\n" +
		"    expires: 2027-12-31\n"
	path := filepath.Join(t.TempDir(), "riskaccept.yaml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := LoadRiskAccept(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].ID != "anpu-abc123def456" || entries[0].Reason == "" || entries[0].Expires != "2027-12-31" {
		t.Fatalf("entry mismatch: %+v", entries[0])
	}
}

func TestLoadRiskAcceptErrors(t *testing.T) {
	if _, err := LoadRiskAccept(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("missing file must error")
	}
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("accept:\n\t- {unclosed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRiskAccept(bad); err == nil {
		t.Fatal("malformed YAML must error")
	}
}

func TestApplyRiskAccept(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	mk := func(id string) models.Finding {
		f := mkFinding(models.SeverityHigh, models.ConfidenceHigh, models.SourceHeaders)
		f.ID = id
		return f
	}
	findings := []models.Finding{mk("active-1"), mk("expired-1"), mk("badexp-1"), mk("unmatched-1")}
	entries := []RiskAcceptEntry{
		{ID: "active-1", Reason: "accepted", Expires: "2027-01-01"},
		{ID: "expired-1", Reason: "stale", Expires: "2026-01-01"},
		{ID: "badexp-1", Reason: "typo", Expires: "not-a-date"},
		{ID: "", Reason: "empty id is skipped"},
	}
	kept, suppressed, notes := ApplyRiskAccept(findings, entries, now)
	if len(suppressed) != 1 || suppressed[0] != "active-1" {
		t.Fatalf("only active-1 must suppress, got %v", suppressed)
	}
	keptIDs := map[string]bool{}
	for _, f := range kept {
		keptIDs[f.ID] = true
	}
	for _, id := range []string{"expired-1", "badexp-1", "unmatched-1"} {
		if !keptIDs[id] {
			t.Fatalf("%s must be kept, kept=%v", id, keptIDs)
		}
	}
	if len(notes) != 2 {
		t.Fatalf("expected 2 notes (expired + bad expiry), got %v", notes)
	}
}
