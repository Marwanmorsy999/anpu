package models

import "testing"

// Phase 0: DedupKey must be stable under query reordering and fall back
// to Target when URL is empty, so diff/drift identity is deterministic.
func TestDedupKeyCanonicalizesQueryOrder(t *testing.T) {
	a := Finding{Category: CategoryVulnerability, URL: "https://example.com/?b=2&a=1", Title: "SQL Injection", Parameter: "q", CWE: "CWE-89"}
	b := Finding{Category: CategoryVulnerability, URL: "https://example.com/?a=1&b=2", Title: "SQL Injection", Parameter: "q", CWE: "CWE-89"}
	if a.DedupKey() != b.DedupKey() {
		t.Fatalf("query order changed DedupKey:\n%s\n%s", a.DedupKey(), b.DedupKey())
	}
}

func TestDedupKeyFallsBackToTarget(t *testing.T) {
	a := Finding{Category: CategoryHeaders, Target: "https://example.com", Title: "HSTS missing"}
	b := Finding{Category: CategoryHeaders, URL: "https://example.com", Title: "HSTS missing"}
	if a.DedupKey() != b.DedupKey() {
		t.Fatalf("target fallback mismatch:\n%s\n%s", a.DedupKey(), b.DedupKey())
	}
}

func TestDedupKeyDistinguishesParamAndCWE(t *testing.T) {
	base := Finding{Category: CategoryVulnerability, URL: "https://example.com/s", Title: "X", Parameter: "a", CWE: "CWE-79"}
	otherParam := base
	otherParam.Parameter = "b"
	otherCWE := base
	otherCWE.CWE = "CWE-89"
	if base.DedupKey() == otherParam.DedupKey() {
		t.Fatal("param must be part of DedupKey")
	}
	if base.DedupKey() == otherCWE.DedupKey() {
		t.Fatal("cwe must be part of DedupKey")
	}
}

func TestSeverityAndConfidenceRanks(t *testing.T) {
	if SeverityCritical.Rank() <= SeverityHigh.Rank() || SeverityHigh.Rank() <= SeverityMedium.Rank() {
		t.Fatal("severity rank order broken")
	}
	if ConfidenceConfirmed.Rank() <= ConfidenceHigh.Rank() || ConfidenceHigh.Rank() <= ConfidenceMedium.Rank() {
		t.Fatal("confidence rank order broken")
	}
	if Severity("bogus").Rank() >= SeverityInfo.Rank() || !SeverityInfo.Valid() {
		t.Fatal("unknown severity handling broken")
	}
	if Confidence("bogus").Valid() || !ConfidenceLow.Valid() {
		t.Fatal("confidence Valid() broken")
	}
}
