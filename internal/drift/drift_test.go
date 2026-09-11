package drift

import (
	"testing"

	"github.com/anpu-project/anpu/pkg/models"
)

func TestCompareNilPinsUnreliable(t *testing.T) {
	base := &models.ScanSummary{RiskScore: 1, Findings: []models.Finding{{ID: "a"}}}
	cur := &models.ScanSummary{RiskScore: 1, Findings: []models.Finding{{ID: "a"}}}
	r := Compare(base, cur, nil)
	if r.Reliable {
		t.Fatal("nil pins must be unreliable")
	}
	if len(r.Added) != 0 || len(r.Removed) != 0 {
		t.Fatalf("no drift expected: %+v", r)
	}
}

func TestComparePinDriftAndIDs(t *testing.T) {
	pins := ParserVersions()
	pins["active"] = "0"
	base := &models.ScanSummary{RiskScore: 1, Endpoints: []models.Endpoint{{URL: "https://example.com/"}},
		Findings: []models.Finding{{ID: "a"}, {ID: "b"}}}
	cur := &models.ScanSummary{RiskScore: 2, Endpoints: []models.Endpoint{{URL: "https://example.com/"}, {URL: "https://example.com/x"}},
		Findings: []models.Finding{{ID: "b"}, {ID: "c"}}}
	r := Compare(base, cur, pins)
	if r.Reliable {
		t.Fatal("tampered pin must be unreliable")
	}
	if len(r.Added) != 1 || r.Added[0] != "c" || len(r.Removed) != 1 || r.Removed[0] != "a" {
		t.Fatalf("added/removed wrong: %+v", r)
	}
	if r.EndpointDelta != 1 {
		t.Fatalf("endpoint delta must be 1, got %d", r.EndpointDelta)
	}
}

func TestParserVersionsPinned(t *testing.T) {
	v := ParserVersions()
	for _, k := range []string{"headers", "active", "dirs", "nuclei"} {
		if v[k] == "" {
			t.Fatalf("ParserVersions missing %q", k)
		}
	}
}
