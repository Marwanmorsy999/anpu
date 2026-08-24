package diff

import (
	"testing"

	"github.com/anpu-project/anpu/pkg/models"
)

func TestCompareFindingsEndpointsAndRisk(t *testing.T) {
	before := &models.ScanSummary{
		ID: "old", Target: "https://example.com", RiskScore: 4.2,
		Findings:     []models.Finding{{ID: "1", Title: "Missing CSP", Category: models.CategoryHeaders, Severity: models.SeverityMedium, Confidence: models.ConfidenceHigh, Target: "https://example.com", RiskScore: 4.0}},
		Endpoints:    []models.Endpoint{{URL: "https://example.com/old/", Category: models.EndpointPage}},
		Technologies: []models.Technology{{Name: "React", Category: "js-framework", Version: "18"}},
	}
	after := &models.ScanSummary{
		ID: "new", Target: "https://example.com", RiskScore: 6.0,
		Findings:     []models.Finding{{ID: "2", Title: "Missing CSP", Category: models.CategoryHeaders, Severity: models.SeverityHigh, Confidence: models.ConfidenceHigh, Target: "https://example.com", RiskScore: 7.0}, {ID: "3", Title: "Debug endpoint", Category: models.CategoryEndpoint, Severity: models.SeverityHigh, Confidence: models.ConfidenceHigh, Target: "https://example.com", URL: "https://example.com/debug"}},
		Endpoints:    []models.Endpoint{{URL: "https://example.com/old", Category: models.EndpointPage}, {URL: "https://example.com/debug", Category: models.EndpointAdminLike}},
		Technologies: []models.Technology{{Name: "React", Category: "js-framework", Version: "19"}},
	}

	r := Compare(before, after)
	if r.RiskDelta != 1.8 {
		t.Fatalf("expected risk delta 1.8, got %.1f", r.RiskDelta)
	}
	if r.FindingsAdded != 1 || r.FindingsRemoved != 0 || r.FindingsChanged != 1 {
		t.Fatalf("unexpected finding counts: +%d -%d ~%d", r.FindingsAdded, r.FindingsRemoved, r.FindingsChanged)
	}
	if r.EndpointsAdded != 1 || r.EndpointsRemoved != 0 {
		t.Fatalf("unexpected endpoint counts: +%d -%d", r.EndpointsAdded, r.EndpointsRemoved)
	}
	if r.TechnologiesAdded != 0 || r.TechnologiesRemoved != 0 {
		t.Fatalf("technology add/remove mismatch: +%d -%d", r.TechnologiesAdded, r.TechnologiesRemoved)
	}
	if len(r.Technologies) != 1 || r.Technologies[0].Kind != "changed" || r.Technologies[0].Previous.Version != "18" {
		t.Fatalf("expected React 18 → 19 change, got %#v", r.Technologies)
	}
}
