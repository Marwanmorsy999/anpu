package diff

import (
	"strings"
	"testing"

	"github.com/Marwanmorsy999/anpu/pkg/models"
)

func sumry(id, target string, risk float64, findings []models.Finding, endpoints []models.Endpoint, tech []models.Technology) *models.ScanSummary {
	return &models.ScanSummary{ID: id, Target: target, RiskScore: risk, Findings: findings, Endpoints: endpoints, Technologies: tech}
}

func TestCompareAddedRemovedChanged(t *testing.T) {
	before := sumry("a", "https://example.com", 3.0, []models.Finding{
		{Title: "Gone", Category: models.CategoryHeaders, URL: "https://example.com/", Severity: models.SeverityLow, Confidence: models.ConfidenceMedium},
		{Title: "Same", Category: models.CategoryHeaders, URL: "https://example.com/", Severity: models.SeverityLow, Confidence: models.ConfidenceMedium},
	}, nil, nil)
	after := sumry("b", "https://example.com", 5.0, []models.Finding{
		{Title: "Same", Category: models.CategoryHeaders, URL: "https://example.com/", Severity: models.SeverityHigh, Confidence: models.ConfidenceMedium},
		{Title: "New", Category: models.CategoryHeaders, URL: "https://example.com/", Severity: models.SeverityLow, Confidence: models.ConfidenceMedium},
	}, nil, nil)
	r := Compare(before, after)
	if r.FindingsAdded != 1 || r.FindingsRemoved != 1 || r.FindingsChanged != 1 {
		t.Fatalf("added=%d removed=%d changed=%d", r.FindingsAdded, r.FindingsRemoved, r.FindingsChanged)
	}
	if r.RiskDelta != 2.0 {
		t.Fatalf("delta must be 2.0, got %.1f", r.RiskDelta)
	}
	if !strings.Contains(r.Summary(), "worse") {
		t.Fatalf("summary must say worse: %q", r.Summary())
	}
}

func TestCompareEndpointsAndTech(t *testing.T) {
	before := sumry("a", "https://example.com", 0, nil,
		[]models.Endpoint{{URL: "https://example.com/"}},
		[]models.Technology{{Name: "Nginx", Category: "server", Version: "1.24"}})
	after := sumry("b", "https://example.com", 0, nil,
		[]models.Endpoint{{URL: "https://example.com/"}, {URL: "https://example.com/app"}},
		[]models.Technology{{Name: "nginx", Category: "server", Version: "1.26"}})
	r := Compare(before, after)
	if r.EndpointsAdded != 1 || r.EndpointsRemoved != 0 {
		t.Fatalf("endpoints +%d/-%d", r.EndpointsAdded, r.EndpointsRemoved)
	}
	if len(r.Technologies) != 1 || r.Technologies[0].Kind != "changed" {
		t.Fatalf("tech version bump must be changed, got %+v", r.Technologies)
	}
}
