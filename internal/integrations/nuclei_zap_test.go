package integrations

import (
	"strings"
	"testing"

	"github.com/anpu-project/anpu/pkg/models"
)

// Phase 1: template matches with no captured evidence must never be
// High/High — cap at Medium/Medium and say so.
func TestConvertNucleiUnavailableCapped(t *testing.T) {
	var nl nucleiJSONLine
	nl.TemplateID = "cve-2026-0001"
	nl.Info.Name = "Some CVE"
	nl.Info.Severity = "critical"
	nl.MatchedAt = "https://example.com/"
	f := convertNucleiFinding(nl, "https://example.com")
	if !f.Evidence.Unavailable {
		t.Fatal("expected evidence.Unavailable")
	}
	if f.Severity != models.SeverityMedium || f.Confidence != models.ConfidenceMedium {
		t.Fatalf("unavailable must cap at Medium/Medium, got %s/%s", f.Severity, f.Confidence)
	}
	if !strings.Contains(f.Description, "capped at Medium") {
		t.Fatalf("cap must be explicit: %q", f.Description)
	}
}

func TestConvertNucleiWithEvidenceKeepsSeverity(t *testing.T) {
	var nl nucleiJSONLine
	nl.TemplateID = "exposure-config"
	nl.Info.Name = "Config exposure"
	nl.Info.Severity = "high"
	nl.MatchedAt = "https://example.com/.env"
	nl.ExtractedResults = []string{"DB_PASSWORD=..."}
	f := convertNucleiFinding(nl, "https://example.com")
	if f.Severity != models.SeverityHigh || f.Confidence != models.ConfidenceHigh {
		t.Fatalf("evidenced match keeps severity, got %s/%s", f.Severity, f.Confidence)
	}
	if f.Evidence.Unavailable {
		t.Fatal("extracted results are evidence")
	}
}

func TestConvertZapUnavailableCapped(t *testing.T) {
	a := zapAlert{PluginID: "10021", Name: "X-Content-Type-Options", RiskCode: "3", Confidence: "3"}
	f, skip := convertZapAlert(a, "https://example.com")
	if skip != "" || f == nil {
		t.Fatalf("expected finding, got %+v skip=%q", f, skip)
	}
	if !f.Evidence.Unavailable {
		t.Fatal("expected evidence.Unavailable without instances")
	}
	if f.Severity != models.SeverityMedium || f.Confidence != models.ConfidenceMedium {
		t.Fatalf("unavailable must cap at Medium/Medium, got %s/%s", f.Severity, f.Confidence)
	}
}

func TestConvertZapWithEvidenceKeepsSeverity(t *testing.T) {
	a := zapAlert{PluginID: "40012", Name: "XSS", RiskCode: "3", Confidence: "3"}
	a.Instances = append(a.Instances, struct {
		URI      string `json:"uri"`
		Method   string `json:"method"`
		Param    string `json:"param"`
		Evidence string `json:"evidence"`
	}{URI: "https://example.com/s?q=1", Evidence: "<script>alert(1)</script>"})
	f, _ := convertZapAlert(a, "https://example.com")
	if f.Severity != models.SeverityHigh || f.Confidence != models.ConfidenceHigh {
		t.Fatalf("evidenced alert keeps severity, got %s/%s", f.Severity, f.Confidence)
	}
	if f.Evidence.Unavailable {
		t.Fatal("instance evidence must clear Unavailable")
	}
}
