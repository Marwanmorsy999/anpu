package feeds

import (
	"strings"
	"testing"

	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// Sanity-pass follow-up: a CISA KEV listing corroborates a strong
// finding but must never manufacture Confirmed certainty for a weak
// one (e.g. a rule that merely mentions the CVE in its own text).
func TestEnrichKEVNeedsHighConfidence(t *testing.T) {
	kev := map[string]bool{"CVE-2021-44228": true}

	strong := []models.Finding{{
		ID: "nuclei-cve", Title: "CVE-2021-44228 RCE", Severity: models.SeverityHigh,
		Confidence: models.ConfidenceHigh, Category: models.CategoryVulnerability,
	}}
	got := Enrich(strong, kev, false)
	if got[0].Confidence != models.ConfidenceConfirmed {
		t.Fatalf("KEV must confirm an already-High finding, got %s", got[0].Confidence)
	}
	if !strings.Contains(strings.Join(got[0].References, " "), "cisa.gov") {
		t.Fatal("KEV reference must be attached")
	}

	weak := []models.Finding{{
		ID: "active-log4shell-1", Title: "Log4Shell JNDI string reflected — potential CVE-2021-44228 indicator",
		Description: "injected ${jndi:ldap://...} reflected; see CVE-2021-44228",
		Severity:    models.SeverityHigh, Confidence: models.ConfidenceMedium,
		Category: models.CategoryVulnerability,
	}}
	got = Enrich(weak, kev, false)
	if got[0].Confidence != models.ConfidenceMedium {
		t.Fatalf("KEV must not promote Medium to Confirmed, got %s", got[0].Confidence)
	}
	if !strings.Contains(strings.Join(got[0].References, " "), "cisa.gov") {
		t.Fatal("KEV reference must still be attached as intel")
	}
}

func TestEnrichNoKEVUntouched(t *testing.T) {
	fs := []models.Finding{{
		ID: "x", Title: "Missing header", Severity: models.SeverityLow,
		Confidence: models.ConfidenceMedium, Category: models.CategoryHeaders,
	}}
	got := Enrich(fs, map[string]bool{}, false)
	if got[0].Confidence != models.ConfidenceMedium || len(got[0].References) != 0 {
		t.Fatalf("non-KEV findings must pass through, got %+v", got[0])
	}
}
