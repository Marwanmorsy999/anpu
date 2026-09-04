package headers

import (
	"testing"

	"github.com/anpu-project/anpu/pkg/models"
)

// hsts helper — shorthand for calling checkHSTSQuality with a stock target/url.
func hstsFindings(value string) []models.Finding {
	return checkHSTSQuality(value, "https://example.com", "https://example.com/")
}

// --- parseHSTS unit tests ---

func TestParseHSTS_Full(t *testing.T) {
	maxAge, sub, preload := parseHSTS("max-age=31536000; includeSubDomains; preload")
	if maxAge != 31536000 {
		t.Errorf("maxAge: got %d, want 31536000", maxAge)
	}
	if !sub {
		t.Error("includeSubDomains: expected true")
	}
	if !preload {
		t.Error("preload: expected true")
	}
}

func TestParseHSTS_MaxAgeOnly(t *testing.T) {
	maxAge, sub, preload := parseHSTS("max-age=15552000")
	if maxAge != 15552000 {
		t.Errorf("maxAge: got %d, want 15552000", maxAge)
	}
	if sub || preload {
		t.Error("expected no includeSubDomains or preload")
	}
}

func TestParseHSTS_MissingMaxAge(t *testing.T) {
	maxAge, sub, _ := parseHSTS("includeSubDomains; preload")
	if maxAge != -1 {
		t.Errorf("maxAge: got %d, want -1 (absent)", maxAge)
	}
	if !sub {
		t.Error("expected includeSubDomains true")
	}
}

func TestParseHSTS_MaxAgeZero(t *testing.T) {
	maxAge, _, _ := parseHSTS("max-age=0")
	if maxAge != 0 {
		t.Errorf("maxAge: got %d, want 0", maxAge)
	}
}

func TestParseHSTS_Empty(t *testing.T) {
	maxAge, sub, preload := parseHSTS("")
	if maxAge != -1 || sub || preload {
		t.Errorf("empty value: got maxAge=%d sub=%v preload=%v", maxAge, sub, preload)
	}
}

func TestParseHSTS_CaseInsensitive(t *testing.T) {
	maxAge, sub, preload := parseHSTS("Max-Age=86400; IncludeSubDomains; Preload")
	if maxAge != 86400 {
		t.Errorf("maxAge: got %d, want 86400", maxAge)
	}
	if !sub || !preload {
		t.Error("expected sub and preload true")
	}
}

// --- checkHSTSQuality integration tests ---

func TestHSTSQuality_NoFindings(t *testing.T) {
	// max-age=31536000, includeSubDomains, preload — textbook correct.
	f := hstsFindings("max-age=31536000; includeSubDomains; preload")
	if len(f) != 0 {
		t.Errorf("strict HSTS policy produced %d unexpected findings: %v", len(f), ids(f))
	}
}

func TestHSTSQuality_MissingMaxAge(t *testing.T) {
	f := hstsFindings("includeSubDomains")
	if !hasFindingID(f, "headers-hsts-missing-max-age") {
		t.Errorf("expected headers-hsts-missing-max-age, got %v", ids(f))
	}
}

func TestHSTSQuality_MaxAgeZero(t *testing.T) {
	f := hstsFindings("max-age=0")
	if !hasFindingID(f, "headers-hsts-max-age-zero") {
		t.Errorf("expected headers-hsts-max-age-zero, got %v", ids(f))
	}
}

func TestHSTSQuality_MaxAgeTooShort(t *testing.T) {
	// 86400 = 1 day, well below 30-day threshold.
	f := hstsFindings("max-age=86400")
	if !hasFindingID(f, "headers-hsts-max-age-too-short") {
		t.Errorf("expected headers-hsts-max-age-too-short, got %v", ids(f))
	}
}

func TestHSTSQuality_MaxAgeBelowPreloadMin(t *testing.T) {
	// 5184000 = 60 days — above 30d but below 180d preload minimum.
	f := hstsFindings("max-age=5184000")
	if !hasFindingID(f, "headers-hsts-max-age-below-preload-min") {
		t.Errorf("expected headers-hsts-max-age-below-preload-min, got %v", ids(f))
	}
}

func TestHSTSQuality_PreloadShortMaxAge(t *testing.T) {
	// preload + includeSubDomains, but max-age only 180d — below 1-year requirement.
	f := hstsFindings("max-age=15552000; includeSubDomains; preload")
	if !hasFindingID(f, "headers-hsts-preload-max-age-insufficient") {
		t.Errorf("expected headers-hsts-preload-max-age-insufficient, got %v", ids(f))
	}
}

func TestHSTSQuality_PreloadMissingIncludeSubDomains(t *testing.T) {
	// preload + 1-year max-age but no includeSubDomains.
	f := hstsFindings("max-age=31536000; preload")
	if !hasFindingID(f, "headers-hsts-preload-missing-include-subdomains") {
		t.Errorf("expected headers-hsts-preload-missing-include-subdomains, got %v", ids(f))
	}
}

func TestHSTSQuality_MissingIncludeSubdomainsIsInfo(t *testing.T) {
	// 1 year, no includeSubDomains, no preload — exactly one Info finding.
	f := hstsFindings("max-age=31536000")
	if !hasFindingID(f, "headers-hsts-missing-include-subdomains") {
		t.Errorf("expected headers-hsts-missing-include-subdomains, got %v", ids(f))
	}
	if len(f) != 1 {
		t.Errorf("expected exactly 1 finding, got %d: %v", len(f), ids(f))
	}
	if f[0].Severity != models.SeverityInfo {
		t.Errorf("severity: got %q, want info", f[0].Severity)
	}
}

func TestHSTSQuality_SeverityTooShortIsMedium(t *testing.T) {
	f := hstsFindings("max-age=86400")
	for _, finding := range f {
		if finding.ID == "headers-hsts-max-age-too-short" {
			if finding.Severity != models.SeverityMedium {
				t.Errorf("severity: got %q, want medium", finding.Severity)
			}
			return
		}
	}
	t.Error("headers-hsts-max-age-too-short finding not found")
}

func TestHSTSQuality_SeverityBelowPreloadMinIsLow(t *testing.T) {
	f := hstsFindings("max-age=5184000")
	for _, finding := range f {
		if finding.ID == "headers-hsts-max-age-below-preload-min" {
			if finding.Severity != models.SeverityLow {
				t.Errorf("severity: got %q, want low", finding.Severity)
			}
			return
		}
	}
	t.Error("headers-hsts-max-age-below-preload-min finding not found")
}

func TestHSTSQuality_EvidenceContainsHeaderValue(t *testing.T) {
	value := "max-age=31536000; includeSubDomains"
	f := hstsFindings(value)
	for _, finding := range f {
		if finding.Evidence.Observed == "" {
			t.Errorf("finding %s has empty Evidence.Observed", finding.ID)
		}
	}
}
