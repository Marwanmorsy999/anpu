package importx

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/anpu-project/anpu/pkg/models"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return data
}

func TestParseBurpFixture(t *testing.T) {
	fs, err := ParseBurp(fixture(t, "burp-sample.xml"), "https://example.com")
	if err != nil {
		t.Fatalf("ParseBurp: %v", err)
	}
	if len(fs) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(fs))
	}
	if fs[0].Severity != models.SeverityHigh || fs[1].Severity != models.SeverityInfo {
		t.Fatalf("severity mapping wrong: %s, %s", fs[0].Severity, fs[1].Severity)
	}
	if fs[0].URL != "https://example.com/search?q=1" {
		t.Fatalf("burp URL wrong: %q", fs[0].URL)
	}
}

func TestParseBurpRejectsBadXML(t *testing.T) {
	if _, err := ParseBurp([]byte("<broken"), "https://example.com"); err == nil {
		t.Fatal("expected error for malformed XML")
	}
}

func TestParseZAPFixture(t *testing.T) {
	fs, err := ParseZAP(fixture(t, "zap-sample.json"), "https://example.com")
	if err != nil {
		t.Fatalf("ParseZAP: %v", err)
	}
	if len(fs) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(fs))
	}
	if fs[0].Severity != models.SeverityLow || fs[1].Severity != models.SeverityHigh {
		t.Fatalf("risk mapping wrong: %s, %s", fs[0].Severity, fs[1].Severity)
	}
	if fs[0].CWE != "CWE-693" || fs[1].CWE != "CWE-89" {
		t.Fatalf("cwe normalization wrong: %q, %q", fs[0].CWE, fs[1].CWE)
	}
}

func TestParseHARFixture(t *testing.T) {
	fs, eps, err := ParseHAR(fixture(t, "har-sample.json"), "https://example.com")
	if err != nil {
		t.Fatalf("ParseHAR: %v", err)
	}
	if len(eps) != 3 {
		t.Fatalf("expected 3 endpoints, got %d", len(eps))
	}
	found5xx := false
	for _, f := range fs {
		if f.Severity == models.SeverityLow {
			found5xx = true
		}
	}
	if !found5xx {
		t.Fatal("expected a Low 5xx finding")
	}
	if fs[len(fs)-1].ID != "har-summary" || fs[len(fs)-1].Severity != models.SeverityInfo {
		t.Fatalf("last finding must be info summary, got %+v", fs[len(fs)-1])
	}
}
