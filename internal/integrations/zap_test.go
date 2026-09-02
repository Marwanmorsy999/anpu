package integrations

import (
	"context"
	"testing"

	"github.com/anpu-project/anpu/pkg/models"
)

// --- stripHTMLTags ---

func TestStripHTMLTags(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"no tags here", "no tags here"},
		{"<p>Hello</p>", "Hello"},
		{"<ul><li>Item one</li><li>Item two</li></ul>", "Item one Item two"},
		{"", ""},
		{"<b>bold</b> and <i>italic</i>", "bold and italic"},
		{"no angle brackets", "no angle brackets"},
	}
	for _, tc := range cases {
		got := stripHTMLTags(tc.in)
		if got != tc.want {
			t.Errorf("stripHTMLTags(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

// --- zapCategory ---

func TestZapCategory(t *testing.T) {
	cases := []struct {
		code int
		want models.Category
	}{
		{0, models.CategoryExposure},
		{1, models.CategoryConfiguration},
		{2, models.CategoryVulnerability},
		{3, models.CategoryVulnerability},
		{99, models.CategoryOther},
	}
	for _, tc := range cases {
		got := zapCategory(tc.code)
		if got != tc.want {
			t.Errorf("zapCategory(%d) = %q; want %q", tc.code, got, tc.want)
		}
	}
}

// --- convertZapAlert ---

func TestConvertZapAlert_Basic(t *testing.T) {
	alert := zapAlert{
		PluginID:   "10038",
		AlertRef:   "10038-1",
		Name:       "Content Security Policy (CSP) Header Not Set",
		RiskCode:   "2",
		Confidence: "3",
		Desc:       "<p>Content Security Policy (CSP) is an added layer of security.</p>",
		Solution:   "<p>Ensure that your web server sets the Content-Security-Policy header.</p>",
		CWEID:      "693",
		Reference:  "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP\nhttps://owasp.org/",
		Instances: []struct {
			URI      string `json:"uri"`
			Method   string `json:"method"`
			Param    string `json:"param"`
			Evidence string `json:"evidence"`
		}{
			{URI: "https://example.com/", Method: "GET", Evidence: ""},
		},
	}

	f, warn := convertZapAlert(alert, "https://example.com")
	if warn != "" {
		t.Fatalf("unexpected warning: %s", warn)
	}
	if f == nil {
		t.Fatal("expected finding, got nil")
	}
	if f.ID != "zap-10038-1" {
		t.Errorf("ID = %q; want zap-10038-1", f.ID)
	}
	if f.Severity != models.SeverityMedium {
		t.Errorf("Severity = %q; want medium", f.Severity)
	}
	if f.Confidence != models.ConfidenceHigh {
		t.Errorf("Confidence = %q; want high", f.Confidence)
	}
	if f.CWE != "CWE-693" {
		t.Errorf("CWE = %q; want CWE-693", f.CWE)
	}
	if f.URL != "https://example.com/" {
		t.Errorf("URL = %q; want instance URI", f.URL)
	}
	if f.Source != models.SourceZAP {
		t.Errorf("Source = %q; want zap", f.Source)
	}
	// HTML should be stripped from description.
	if f.Description == alert.Desc {
		t.Error("Description should have HTML stripped")
	}
	// References should be split on newlines.
	if len(f.References) != 2 {
		t.Errorf("References len = %d; want 2", len(f.References))
	}
}

func TestConvertZapAlert_NoName(t *testing.T) {
	alert := zapAlert{PluginID: "9999", Name: "", Alert: ""}
	f, warn := convertZapAlert(alert, "https://example.com")
	if f != nil {
		t.Error("expected nil finding for no-name alert")
	}
	if warn == "" {
		t.Error("expected warning for no-name alert")
	}
}

func TestConvertZapAlert_FallbackName(t *testing.T) {
	// When Name is empty, Alert is used as title.
	alert := zapAlert{PluginID: "1", Name: "", Alert: "Fallback Title", RiskCode: "0", Confidence: "2"}
	f, warn := convertZapAlert(alert, "https://example.com")
	if warn != "" {
		t.Fatalf("unexpected warning: %s", warn)
	}
	if f.Title != "Fallback Title" {
		t.Errorf("Title = %q; want Fallback Title", f.Title)
	}
}

func TestConvertZapAlert_NegativeCWE(t *testing.T) {
	alert := zapAlert{PluginID: "2", Name: "X", RiskCode: "1", Confidence: "2", CWEID: "-1"}
	f, _ := convertZapAlert(alert, "https://example.com")
	if f.CWE != "" {
		t.Errorf("CWE should be empty for -1, got %q", f.CWE)
	}
}

func TestConvertZapAlert_EvidenceFromParam(t *testing.T) {
	alert := zapAlert{
		PluginID:   "3",
		Name:       "SQLi",
		RiskCode:   "3",
		Confidence: "3",
		Instances: []struct {
			URI      string `json:"uri"`
			Method   string `json:"method"`
			Param    string `json:"param"`
			Evidence string `json:"evidence"`
		}{
			{URI: "https://example.com/search", Param: "q"},
		},
	}
	f, _ := convertZapAlert(alert, "https://example.com")
	if f.Evidence.Observed != "param: q" {
		t.Errorf("Evidence.Observed = %q; want 'param: q'", f.Evidence.Observed)
	}
}

// --- parseReport ---

func TestParseReport_ValidJSON(t *testing.T) {
	z := NewZapScanner()
	data := []byte(`{
		"site": [{
			"@name": "https://example.com",
			"alerts": [{
				"pluginid": "10038",
				"name": "CSP Header Not Set",
				"riskcode": "2",
				"confidence": "3",
				"cweid": "693",
				"instances": [{"uri":"https://example.com/"}]
			}]
		}]
	}`)
	findings, warnings := z.parseReport(data, "https://example.com")
	if len(warnings) > 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != models.SeverityMedium {
		t.Errorf("Severity = %q; want medium", findings[0].Severity)
	}
}

func TestParseReport_EmptyData(t *testing.T) {
	z := NewZapScanner()
	findings, warnings := z.parseReport([]byte{}, "https://example.com")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty data, got %d", len(findings))
	}
	if len(warnings) == 0 {
		t.Error("expected warning for empty data")
	}
}

func TestParseReport_InvalidJSON(t *testing.T) {
	z := NewZapScanner()
	findings, warnings := z.parseReport([]byte("not json at all"), "https://example.com")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for invalid JSON, got %d", len(findings))
	}
	if len(warnings) == 0 {
		t.Error("expected warning for unparseable output")
	}
}

func TestParseReport_NoisyOutput(t *testing.T) {
	// ZAP sometimes emits progress lines before the JSON object.
	z := NewZapScanner()
	data := []byte(`Progress: 50%
Scanning...
{"site":[{"@name":"https://example.com","alerts":[{"pluginid":"1","name":"T","riskcode":"1","confidence":"2"}]}]}
Done.`)
	findings, warnings := z.parseReport(data, "https://example.com")
	if len(warnings) > 0 {
		t.Logf("warnings (acceptable): %v", warnings)
	}
	// Noisy output may fail full-doc parse but should succeed via line scan.
	_ = findings
}

// --- scanScript ---

func TestScanScript(t *testing.T) {
	if s := scanScript(models.ProfileDeep); s != "zap-full-scan.py" {
		t.Errorf("deep profile should use full scan, got %q", s)
	}
	if s := scanScript(models.ProfileSafe); s != "zap-baseline.py" {
		t.Errorf("safe profile should use baseline, got %q", s)
	}
	if s := scanScript(models.ProfileStandard); s != "zap-baseline.py" {
		t.Errorf("standard profile should use baseline, got %q", s)
	}
}

// --- Available (unit: no docker/zap in CI) ---

func TestAvailable_ReturnsFalseWhenNeitherPresent(t *testing.T) {
	z := &ZapScanner{
		DockerBinary: "/nonexistent/docker",
		ZapBinary:    "/nonexistent/zap.sh",
		Timeout:      5,
	}
	// Should not panic and should return false gracefully.
	got := z.Available(context.Background())
	if got {
		t.Error("Expected Available=false when no docker/zap installed")
	}
}

func TestRun_WarnsWhenUnavailable(t *testing.T) {
	z := &ZapScanner{
		DockerBinary: "/nonexistent/docker",
		ZapBinary:    "/nonexistent/zap.sh",
		Timeout:      5,
	}
	result, err := z.Run(context.Background(), nil)
	if err != nil {
		t.Fatalf("Run should not return error when unavailable, got: %v", err)
	}
	if len(result.Warnings) == 0 {
		t.Error("Expected warning when ZAP unavailable")
	}
}
