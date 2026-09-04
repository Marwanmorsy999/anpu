package sri

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// --- Unit tests for helpers ---

func TestHostOf(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"https://cdn.example.com/lib.js", "https://cdn.example.com"},
		{"https://cdn.example.com/lib.js?v=1", "https://cdn.example.com"},
		{"http://example.com/page", "http://example.com"},
		{"https://example.com", "https://example.com"},
		{"/relative/path", ""},
		{"data:text/javascript,alert(1)", ""},
	}
	for _, tc := range tests {
		got := hostOf(tc.in)
		if got != tc.want {
			t.Errorf("hostOf(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestIsCrossOrigin_CrossOrigin(t *testing.T) {
	if !isCrossOrigin("https://cdn.jquery.com/jquery.min.js", "https://example.com") {
		t.Error("CDN URL should be cross-origin")
	}
}

func TestIsCrossOrigin_SameOrigin(t *testing.T) {
	if isCrossOrigin("https://example.com/js/app.js", "https://example.com") {
		t.Error("same-host URL should not be cross-origin")
	}
}

func TestIsCrossOrigin_RelativeURL(t *testing.T) {
	if isCrossOrigin("/js/app.js", "https://example.com") {
		t.Error("relative URL should not be cross-origin")
	}
}

func TestIsCrossOrigin_DataURI(t *testing.T) {
	if isCrossOrigin("data:text/javascript,alert(1)", "https://example.com") {
		t.Error("data: URI should not be cross-origin")
	}
}

// --- extractMissingIntegrity unit tests ---

func TestExtractMissingIntegrity_ScriptNoIntegrity(t *testing.T) {
	body := `<html><head>
		<script src="https://cdn.jsdelivr.net/npm/jquery/jquery.min.js"></script>
	</head></html>`
	refs := extractMissingIntegrity(body, "https://example.com")
	if len(refs) != 1 {
		t.Fatalf("expected 1 ref, got %d", len(refs))
	}
	if refs[0].Kind != "script" {
		t.Errorf("kind: got %q, want script", refs[0].Kind)
	}
	if !strings.Contains(refs[0].URL, "jquery") {
		t.Errorf("URL should contain jquery, got %q", refs[0].URL)
	}
}

func TestExtractMissingIntegrity_ScriptWithIntegrity(t *testing.T) {
	body := `<script src="https://cdn.jsdelivr.net/npm/jquery/jquery.min.js"
		integrity="sha384-abc123" crossorigin="anonymous"></script>`
	refs := extractMissingIntegrity(body, "https://example.com")
	if len(refs) != 0 {
		t.Errorf("script with integrity= should produce no refs, got %d", len(refs))
	}
}

func TestExtractMissingIntegrity_StylesheetNoIntegrity(t *testing.T) {
	body := `<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Roboto">`
	refs := extractMissingIntegrity(body, "https://example.com")
	if len(refs) != 1 {
		t.Fatalf("expected 1 ref, got %d", len(refs))
	}
	if refs[0].Kind != "stylesheet" {
		t.Errorf("kind: got %q, want stylesheet", refs[0].Kind)
	}
}

func TestExtractMissingIntegrity_StylesheetWithIntegrity(t *testing.T) {
	body := `<link rel="stylesheet" href="https://fonts.googleapis.com/css"
		integrity="sha384-xyz" crossorigin="anonymous">`
	refs := extractMissingIntegrity(body, "https://example.com")
	if len(refs) != 0 {
		t.Errorf("stylesheet with integrity= should produce no refs, got %d", len(refs))
	}
}

func TestExtractMissingIntegrity_SameOriginSkipped(t *testing.T) {
	body := `<script src="https://example.com/js/app.js"></script>`
	refs := extractMissingIntegrity(body, "https://example.com")
	if len(refs) != 0 {
		t.Errorf("same-origin script should be skipped, got %d refs", len(refs))
	}
}

func TestExtractMissingIntegrity_RelativeURLSkipped(t *testing.T) {
	body := `<script src="/js/bundle.js"></script>`
	refs := extractMissingIntegrity(body, "https://example.com")
	if len(refs) != 0 {
		t.Errorf("relative URL should be skipped, got %d refs", len(refs))
	}
}

func TestExtractMissingIntegrity_MultipleAssets(t *testing.T) {
	body := `<html><head>
		<link rel="stylesheet" href="https://cdn.example.net/style.css">
		<script src="https://cdn.jsdelivr.net/lib.js"></script>
		<script src="https://example.com/local.js"></script>
	</head></html>`
	refs := extractMissingIntegrity(body, "https://example.com")
	if len(refs) != 2 {
		t.Errorf("expected 2 cross-origin refs (1 stylesheet + 1 script), got %d", len(refs))
	}
}

func TestExtractMissingIntegrity_LinkHrefBeforeRel(t *testing.T) {
	// Test the alternate permutation: href before rel
	body := `<link href="https://cdn.example.net/style.css" rel="stylesheet">`
	refs := extractMissingIntegrity(body, "https://example.com")
	if len(refs) != 1 {
		t.Fatalf("href-before-rel permutation: expected 1 ref, got %d", len(refs))
	}
	if refs[0].Kind != "stylesheet" {
		t.Errorf("kind: got %q, want stylesheet", refs[0].Kind)
	}
}

// --- Integration tests via Scanner.Run ---

func testSRIClient() *anpuhttp.Client {
	return anpuhttp.NewClientWithLocalNetworkAllowed(true)
}

func testSRIContext(serverURL string) *scanner.ScanContext {
	return &scanner.ScanContext{
		Target: &scanner.ValidatedTarget{Raw: serverURL},
		Endpoints: []models.Endpoint{
			{
				URL:      serverURL + "/",
				Category: models.EndpointPage,
				Sources:  []string{"crawler"},
			},
		},
	}
}

func TestSRIScanner_FindsMissingIntegrity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head>
			<script src="https://cdn.jsdelivr.net/npm/jquery/jquery.min.js"></script>
			<link rel="stylesheet" href="https://fonts.googleapis.com/css">
		</head><body>Hello</body></html>`))
	}))
	defer srv.Close()

	s := New(testSRIClient())
	sc := testSRIContext(srv.URL)
	result, err := s.Run(context.Background(), sc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.Findings) != 2 {
		t.Errorf("expected 2 findings (1 script + 1 stylesheet), got %d", len(result.Findings))
	}
	for _, f := range result.Findings {
		if f.CWE != "CWE-829" {
			t.Errorf("CWE: got %q, want CWE-829", f.CWE)
		}
		if f.Severity != models.SeverityLow {
			t.Errorf("severity: got %q, want low", f.Severity)
		}
		if f.Confidence != models.ConfidenceHigh {
			t.Errorf("confidence: got %q, want high", f.Confidence)
		}
		if f.Source != models.SourceSRI {
			t.Errorf("source: got %q, want sri-scanner", f.Source)
		}
	}
}

func TestSRIScanner_NoFindingsWhenIntegrityPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head>
			<script src="https://cdn.jsdelivr.net/npm/jquery/jquery.min.js"
				integrity="sha384-abc123" crossorigin="anonymous"></script>
		</head></html>`))
	}))
	defer srv.Close()

	s := New(testSRIClient())
	sc := testSRIContext(srv.URL)
	result, err := s.Run(context.Background(), sc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings when integrity present, got %d", len(result.Findings))
	}
}

func TestSRIScanner_DeduplicatesAcrossPages(t *testing.T) {
	// Two pages both reference the same CDN script — should produce 1 finding.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<script src="https://cdn.jsdelivr.net/npm/jquery/jquery.min.js"></script>`))
	}))
	defer srv.Close()

	s := New(testSRIClient())
	sc := &scanner.ScanContext{
		Target: &scanner.ValidatedTarget{Raw: srv.URL},
		Endpoints: []models.Endpoint{
			{URL: srv.URL + "/page1", Category: models.EndpointPage, Sources: []string{"crawler"}},
			{URL: srv.URL + "/page2", Category: models.EndpointPage, Sources: []string{"crawler"}},
		},
	}
	result, err := s.Run(context.Background(), sc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Errorf("duplicate CDN ref should produce 1 deduplicated finding, got %d", len(result.Findings))
	}
}

func TestSRIScanner_SkipsNonHTMLEndpoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"script":"https://cdn.example.com/lib.js"}`))
	}))
	defer srv.Close()

	s := New(testSRIClient())
	sc := testSRIContext(srv.URL)
	sc.Endpoints[0].Category = models.EndpointAPI
	result, err := s.Run(context.Background(), sc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("non-HTML API endpoint should produce no findings, got %d", len(result.Findings))
	}
}

func TestSRIScanner_SkipsSameOriginAssets(t *testing.T) {
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Same-origin script — no SRI needed
		body := `<script src="` + srvURL + `/js/app.js"></script>`
		w.Write([]byte(body))
	}))
	defer srv.Close()
	srvURL = srv.URL

	s := New(testSRIClient())
	sc := testSRIContext(srv.URL)
	result, err := s.Run(context.Background(), sc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("same-origin assets should produce no findings, got %d", len(result.Findings))
	}
}
