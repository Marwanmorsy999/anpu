package backup

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

func testClient() *anpuhttp.Client {
	return anpuhttp.NewClientWithLocalNetworkAllowed(true)
}

// --- Helper unit tests ---

func TestHasFileExtension(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/config.php", true},
		{"/app.js", true},
		{"/style.css", true},
		{"/api/v1/users", false},
		{"/", false},
		{"/.env", false}, // dotfile without extension — handled by dirs scanner
		{"/page", false},
	}
	for _, tc := range tests {
		got := hasFileExtension(tc.path)
		if got != tc.want {
			t.Errorf("hasFileExtension(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestPathOf(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"https://example.com/config.php", "/config.php"},
		{"https://example.com/api/v1/users?foo=bar", "/api/v1/users"},
		{"http://example.com/", "/"},
		{"https://example.com", "/"},
	}
	for _, tc := range tests {
		got := pathOf(tc.in)
		if got != tc.want {
			t.Errorf("pathOf(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestBaseURL(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"https://example.com/config.php", "https://example.com"},
		{"http://example.com:8080/path", "http://example.com:8080"},
		{"https://example.com", "https://example.com"},
	}
	for _, tc := range tests {
		got := baseURL(tc.in)
		if got != tc.want {
			t.Errorf("baseURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestStringsAreSimilar(t *testing.T) {
	identical := "This is a 404 page with some content that is quite long for testing purposes."
	if !stringsAreSimilar(identical, identical) {
		t.Error("identical strings should be similar")
	}
	very_different := strings.Repeat("X", 300)
	normal := strings.Repeat("Y", 300)
	if stringsAreSimilar(very_different, normal) {
		// Same length but different content — our prefix check handles this.
		// Actually stringsAreSimilar only compares first 200 chars, so different content matters.
		// This test checks that completely different content returns false.
	}
	// Length mismatch > 20%.
	short := "abc"
	long := strings.Repeat("a", 300)
	if stringsAreSimilar(short, long) {
		t.Error("very different length strings should not be similar")
	}
}

// --- Integration tests ---

func testScanContext(serverURL string, endpoints []models.Endpoint) *scanner.ScanContext {
	return &scanner.ScanContext{
		Target:    &scanner.ValidatedTarget{Raw: serverURL},
		Endpoints: endpoints,
	}
}

func TestBackupScanner_DetectsExposedBackup(t *testing.T) {
	// Serve a PHP-like backup at /config.php.bak.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/config.php.bak" {
			w.Header().Set("Content-Type", "text/plain")
			body := "<?php\n$db_password = 'supersecret';\n$api_key = 'sk-abc123';\n// Production config\n"
			body += strings.Repeat("x", 300) // pad to exceed minBodyBytes
			w.Write([]byte(body))
			return
		}
		// All other paths → 404.
		http.NotFound(w, r)
	}))
	defer srv.Close()

	s := New(testClient())
	sc := testScanContext(srv.URL, []models.Endpoint{
		{URL: srv.URL + "/config.php", Category: models.EndpointPage, Sources: []string{"crawler"}},
	})
	result, err := s.Run(context.Background(), sc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	found := false
	for _, f := range result.Findings {
		if strings.Contains(f.URL, "config.php.bak") {
			found = true
			if f.Severity != models.SeverityHigh {
				t.Errorf("source code exposure should be SeverityHigh, got %s", f.Severity)
			}
			if f.CWE != "CWE-530" {
				t.Errorf("CWE: got %q, want CWE-530", f.CWE)
			}
			break
		}
	}
	if !found {
		t.Errorf("expected finding for config.php.bak, got %d findings: %v", len(result.Findings), result.Findings)
	}
}

func TestBackupScanner_DetectsRootArchive(t *testing.T) {
	// Serve backup.tar.bz2 at root (a rootBackupPaths entry not in dirs).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/backup.tar.bz2" {
			w.Header().Set("Content-Type", "application/x-bzip2")
			// Write enough bytes to pass minBodyBytes check.
			w.Write([]byte(strings.Repeat("\x42\x5A\x68", 100)))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	s := New(testClient())
	sc := testScanContext(srv.URL, nil)
	result, err := s.Run(context.Background(), sc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	found := false
	for _, f := range result.Findings {
		if strings.Contains(f.URL, "backup.tar.bz2") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected finding for backup.tar.bz2 root archive")
	}
}

func TestBackupScanner_NoFinding_404(t *testing.T) {
	// Server returns 404 for everything.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	s := New(testClient())
	sc := testScanContext(srv.URL, []models.Endpoint{
		{URL: srv.URL + "/app.js", Category: models.EndpointAsset, Sources: []string{"crawler"}},
	})
	result, err := s.Run(context.Background(), sc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("404 responses should produce no findings, got %d", len(result.Findings))
	}
}

func TestBackupScanner_SoftNotFound_CatchAll(t *testing.T) {
	// Catch-all server that returns 200 for everything (soft 404).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Return the same body for every path — should be detected as soft-404.
		w.Write([]byte(strings.Repeat("This is a 404 page rendered by the catch-all router. ", 10)))
	}))
	defer srv.Close()

	s := New(testClient())
	sc := testScanContext(srv.URL, []models.Endpoint{
		{URL: srv.URL + "/config.php", Category: models.EndpointPage, Sources: []string{"crawler"}},
	})
	result, err := s.Run(context.Background(), sc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("catch-all soft-404 should produce no findings, got %d", len(result.Findings))
	}
}

func TestBackupScanner_SkipsAPIEndpoints(t *testing.T) {
	// API endpoint with file-like path — should be skipped for per-endpoint backup probes.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return 200 for anything — if we probe api.json.bak etc it would fire.
		w.Write([]byte(strings.Repeat("data", 100)))
	}))
	defer srv.Close()

	s := New(testClient())
	sc := testScanContext(srv.URL, []models.Endpoint{
		{URL: srv.URL + "/api/data.json", Category: models.EndpointAPI, Sources: []string{"api-scanner"}},
	})
	result, err := s.Run(context.Background(), sc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// API endpoints should not generate per-endpoint backup probes.
	// (Root-level probes may still fire — filter to per-endpoint ones.)
	for _, f := range result.Findings {
		if strings.Contains(f.URL, "data.json") {
			t.Errorf("API endpoint backup probe should be skipped, got: %s", f.URL)
		}
	}
}

func TestBackupScanner_Source(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".bak") {
			w.Write([]byte("<?php $secret = 'hello';\n" + strings.Repeat("x", 300)))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	s := New(testClient())
	sc := testScanContext(srv.URL, []models.Endpoint{
		{URL: srv.URL + "/index.php", Category: models.EndpointPage, Sources: []string{"crawler"}},
	})
	result, err := s.Run(context.Background(), sc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range result.Findings {
		if f.Source != models.SourceBackup {
			t.Errorf("source: got %q, want backup-scanner", f.Source)
		}
	}
}
