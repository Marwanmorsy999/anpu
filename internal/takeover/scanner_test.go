package takeover

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// --- unit tests ---

func TestProviderTable_NoDuplicateNames(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range providerTable {
		if seen[p.Name] {
			t.Errorf("duplicate provider name in table: %q", p.Name)
		}
		seen[p.Name] = true
	}
}

func TestProviderTable_AllHaveFingerprints(t *testing.T) {
	for _, p := range providerTable {
		if len(p.BodyFingerprints) == 0 {
			t.Errorf("provider %q has no body fingerprints", p.Name)
		}
		if len(p.CNAMESuffix) == 0 {
			t.Errorf("provider %q has no CNAME suffixes", p.Name)
		}
	}
}

func TestFetchBody_HTTPSFallback(t *testing.T) {
	// httptest serves plain HTTP — fetchBody should succeed via http fallback.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("There isn't a GitHub Pages site here."))
	}))
	defer srv.Close()

	// Strip scheme to get just host:port
	host := strings.TrimPrefix(srv.URL, "http://")
	s := New()
	// Override client to allow plain HTTP directly.
	s.client = srv.Client()
	body, warn := s.fetchBody(context.Background(), host)
	// warn may be non-empty because HTTPS fails and falls back; what matters
	// is body has content.
	_ = warn
	if !strings.Contains(body, "GitHub Pages") {
		t.Errorf("fetchBody returned %q, want GitHub Pages fingerprint", body)
	}
}

// --- integration-style check() test using a mock HTTP server ---

type mockResolver struct {
	cname string
}

func (m *mockResolver) LookupCNAME(_ context.Context, _ string) (string, error) {
	return m.cname, nil
}

// check uses s.resolver which is a *net.Resolver — we can't swap that in
// tests without an interface. Instead, test the body-matching logic directly
// via a table check that mirrors check()'s fingerprint scan.
func TestBodyFingerprintMatching(t *testing.T) {
	cases := []struct {
		provider string
		body     string
		wantHit  bool
	}{
		{"GitHub Pages", "There isn't a GitHub Pages site here.", true},
		{"GitHub Pages", "Normal page content", false},
		{"Heroku", "No such app", true},
		{"AWS S3", "NoSuchBucket", true},
		{"Netlify", "Not Found - Request ID", true},
		{"Azure", "404 Web Site not found", true},
		{"Fastly", "Fastly error: unknown domain", true},
		{"Shopify", "Sorry, this shop is currently unavailable.", true},
		{"Zendesk", "Help Center Closed", true},
		{"Ghost", "The thing you were looking for is no longer here", true},
	}
	for _, tc := range cases {
		var sig *providerSig
		for i := range providerTable {
			if providerTable[i].Name == tc.provider {
				sig = &providerTable[i]
				break
			}
		}
		if sig == nil {
			t.Errorf("provider %q not in table", tc.provider)
			continue
		}
		bodyLower := strings.ToLower(tc.body)
		hit := false
		for _, fp := range sig.BodyFingerprints {
			if strings.Contains(bodyLower, strings.ToLower(fp)) {
				hit = true
				break
			}
		}
		if hit != tc.wantHit {
			t.Errorf("provider %q body %q: hit=%v want %v", tc.provider, tc.body, hit, tc.wantHit)
		}
	}
}

func TestRun_EmptySubdomains(t *testing.T) {
	s := New()
	sc := &scanner.ScanContext{
		Target: mustValidateTarget(t, "https://example.com"),
		Config: models.ScanConfig{Profile: models.ProfileSafe},
	}
	result, err := s.Run(context.Background(), sc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected no findings for empty subdomains, got %d", len(result.Findings))
	}
}

func mustValidateTarget(t *testing.T, raw string) *scanner.ValidatedTarget {
	t.Helper()
	vt, err := scanner.ValidateTarget(raw)
	if err != nil {
		t.Fatalf("ValidateTarget(%q): %v", raw, err)
	}
	return vt
}
