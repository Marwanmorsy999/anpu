package endpoints

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

func init() {
	scanner.AllowLocalNetwork = true
}

const testHTML = `<html><body>
<a href="/about">About</a>
<a href="/admin/dashboard">Admin</a>
<a href="https://other-domain.example/x">External</a>
<a href="mailto:test@example.com">Email</a>
<form action="/api/login" method="POST"></form>
<script src="/static/app.js"></script>
<script>fetch("/api/users/list")</script>
</body></html>`

func TestDiscovery_ExtractsAndCategorizesEndpoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(testHTML))
	}))
	defer srv.Close()

	vt, err := scanner.ValidateTarget(srv.URL)
	if err != nil {
		t.Fatalf("validating target: %v", err)
	}

	d := New(anpuhttp.NewClientWithLocalNetworkAllowed(true))
	res, err := d.Run(context.Background(), &scanner.ScanContext{Target: vt, Config: models.ScanConfig{Profile: models.ProfileSafe}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ep, ok := findBySuffix(res.Endpoints, "/admin/dashboard"); !ok || ep.Category != models.EndpointAdminLike {
		t.Errorf("expected /admin/dashboard to be categorized admin-like, got %+v (found=%v)", ep, ok)
	}
	if ep, ok := findBySuffix(res.Endpoints, "/api/login"); !ok || ep.Category != models.EndpointAPI {
		t.Errorf("expected /api/login to be categorized api, got %+v (found=%v)", ep, ok)
	}
	if ep, ok := findBySuffix(res.Endpoints, "/static/app.js"); !ok || ep.Category != models.EndpointAsset {
		t.Errorf("expected /static/app.js to be categorized asset, got %+v (found=%v)", ep, ok)
	}
	if _, ok := findBySuffix(res.Endpoints, "other-domain.example/x"); ok {
		t.Error("did not expect an external-domain link to be included as an endpoint")
	}
	for _, e := range res.Endpoints {
		if e.URL == "mailto:test@example.com" {
			t.Error("mailto: links must not be treated as endpoints")
		}
	}
}

func TestDiscovery_DeduplicatesAndMergesSources(t *testing.T) {
	html := `<a href="/dup">A</a><script>fetch("/dup")</script>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(html))
	}))
	defer srv.Close()

	vt, err := scanner.ValidateTarget(srv.URL)
	if err != nil {
		t.Fatalf("validating target: %v", err)
	}
	d := New(anpuhttp.NewClientWithLocalNetworkAllowed(true))
	res, err := d.Run(context.Background(), &scanner.ScanContext{Target: vt, Config: models.ScanConfig{Profile: models.ProfileSafe}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	count := 0
	for _, e := range res.Endpoints {
		if endsWith(e.URL, "/dup") {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected /dup to appear exactly once after dedup, appeared %d times", count)
	}
}

// TestDiscovery_AuthenticatedPassExpandsSurface verifies that the two-pass
// crawl finds gated endpoints and produces the expected finding.
func TestDiscovery_AuthenticatedPassExpandsSurface(t *testing.T) {
	const secretToken = "test-bearer-token"

	// The test server exposes /public to everyone and /gated only to
	// requests that carry the correct Authorization header.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		body := `<a href="/public">public</a>`
		if r.Header.Get("Authorization") == "Bearer "+secretToken {
			body += `<a href="/gated">gated</a>`
		}
		w.Write([]byte(body))
	})
	mux.HandleFunc("/public", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<p>public page</p>"))
	})
	mux.HandleFunc("/gated", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secretToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<p>secret page</p>"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	vt, err := scanner.ValidateTarget(srv.URL)
	if err != nil {
		t.Fatalf("validating target: %v", err)
	}

	authCtx := models.AuthContext{
		Method:      models.AuthMethodBearer,
		BearerToken: secretToken,
		Role:        "tester",
	}

	d := New(anpuhttp.NewClientWithLocalNetworkAllowed(true))
	res, err := d.Run(context.Background(), &scanner.ScanContext{
		Target: vt,
		Config: models.ScanConfig{Profile: models.ProfileStandard},
		Auth:   authCtx,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// /gated must appear in the merged endpoint list.
	if _, ok := findBySuffix(res.Endpoints, "/gated"); !ok {
		t.Error("expected /gated to be included in the merged endpoint surface")
	}

	// /gated must carry the "crawler-authenticated" source tag.
	if ep, ok := findBySuffix(res.Endpoints, "/gated"); ok {
		if !hasSource(ep, "crawler-authenticated") {
			t.Errorf("/gated endpoint missing 'crawler-authenticated' source tag, got: %v", ep.Sources)
		}
	}

	// The gated-surface finding must be present.
	var gatedFinding *models.Finding
	for i := range res.Findings {
		if res.Findings[i].ID == "endpoints-authenticated-surface-expanded" {
			gatedFinding = &res.Findings[i]
			break
		}
	}
	if gatedFinding == nil {
		t.Fatal("expected 'endpoints-authenticated-surface-expanded' finding to be emitted")
	}
	if !strings.Contains(gatedFinding.Description, "tester") {
		t.Errorf("gated finding description should mention the auth role, got: %s", gatedFinding.Description)
	}
	if gatedFinding.Confidence != models.ConfidenceMedium {
		t.Errorf("expected ConfidenceMedium, got %q", gatedFinding.Confidence)
	}
}

// TestDiscovery_AuthenticatedPassNoNewEndpoints verifies that no gated
// finding is emitted when authenticated and anonymous surfaces are identical.
func TestDiscovery_AuthenticatedPassNoNewEndpoints(t *testing.T) {
	// Server exposes the same pages regardless of auth headers.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<a href="/same">same</a>`))
	}))
	defer srv.Close()

	vt, err := scanner.ValidateTarget(srv.URL)
	if err != nil {
		t.Fatalf("validating target: %v", err)
	}

	authCtx := models.AuthContext{
		Method:      models.AuthMethodBearer,
		BearerToken: "any-token",
		Role:        "user",
	}

	d := New(anpuhttp.NewClientWithLocalNetworkAllowed(true))
	res, err := d.Run(context.Background(), &scanner.ScanContext{
		Target: vt,
		Config: models.ScanConfig{Profile: models.ProfileStandard},
		Auth:   authCtx,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range res.Findings {
		if f.ID == "endpoints-authenticated-surface-expanded" {
			t.Error("did not expect gated-surface finding when authenticated and anonymous surfaces are identical")
		}
	}
}

// TestDiscovery_AnonymousScanSkipsAuthPass verifies no second crawl runs
// and no gated finding is emitted when no auth context is configured.
func TestDiscovery_AnonymousScanSkipsAuthPass(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<a href="/page">page</a>`))
	}))
	defer srv.Close()

	vt, err := scanner.ValidateTarget(srv.URL)
	if err != nil {
		t.Fatalf("validating target: %v", err)
	}

	d := New(anpuhttp.NewClientWithLocalNetworkAllowed(true))
	// No Auth configured — anonymous scan.
	res, err := d.Run(context.Background(), &scanner.ScanContext{
		Target: vt,
		Config: models.ScanConfig{Profile: models.ProfileStandard},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range res.Findings {
		if f.ID == "endpoints-authenticated-surface-expanded" {
			t.Error("did not expect gated-surface finding during an anonymous scan")
		}
	}
	// Profile=standard, MaxPages=25. Safe profile would only call /. Standard
	// crawls up to 25 pages. We just verify no duplicate-pass inflation.
	// The important assertion: crawler-authenticated source should not appear.
	for _, ep := range res.Endpoints {
		if hasSource(ep, "crawler-authenticated") {
			t.Errorf("anonymous scan produced an endpoint with 'crawler-authenticated' source: %s", ep.URL)
		}
	}
}

// TestGatedEndpoints unit-tests the diff logic directly.
func TestGatedEndpoints(t *testing.T) {
	anon := []models.Endpoint{
		{URL: "http://example.com/public"},
		{URL: "http://example.com/shared"},
	}
	auth := []models.Endpoint{
		{URL: "http://example.com/shared"},
		{URL: "http://example.com/gated1"},
		{URL: "http://example.com/gated2"},
	}

	gated := gatedEndpoints(anon, auth)
	if len(gated) != 2 {
		t.Fatalf("expected 2 gated endpoints, got %d: %+v", len(gated), gated)
	}
	gatedURLs := map[string]bool{}
	for _, ep := range gated {
		gatedURLs[ep.URL] = true
	}
	if !gatedURLs["http://example.com/gated1"] {
		t.Error("expected gated1 in gated set")
	}
	if !gatedURLs["http://example.com/gated2"] {
		t.Error("expected gated2 in gated set")
	}
	if gatedURLs["http://example.com/shared"] {
		t.Error("shared endpoint should not be in gated set")
	}
}

// TestMergeEndpoints unit-tests the merge logic.
func TestMergeEndpoints(t *testing.T) {
	anon := []models.Endpoint{
		{URL: "http://example.com/a", Sources: []string{"crawler"}},
		{URL: "http://example.com/b", Sources: []string{"crawler"}},
	}
	auth := []models.Endpoint{
		{URL: "http://example.com/b", Sources: []string{"crawler"}}, // overlap
		{URL: "http://example.com/c", Sources: []string{"crawler"}}, // auth-only
	}

	merged := mergeEndpoints(anon, auth)

	// Total unique URLs: a, b, c.
	if len(merged) != 3 {
		t.Fatalf("expected 3 merged endpoints, got %d", len(merged))
	}

	// /b should have both "crawler" and "crawler-authenticated".
	bEp, ok := findInSlice(merged, "http://example.com/b")
	if !ok {
		t.Fatal("/b missing from merged set")
	}
	if !hasSource(bEp, "crawler-authenticated") {
		t.Errorf("/b should have 'crawler-authenticated' source, got: %v", bEp.Sources)
	}

	// /c should have "crawler-authenticated".
	cEp, ok := findInSlice(merged, "http://example.com/c")
	if !ok {
		t.Fatal("/c missing from merged set")
	}
	if !hasSource(cEp, "crawler-authenticated") {
		t.Errorf("/c should have 'crawler-authenticated' source, got: %v", cEp.Sources)
	}

	// /a should only have "crawler".
	aEp, ok := findInSlice(merged, "http://example.com/a")
	if !ok {
		t.Fatal("/a missing from merged set")
	}
	if hasSource(aEp, "crawler-authenticated") {
		t.Errorf("/a should not have 'crawler-authenticated' source, got: %v", aEp.Sources)
	}
}

// TestGatedFinding_Evidence checks that the finding evidence lists URLs correctly.
func TestGatedFinding_Evidence(t *testing.T) {
	gated := make([]models.Endpoint, 7)
	for i := range gated {
		gated[i] = models.Endpoint{URL: "http://example.com/page" + string(rune('a'+i))}
	}
	f := gatedFinding("http://example.com", "admin", gated)

	if f.ID != "endpoints-authenticated-surface-expanded" {
		t.Errorf("unexpected finding ID: %s", f.ID)
	}
	if f.Severity != models.SeverityInfo {
		t.Errorf("expected info severity, got %s", f.Severity)
	}
	// With 7 gated and maxList=5, evidence should mention "and 2 more".
	if !strings.Contains(f.Evidence.Observed, "and 2 more") {
		t.Errorf("expected overflow suffix in evidence, got: %s", f.Evidence.Observed)
	}
	if !strings.Contains(f.Description, "admin") {
		t.Errorf("expected role 'admin' in description, got: %s", f.Description)
	}
}

// --- helpers ---

func findBySuffix(eps []models.Endpoint, suffix string) (models.Endpoint, bool) {
	for _, e := range eps {
		if endsWith(e.URL, suffix) {
			return e, true
		}
	}
	return models.Endpoint{}, false
}

func findInSlice(eps []models.Endpoint, url string) (models.Endpoint, bool) {
	for _, e := range eps {
		if e.URL == url {
			return e, true
		}
	}
	return models.Endpoint{}, false
}

func hasSource(ep models.Endpoint, src string) bool {
	for _, s := range ep.Sources {
		if s == src {
			return true
		}
	}
	return false
}

func endsWith(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}
