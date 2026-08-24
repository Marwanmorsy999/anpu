package endpoints

import (
	"context"
	"net/http"
	"net/http/httptest"
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

	byURLSuffix := map[string]models.Endpoint{}
	for _, e := range res.Endpoints {
		byURLSuffix[e.URL] = e
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

	// External domain links must never appear as endpoints for this target.
	if _, ok := findBySuffix(res.Endpoints, "other-domain.example/x"); ok {
		t.Error("did not expect an external-domain link to be included as an endpoint")
	}
	// mailto: links must be excluded.
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

func findBySuffix(eps []models.Endpoint, suffix string) (models.Endpoint, bool) {
	for _, e := range eps {
		if endsWith(e.URL, suffix) {
			return e, true
		}
	}
	return models.Endpoint{}, false
}

func endsWith(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}
