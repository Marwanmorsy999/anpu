package recon

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

func TestRecon_ParsesRobotsTxt(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("User-agent: *\nDisallow: /admin/\nDisallow: /private/\nSitemap: /sitemap.xml\n"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html></html>"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	vt, err := scanner.ValidateTarget(srv.URL)
	if err != nil {
		t.Fatalf("validating target: %v", err)
	}

	r := New(anpuhttp.NewClientWithLocalNetworkAllowed(true))
	res, err := r.Run(context.Background(), &scanner.ScanContext{Target: vt, Config: models.ScanConfig{Profile: models.ProfileSafe}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundRobots := false
	foundAdminNote := false
	for _, f := range res.Findings {
		if f.ID == "recon-robots-txt-found" {
			foundRobots = true
		}
		if f.ID == "recon-robots-admin-path-admin" {
			foundAdminNote = true
		}
	}
	if !foundRobots {
		t.Error("expected recon-robots-txt-found finding")
	}
	if !foundAdminNote {
		t.Error("expected a note about the admin-like disallowed path")
	}

	foundAdminEndpoint := false
	for _, e := range res.Endpoints {
		if e.Category == models.EndpointAdminLike {
			foundAdminEndpoint = true
		}
	}
	if !foundAdminEndpoint {
		t.Error("expected /admin/ from robots.txt to be recorded as an admin-like endpoint")
	}
}

func TestRecon_DetectsSourceMapReference(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<script>//# sourceMappingURL=/static/app.js.map</script>"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	vt, err := scanner.ValidateTarget(srv.URL)
	if err != nil {
		t.Fatalf("validating target: %v", err)
	}
	r := New(anpuhttp.NewClientWithLocalNetworkAllowed(true))
	res, err := r.Run(context.Background(), &scanner.ScanContext{Target: vt, Config: models.ScanConfig{Profile: models.ProfileSafe}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range res.Findings {
		if f.ID == "recon-sourcemap-reference" {
			found = true
		}
	}
	if !found {
		t.Error("expected recon-sourcemap-reference finding")
	}
}

func TestRecon_NoRobotsTxtNoCrash(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/only-this-path", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html></html>"))
	})
	// Deliberately no "/" catch-all handler registered: net/http's default
	// ServeMux returns a genuine 404 for any unmatched path, including
	// both "/" (the scan target) and "/robots.txt", so this test exercises
	// the real "robots.txt truly absent" case.
	srv := httptest.NewServer(mux)
	defer srv.Close()

	vt, err := scanner.ValidateTarget(srv.URL)
	if err != nil {
		t.Fatalf("validating target: %v", err)
	}
	r := New(anpuhttp.NewClientWithLocalNetworkAllowed(true))
	res, err := r.Run(context.Background(), &scanner.ScanContext{Target: vt, Config: models.ScanConfig{Profile: models.ProfileSafe}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range res.Findings {
		if f.ID == "recon-robots-txt-found" {
			t.Error("did not expect robots.txt finding when robots.txt returns 404")
		}
	}
}
