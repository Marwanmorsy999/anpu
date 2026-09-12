package cvepack

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

func cveClient() *anpuhttp.Client {
	return anpuhttp.NewClientWithLocalNetworkAllowed(true)
}

func cveContext(srv string, techs []models.Technology) *scanner.ScanContext {
	u, _ := url.Parse(srv)
	host := ""
	if u != nil {
		host = u.Hostname()
	}
	return &scanner.ScanContext{
		Target:       &scanner.ValidatedTarget{Raw: srv, URL: u, Host: host},
		Technologies: techs,
	}
}

// A confident Next.js stack cannot process Spring prefixes — the probe is
// meaningless there and must be skipped with a reason.
func TestSpringProbeSkippedOnNextJS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()
	techs := []models.Technology{{Name: "Next.js", Category: "framework", Confidence: 0.9}}
	res, err := New(cveClient()).Run(context.Background(), cveContext(srv.URL, techs))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range res.Findings {
		if f.ID == "cvepack-spring-prefix" {
			t.Fatal("Spring probe must not run on confident Next.js")
		}
	}
	if len(res.Warnings) == 0 {
		t.Fatal("skip must carry a reason")
	}
}

// Weak stacks fail open: the probe still runs.
func TestSpringProbeRunsOnWeakStack(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Differ on the classLoader param like a Spring binder would.
		if r.URL.Query().Has("class.module.classLoader.anpuProbe") {
			_, _ = w.Write([]byte("hello spring-bound"))
			return
		}
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()
	techs := []models.Technology{{Name: "Next.js", Category: "framework", Confidence: 0.65}}
	res, err := New(cveClient()).Run(context.Background(), cveContext(srv.URL, techs))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	found := false
	for _, f := range res.Findings {
		if f.ID == "cvepack-spring-prefix" {
			found = true
		}
	}
	if !found {
		t.Fatal("weak Next.js signal must not suppress the probe")
	}
}
