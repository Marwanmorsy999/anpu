package headers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
)

func postureClient() *anpuhttp.Client {
	return anpuhttp.NewClientWithLocalNetworkAllowed(true)
}

func postureContext(srv string) *scanner.ScanContext {
	u, _ := url.Parse(srv)
	host := ""
	if u != nil {
		host = u.Hostname()
	}
	return &scanner.ScanContext{Target: &scanner.ValidatedTarget{Raw: srv, URL: u, Host: host}}
}

// A bare HTTP server must yield exactly one posture finding covering all
// absent headers — not one row per header.
func TestPostureCollapsesAbsentHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><body>hi</body></html>"))
	}))
	defer srv.Close()
	res, err := New(postureClient()).Run(context.Background(), postureContext(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var posture int
	for _, f := range res.Findings {
		if f.ID == "headers-posture" {
			posture++
			if !strings.Contains(f.Title, "8 of 8") {
				t.Fatalf("bare server must miss 8 of 8, got %q", f.Title)
			}
			for _, want := range []string{"Content-Security-Policy", "Framing", "nosniff", "Referrer-Policy"} {
				if !strings.Contains(f.Description, want) {
					t.Fatalf("checklist must mention %q:\n%s", want, f.Description)
				}
			}
		}
		if strings.HasPrefix(f.ID, "headers-missing-") && f.ID != "headers-missing-hsts-http" {
			t.Fatalf("no per-header absent rows allowed, got %q", f.ID)
		}
	}
	if posture != 1 {
		t.Fatalf("must emit exactly one posture finding, got %d", posture)
	}
}

// A fully-headed HTTPS-ish response must yield no posture finding.
func TestPostureSilentWhenCovered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Embedder-Policy", "require-corp")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Permissions-Policy", "camera=()")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		_, _ = w.Write([]byte("<html><body>hi</body></html>"))
	}))
	defer srv.Close()
	res, err := New(postureClient()).Run(context.Background(), postureContext(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range res.Findings {
		if f.ID == "headers-posture" {
			t.Fatalf("covered response must not emit posture, got %q", f.Title)
		}
	}
}

// Present-but-weak CSP still earns its quality row on top of posture.
func TestPosturePlusQualityRow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "script-src 'unsafe-inline'")
		_, _ = w.Write([]byte("<html><body>hi</body></html>"))
	}))
	defer srv.Close()
	res, err := New(postureClient()).Run(context.Background(), postureContext(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var posture, quality bool
	for _, f := range res.Findings {
		if f.ID == "headers-posture" {
			posture = true
			if !strings.Contains(f.Title, "7 of 8") {
				t.Fatalf("CSP present must leave 7 of 8, got %q", f.Title)
			}
		}
		if f.ID == "headers-csp-unsafe-inline" {
			quality = true
		}
	}
	if !posture || !quality {
		t.Fatalf("need posture + quality rows, got posture=%v quality=%v", posture, quality)
	}
}
