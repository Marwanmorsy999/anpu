package technology

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

func TestDetector_IdentifiesServerAndPoweredBy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.Header().Set("X-Powered-By", "PHP/7.4.3")
		w.Write([]byte("<html></html>"))
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

	var names []string
	for _, tech := range res.Technologies {
		names = append(names, tech.Name)
	}
	if !contains(names, "nginx") {
		t.Errorf("expected nginx to be detected, got %v", names)
	}
	if !contains(names, "PHP") {
		t.Errorf("expected PHP to be detected, got %v", names)
	}
}

func TestDetector_ExtractsVersionWhenPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()

	vt, _ := scanner.ValidateTarget(srv.URL)
	d := New(anpuhttp.NewClientWithLocalNetworkAllowed(true))
	res, err := d.Run(context.Background(), &scanner.ScanContext{Target: vt, Config: models.ScanConfig{Profile: models.ProfileSafe}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, tech := range res.Technologies {
		if tech.Name == "nginx" && tech.Version != "1.18.0" {
			t.Errorf("expected nginx version 1.18.0, got %q", tech.Version)
		}
	}
}

func TestDetector_DoesNotInventVersionWhenAbsent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()

	vt, _ := scanner.ValidateTarget(srv.URL)
	d := New(anpuhttp.NewClientWithLocalNetworkAllowed(true))
	res, err := d.Run(context.Background(), &scanner.ScanContext{Target: vt, Config: models.ScanConfig{Profile: models.ProfileSafe}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, tech := range res.Technologies {
		if tech.Name == "nginx" && tech.Version != "" {
			t.Errorf("did not expect a fabricated version, got %q", tech.Version)
		}
	}
}

func TestDetector_DetectsFromBodyContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><head><meta name="generator" content="WordPress 6.0"></head><body class="wp-content"></body></html>`))
	}))
	defer srv.Close()

	vt, _ := scanner.ValidateTarget(srv.URL)
	d := New(anpuhttp.NewClientWithLocalNetworkAllowed(true))
	res, err := d.Run(context.Background(), &scanner.ScanContext{Target: vt, Config: models.ScanConfig{Profile: models.ProfileSafe}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, tech := range res.Technologies {
		if tech.Name == "WordPress" {
			found = true
		}
	}
	if !found {
		t.Error("expected WordPress to be detected from body content")
	}
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
