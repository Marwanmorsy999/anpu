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

func TestDetector_ExtractsVersionFromInlineBanner(t *testing.T) {
	cases := []struct {
		body        string
		wantName    string
		wantVersion string
	}{
		// jQuery inline banner
		{`<script>/*! jQuery v3.6.0 | (c) jQuery Foundation */</script>`, "jQuery", "3.6.0"},
		// jQuery script src filename
		{`<script src="/js/jquery-3.4.1.min.js"></script>`, "jQuery", "3.4.1"},
		// Bootstrap inline banner
		{`/*!  Bootstrap v5.3.0 (https://getbootstrap.com/) */`, "Bootstrap", "5.3.0"},
		// Angular ng-version attribute
		{`<app-root ng-version="17.3.1"></app-root>`, "Angular", "17.3.1"},
		// lodash inline banner
		{`/*! lodash v4.17.21 */`, "lodash", "4.17.21"},
		// moment.js inline banner
		{`//! moment.js 2.29.4`, "moment", "2.29.4"},
	}
	for _, tc := range cases {
		techs := detectFromBody(tc.body)
		found := false
		for _, tech := range techs {
			if tech.Name == tc.wantName {
				found = true
				if tech.Version != tc.wantVersion {
					t.Errorf("detectFromBody(%q): %s version = %q, want %q",
						tc.body, tc.wantName, tech.Version, tc.wantVersion)
				}
			}
		}
		if !found {
			t.Errorf("detectFromBody(%q): %s not detected", tc.body, tc.wantName)
		}
	}
}

func TestDetectFromGenerator_ExtractsNameAndVersion(t *testing.T) {
	cases := []struct {
		html        string
		wantName    string
		wantVersion string
	}{
		{`<meta name="generator" content="WordPress 6.4.3">`, "WordPress", "6.4.3"},
		{`<meta name="generator" content="Joomla! 4.3.2">`, "Joomla", "4.3.2"},
		{`<meta content="Hugo 0.121.1" name="generator">`, "Hugo", "0.121.1"},
		{`<meta name="generator" content="Jekyll v4.3.2">`, "Jekyll", "4.3.2"},
		// Unknown generator should produce no output
		{`<meta name="generator" content="SomeUnknownCMS 9.9">`, "", ""},
	}
	for _, tc := range cases {
		techs := detectFromGenerator(tc.html)
		if tc.wantName == "" {
			if len(techs) != 0 {
				t.Errorf("detectFromGenerator(%q): expected no output, got %v", tc.html, techs)
			}
			continue
		}
		found := false
		for _, tech := range techs {
			if tech.Name == tc.wantName {
				found = true
				if tech.Version != tc.wantVersion {
					t.Errorf("detectFromGenerator(%q): version = %q, want %q",
						tc.html, tech.Version, tc.wantVersion)
				}
				if tech.Confidence != 0.85 {
					t.Errorf("generator confidence = %v, want 0.85", tech.Confidence)
				}
			}
		}
		if !found {
			t.Errorf("detectFromGenerator(%q): %s not detected", tc.html, tc.wantName)
		}
	}
}

func TestDetector_GeneratorTagInRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><head><meta name="generator" content="WordPress 6.4.3"></head><body></body></html>`))
	}))
	defer srv.Close()

	vt, _ := scanner.ValidateTarget(srv.URL)
	d := New(anpuhttp.NewClientWithLocalNetworkAllowed(true))
	res, err := d.Run(context.Background(), &scanner.ScanContext{Target: vt, Config: models.ScanConfig{Profile: models.ProfileSafe}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, tech := range res.Technologies {
		if tech.Name == "WordPress" && tech.Version == "6.4.3" {
			return // pass
		}
	}
	t.Errorf("expected WordPress 6.4.3 from generator tag, got %v", res.Technologies)
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
