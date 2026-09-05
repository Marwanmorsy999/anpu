package cors

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

func init() { scanner.AllowLocalNetwork = true }

func newTestContext(t *testing.T, srv *httptest.Server) *scanner.ScanContext {
	t.Helper()
	vt, err := scanner.ValidateTarget(srv.URL)
	if err != nil {
		t.Fatalf("validating test target: %v", err)
	}
	return &scanner.ScanContext{Target: vt, Config: models.ScanConfig{Profile: models.ProfileSafe}}
}

func TestCORS_NoHeaders_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res, err := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Run(context.Background(), newTestContext(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings, got %+v", res.Findings)
	}
}

func TestCORS_WildcardWithCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}))
	defer srv.Close()

	res, err := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Run(context.Background(), newTestContext(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range res.Findings {
		if f.Severity == models.SeverityMedium && strings.Contains(f.Title, "Wildcard CORS combined with credentials") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected wildcard+credentials finding, got %+v", res.Findings)
	}
}

func TestCORS_WildcardOnly_LowSeverity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res, err := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Run(context.Background(), newTestContext(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if f.Severity == models.SeverityLow && strings.Contains(f.Title, "wildcard") {
			return
		}
	}
	t.Fatalf("expected wildcard-only low-severity finding, got %+v", res.Findings)
}

func TestCORS_ReflectsArbitraryOriginWithCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res, err := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Run(context.Background(), newTestContext(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range res.Findings {
		if f.Severity == models.SeverityHigh && strings.Contains(f.Title, "reflects arbitrary origins with credentials") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected arbitrary-origin+creds finding, got %+v", res.Findings)
	}
}

func TestCORS_NullOriginWithCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "null" {
			w.Header().Set("Access-Control-Allow-Origin", "null")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res, err := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Run(context.Background(), newTestContext(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range res.Findings {
		if f.Severity == models.SeverityHigh && strings.Contains(f.Title, "null origin") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected null-origin+creds finding (SeverityHigh), got %+v", res.Findings)
	}
}

func TestCORS_SubdomainOriginWithCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		// Reflect any subdomain of the host.
		if strings.HasPrefix(origin, "https://evil.") {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res, err := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Run(context.Background(), newTestContext(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range res.Findings {
		if strings.Contains(f.Title, "subdomain") {
			found = true
			if f.Severity != models.SeverityHigh {
				t.Errorf("subdomain+creds should be SeverityHigh, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Fatalf("expected subdomain-origin finding, got %+v", res.Findings)
	}
}

func TestCORS_ReflectsArbitraryOriginNoCreds_Medium(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			// No credentials header
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res, err := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Run(context.Background(), newTestContext(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range res.Findings {
		if strings.Contains(f.Title, "reflects arbitrary origins (no credentials)") {
			found = true
			if f.Severity != models.SeverityMedium {
				t.Errorf("no-creds reflection should be Medium, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Fatalf("expected medium no-creds reflection finding, got %+v", res.Findings)
	}
}

func TestCORS_SafeEndpoint_SpecificOrigin(t *testing.T) {
	// Server only allows a specific trusted origin — no findings expected.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://trusted.example.com")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res, err := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Run(context.Background(), newTestContext(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if f.Severity == models.SeverityHigh {
			t.Errorf("specific-origin allowlist should produce no High findings, got: %s", f.Title)
		}
	}
}

func TestCORS_Name(t *testing.T) {
	if got := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Name(); got != "cors" {
		t.Fatalf("got %q", got)
	}
}

func TestCORS_IsReflected(t *testing.T) {
	if !isReflected("https://evil.example.com", "https://evil.example.com") {
		t.Error("identical origins should match")
	}
	if isReflected("https://trusted.example.com", "https://evil.example.com") {
		t.Error("different origins should not match")
	}
	if isReflected("*", "https://evil.example.com") {
		t.Error("wildcard should not match a specific origin via isReflected")
	}
}
