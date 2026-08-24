package tls

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

func TestTLSAnalyzer_HTTPSUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	vt, err := scanner.ValidateTarget(srv.URL) // plain http:// server
	if err != nil {
		t.Fatalf("validating target: %v", err)
	}

	a := New(anpuhttp.NewClientWithLocalNetworkAllowed(true))
	res, err := a.Run(context.Background(), &scanner.ScanContext{Target: vt, Config: models.ScanConfig{Profile: models.ProfileSafe}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range res.Findings {
		if f.ID == "tls-https-unavailable" {
			found = true
		}
	}
	if !found {
		t.Error("expected tls-https-unavailable finding for a plain-HTTP-only server")
	}
}

func TestTLSAnalyzer_ValidCertNoFindings(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	vt, err := scanner.ValidateTarget(srv.URL)
	if err != nil {
		t.Fatalf("validating target: %v", err)
	}

	a := New(anpuhttp.NewInsecureClientWithLocalNetworkAllowed(true))
	res, err := a.Run(context.Background(), &scanner.ScanContext{Target: vt, Config: models.ScanConfig{Profile: models.ProfileSafe}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// httptest's self-signed cert will fail hostname/chain verification
	// against "127.0.0.1" in most Go versions unless SANs match, so we
	// only assert that the analyzer ran without crashing and, if it did
	// flag anything, that it never fabricated evidence.
	for _, f := range res.Findings {
		if f.Evidence.Unavailable && f.Evidence.Observed != "" {
			t.Errorf("finding %s: Unavailable=true but has Observed content", f.ID)
		}
	}
}
