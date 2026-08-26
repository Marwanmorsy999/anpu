package secrets

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

func secretsContext(t *testing.T, srv *httptest.Server, endpoints []models.Endpoint) *scanner.ScanContext {
	t.Helper()
	vt, err := scanner.ValidateTarget(srv.URL)
	if err != nil { t.Fatalf("validate target: %v", err) }
	return &scanner.ScanContext{Target: vt, Config: models.ScanConfig{Profile: models.ProfileSafe}, Endpoints: endpoints}
}

func TestSecrets_NoEndpoints_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	res, err := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Run(context.Background(), secretsContext(t, srv, nil))
	if err != nil { t.Fatal(err) }
	if len(res.Findings) != 0 { t.Fatalf("expected no findings, got %+v", res.Findings) }
}

func TestSecrets_DetectsAWSKey_RedactsEvidence(t *testing.T) {
	const fakeKey = "AKIAABCDEFGHIJKLMNOP"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".js") { _, _ = w.Write([]byte("const key = '" + fakeKey + "';")); return }
	}))
	defer srv.Close()
	endpoints := []models.Endpoint{{URL: srv.URL + "/app.js", Category: models.EndpointAsset, Sources: []string{"html-link"}}}
	res, err := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Run(context.Background(), secretsContext(t, srv, endpoints))
	if err != nil { t.Fatal(err) }
	var found *models.Finding
	for i := range res.Findings { if strings.HasPrefix(res.Findings[i].ID, "secrets-aws-access-key-") { found = &res.Findings[i]; break } }
	if found == nil { t.Fatalf("expected AWS finding, got %+v", res.Findings) }
	if strings.Contains(found.Evidence.Observed, fakeKey) { t.Fatalf("evidence leaked full secret: %q", found.Evidence.Observed) }
}

func TestSecrets_IgnoresNonAssetEndpoints(t *testing.T) {
	const fakeKey = "AKIAABCDEFGHIJKLMNOP"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("const key = '" + fakeKey + "';")) }))
	defer srv.Close()
	endpoints := []models.Endpoint{{URL: srv.URL + "/about", Category: models.EndpointPage, Sources: []string{"html-link"}}}
	res, err := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Run(context.Background(), secretsContext(t, srv, endpoints))
	if err != nil { t.Fatal(err) }
	if len(res.Findings) != 0 { t.Fatalf("expected no findings, got %+v", res.Findings) }
}

func TestSecrets_DetectsPrivateKeyBlock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".js") { _, _ = w.Write([]byte("-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----")); return }
	}))
	defer srv.Close()
	endpoints := []models.Endpoint{{URL: srv.URL + "/bundle.js", Category: models.EndpointAsset, Sources: []string{"javascript"}}}
	res, err := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Run(context.Background(), secretsContext(t, srv, endpoints))
	if err != nil { t.Fatal(err) }
	found := false
	for _, f := range res.Findings { if strings.HasPrefix(f.ID, "secrets-private-key-") { found = true; if f.Severity != models.SeverityCritical { t.Fatalf("expected critical, got %s", f.Severity) } } }
	if !found { t.Fatalf("expected private-key finding, got %+v", res.Findings) }
}

func TestSecrets_Name(t *testing.T) {
	if got := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Name(); got != "secrets" { t.Fatalf("got %q", got) }
}
