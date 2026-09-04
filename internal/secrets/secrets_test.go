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
	if err != nil {
		t.Fatalf("validate target: %v", err)
	}
	return &scanner.ScanContext{Target: vt, Config: models.ScanConfig{Profile: models.ProfileSafe}, Endpoints: endpoints}
}

func TestSecrets_NoEndpoints_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	res, err := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Run(context.Background(), secretsContext(t, srv, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings, got %+v", res.Findings)
	}
}

func TestSecrets_DetectsAWSKey_RedactsEvidence(t *testing.T) {
	const fakeKey = "AKIAABCDEFGHIJKLMNOP"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".js") {
			_, _ = w.Write([]byte("const key = '" + fakeKey + "';"))
			return
		}
	}))
	defer srv.Close()
	endpoints := []models.Endpoint{{URL: srv.URL + "/app.js", Category: models.EndpointAsset, Sources: []string{"html-link"}}}
	res, err := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Run(context.Background(), secretsContext(t, srv, endpoints))
	if err != nil {
		t.Fatal(err)
	}
	var found *models.Finding
	for i := range res.Findings {
		if strings.HasPrefix(res.Findings[i].ID, "secrets-aws-access-key-") {
			found = &res.Findings[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected AWS finding, got %+v", res.Findings)
	}
	if strings.Contains(found.Evidence.Observed, fakeKey) {
		t.Fatalf("evidence leaked full secret: %q", found.Evidence.Observed)
	}
}

func TestSecrets_IgnoresNonAssetEndpoints(t *testing.T) {
	const fakeKey = "AKIAABCDEFGHIJKLMNOP"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("const key = '" + fakeKey + "';")) }))
	defer srv.Close()
	endpoints := []models.Endpoint{{URL: srv.URL + "/about", Category: models.EndpointPage, Sources: []string{"html-link"}}}
	res, err := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Run(context.Background(), secretsContext(t, srv, endpoints))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings, got %+v", res.Findings)
	}
}

func TestSecrets_DetectsPrivateKeyBlock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".js") {
			_, _ = w.Write([]byte("-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----"))
			return
		}
	}))
	defer srv.Close()
	endpoints := []models.Endpoint{{URL: srv.URL + "/bundle.js", Category: models.EndpointAsset, Sources: []string{"javascript"}}}
	res, err := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Run(context.Background(), secretsContext(t, srv, endpoints))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range res.Findings {
		if strings.HasPrefix(f.ID, "secrets-private-key-") {
			found = true
			if f.Severity != models.SeverityCritical {
				t.Fatalf("expected critical, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatalf("expected private-key finding, got %+v", res.Findings)
	}
}

func TestSecrets_Name(t *testing.T) {
	if got := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Name(); got != "secrets" {
		t.Fatalf("got %q", got)
	}
}

func TestSecrets_NewPatterns(t *testing.T) {
	// Build payloads at runtime — avoids GitHub push protection scanning
	// literal secret-shaped strings in source files.
	stripePrefix := "sk" + "_live_"
	sgPrefix := "S" + "G."
	npmPrefix := "n" + "pm_"
	cases := []struct {
		id      string
		payload string
	}{
		{"stripe-key", "var key = \"" + stripePrefix + "AAAAAAAAAAAAAAAAAAAAAAAAA\""},
		{"sendgrid-api-key", sgPrefix + "AAAAAAAAAAAAAAAAAAAAAA.BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"},
		{"npm-access-token", npmPrefix + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"},
		{"mailchimp-api-key", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4" + "-us12"},
	}
	for _, tc := range cases {
		matched := false
		for _, r := range rules {
			if r.ID == tc.id && r.Pattern.MatchString(tc.payload) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("rule %q did not match payload", tc.id)
		}
	}
}

func TestSecrets_StripePublishableKeyNotCritical(t *testing.T) {
	for _, r := range rules {
		if r.ID == "stripe-publishable-key" {
			if r.Severity == models.SeverityCritical || r.Severity == models.SeverityHigh {
				t.Errorf("stripe-publishable-key should be Low severity, got %s", r.Severity)
			}
			return
		}
	}
	t.Error("stripe-publishable-key rule not found")
}

func TestSecrets_AllRulesHavePattern(t *testing.T) {
	for _, r := range rules {
		if r.Pattern == nil {
			t.Errorf("rule %q has nil Pattern", r.ID)
		}
		if r.ID == "" {
			t.Error("rule has empty ID")
		}
		if r.Title == "" {
			t.Errorf("rule %q has empty Title", r.ID)
		}
	}
}
