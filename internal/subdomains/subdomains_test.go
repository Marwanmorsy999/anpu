package subdomains

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

func init() { scanner.AllowLocalNetwork = true }

func TestSubdomains_Name(t *testing.T) {
	if got := New().Name(); got != "subdomains" {
		t.Fatalf("got %q", got)
	}
}

func TestSubdomains_Available(t *testing.T) {
	if !New().Available(context.Background()) {
		t.Fatal("expected available")
	}
}

func TestSubdomains_BareHost_NoFindings(t *testing.T) {
	vt := &scanner.ValidatedTarget{Raw: "http://singlelabel/", Host: "singlelabel"}
	sc := &scanner.ScanContext{Target: vt, Config: models.ScanConfig{Profile: models.ProfileSafe}}
	res, err := New().Run(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 || len(res.Warnings) != 0 {
		t.Fatalf("expected empty result, got findings=%+v warnings=%v", res.Findings, res.Warnings)
	}
}

type redirectTransport struct{ targetURL string }

func (r *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	target, err := http.NewRequest(req.Method, r.targetURL+"?"+req.URL.RawQuery, req.Body)
	if err != nil {
		return nil, err
	}
	return http.DefaultTransport.RoundTrip(target)
}

func TestQueryCTLogs_ParsesSubdomains(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"name_value":"www.example.com"},{"name_value":"api.example.com\nstaging.example.com"},{"name_value":"*.example.com"}]`))
	}))
	defer srv.Close()
	s := New()
	s.client = &http.Client{Transport: &redirectTransport{targetURL: srv.URL}, Timeout: 5 * time.Second}
	names, warn := s.queryCTLogs(context.Background(), "example.com")
	if warn != "" {
		t.Fatalf("unexpected warning: %s", warn)
	}
	joined := strings.Join(names, ",")
	for _, want := range []string{"www.example.com", "api.example.com", "staging.example.com", "*.example.com"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in %v", want, names)
		}
	}
}

func TestQueryCTLogs_NonOKStatus_Warns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer srv.Close()
	s := New()
	s.client = &http.Client{Transport: &redirectTransport{targetURL: srv.URL}, Timeout: 5 * time.Second}
	names, warn := s.queryCTLogs(context.Background(), "example.com")
	if warn == "" || len(names) != 0 {
		t.Fatalf("expected warning and no names, got names=%v warning=%q", names, warn)
	}
}

func TestDNSBruteSuffix(t *testing.T) {
	if got := dnsBruteSuffix(models.ProfileSafe); got != "" {
		t.Fatalf("safe suffix=%q", got)
	}
	if got := dnsBruteSuffix(models.ProfileDeep); !strings.Contains(got, "brute") {
		t.Fatalf("deep suffix=%q", got)
	}
}

func TestExtraSuffix(t *testing.T) {
	if got := extraSuffix(0); got != "" {
		t.Fatalf("zero suffix=%q", got)
	}
	if got := extraSuffix(5); !strings.Contains(got, "5 more") {
		t.Fatalf("five suffix=%q", got)
	}
}
