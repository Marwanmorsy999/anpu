package methods

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

func init() { scanner.AllowLocalNetwork = true }

func methodsContext(t *testing.T, srv *httptest.Server) *scanner.ScanContext {
	t.Helper()
	vt, err := scanner.ValidateTarget(srv.URL)
	if err != nil { t.Fatalf("validate target: %v", err) }
	return &scanner.ScanContext{Target: vt, Config: models.ScanConfig{Profile: models.ProfileSafe}}
}

func hasMethodFinding(fs []models.Finding, id string) bool {
	for _, f := range fs { if f.ID == id { return true } }
	return false
}

func TestMethods_NoRiskyVerbsAdvertised(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions { w.Header().Set("Allow", "GET, HEAD") }
	}))
	defer srv.Close()
	res, err := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Run(context.Background(), methodsContext(t, srv))
	if err != nil { t.Fatal(err) }
	if len(res.Findings) != 0 { t.Fatalf("expected no findings, got %+v", res.Findings) }
}

func TestMethods_AdvertisedPUT(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions { w.Header().Set("Allow", "GET, HEAD, PUT") }
	}))
	defer srv.Close()
	res, err := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Run(context.Background(), methodsContext(t, srv))
	if err != nil { t.Fatal(err) }
	if !hasMethodFinding(res.Findings, "methods-advertised-put") { t.Fatalf("expected PUT finding, got %+v", res.Findings) }
}

func TestMethods_TraceEchoesMarker(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodTrace {
			w.Header().Set("X-Anpu-Probe", r.Header.Get("X-Anpu-Probe"))
			w.WriteHeader(http.StatusOK)
			return
		}
	}))
	defer srv.Close()
	res, err := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Run(context.Background(), methodsContext(t, srv))
	if err != nil { t.Fatal(err) }
	if !hasMethodFinding(res.Findings, "methods-trace-enabled") { t.Fatalf("expected TRACE finding, got %+v", res.Findings) }
}

func TestMethods_TraceRejected_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodTrace { w.WriteHeader(http.StatusMethodNotAllowed); return }
	}))
	defer srv.Close()
	res, err := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Run(context.Background(), methodsContext(t, srv))
	if err != nil { t.Fatal(err) }
	if hasMethodFinding(res.Findings, "methods-trace-enabled") { t.Fatalf("unexpected TRACE finding: %+v", res.Findings) }
}

func TestParseAllow(t *testing.T) {
	got := parseAllow("GET, POST", "PUT,DELETE")
	for _, want := range []string{"GET", "POST", "PUT", "DELETE"} {
		if !got[want] { t.Errorf("missing %s in %v", want, got) }
	}
	if got["TRACE"] { t.Error("TRACE should not be present") }
}

func TestMethods_Name(t *testing.T) {
	if got := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Name(); got != "methods" { t.Fatalf("got %q", got) }
}
