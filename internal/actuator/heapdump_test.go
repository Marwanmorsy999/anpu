package actuator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/internal/scanner"
)

func heapdumpCtx(srv string) *scanner.ScanContext {
	u, _ := url.Parse(srv)
	host := ""
	if u != nil {
		host = u.Hostname()
	}
	return &scanner.ScanContext{Target: &scanner.ValidatedTarget{Raw: srv, URL: u, Host: host}}
}

// Sanity-pass follow-up: a catch-all serving identical headers for
// every path must not produce a heapdump finding from the
// headers-only check.
func TestHeapdumpCatchAllSuppressed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		body := "<html><body>shell</body></html>"
		w.Header().Set("Content-Length", "31")
		w.WriteHeader(http.StatusOK)
		if r.Method != "HEAD" {
			_, _ = w.Write([]byte(body))
		}
	}))
	defer srv.Close()
	res, err := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Run(context.Background(), heapdumpCtx(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range res.Findings {
		if f.ID == "actuator-heapdump-headers" {
			t.Fatalf("catch-all must not yield heapdump finding: %+v", f)
		}
	}
}

// A real dump-shaped response (octet-stream, distinct length vs a 404
// root) must still be found.
func TestHeapdumpRealDumpFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/actuator/heapdump" {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", "12345678")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	res, err := New(anpuhttp.NewClientWithLocalNetworkAllowed(true)).Run(context.Background(), heapdumpCtx(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	found := false
	for _, f := range res.Findings {
		if f.ID == "actuator-heapdump-headers" {
			found = true
		}
	}
	if !found {
		t.Fatal("real heapdump headers must be found")
	}
}
