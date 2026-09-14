package http

import (
	"context"
	stdhttp "net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func redirectFixture() *httptest.Server {
	mux := stdhttp.NewServeMux()
	mux.HandleFunc("/go", func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		dest := r.URL.Query().Get("url")
		if dest == "" {
			w.WriteHeader(stdhttp.StatusBadRequest)
			return
		}
		w.Header().Set("Location", dest)
		w.WriteHeader(stdhttp.StatusFound)
	})
	mux.HandleFunc("/b", func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		_, _ = w.Write([]byte("final"))
	})
	return httptest.NewServer(mux)
}

func testCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 15*time.Second)
}

// GetNoRedirect must surface the 3xx + Location instead of chasing it:
// redirect-observing rules (open-redirect probes) depend on this.
func TestGetNoRedirectSurfaces3xx(t *testing.T) {
	srv := redirectFixture()
	defer srv.Close()
	client := NewClientWithLocalNetworkAllowed(true)
	ctx, cancel := testCtx()
	defer cancel()
	resp, err := client.GetNoRedirect(ctx, srv.URL+"/go?url=https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != stdhttp.StatusFound {
		t.Fatalf("expected first-response 302, got %d (client followed?)", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "https://example.com/" {
		t.Fatalf("Location must survive, got %q", got)
	}
	if resp.FinalURL != srv.URL+"/go?url=https://example.com/" {
		t.Fatalf("FinalURL must be the requested URL, got %q", resp.FinalURL)
	}
}

// Control: plain Get follows the chain (documents the distinction the
// rule fix relies on).
func TestGetFollowsRedirects(t *testing.T) {
	srv := redirectFixture()
	defer srv.Close()
	client := NewClientWithLocalNetworkAllowed(true)
	ctx, cancel := testCtx()
	defer cancel()
	resp, err := client.Get(ctx, srv.URL+"/go?url="+srv.URL+"/b")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != stdhttp.StatusOK || resp.FinalURL != srv.URL+"/b" {
		t.Fatalf("Get must follow: status=%d final=%q", resp.StatusCode, resp.FinalURL)
	}
}
