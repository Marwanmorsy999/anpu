package crawler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

func TestDiscover_RespectsScopeAndDepth(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<a href="/one">one</a><a href="https://example.invalid/outside">external</a>`))
	})
	mux.HandleFunc("/one", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<a href="/two">two</a><img src="/image.png">`))
	})
	mux.HandleFunc("/two", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<a href="/three">three</a>`))
	})
	mux.HandleFunc("/three", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<p>terminal</p>`))
	})
	mux.HandleFunc("/image.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("not-an-image"))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New(anpuhttp.NewClientWithLocalNetworkAllowed(true), Limits{MaxPages: 10, MaxDepth: 1})
	endpoints, warnings, err := c.Discover(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}

	want := map[string]bool{
		srv.URL:         true,
		srv.URL + "/one": true,
		srv.URL + "/two": true, // discovered, but not crawled at depth 2
	}
	for raw := range want {
		if _, ok := findEndpoint(endpoints, raw); !ok {
			t.Errorf("expected endpoint %s", raw)
		}
	}
	if _, ok := findEndpoint(endpoints, srv.URL+"/three"); ok {
		t.Error("did not expect depth-3 page to be discovered")
	}
	if _, ok := findEndpoint(endpoints, srv.URL+"/image.png"); !ok {
		t.Error("expected non-page asset to be recorded but not crawled")
	}
}

func TestDiscover_EnforcesPageLimit(t *testing.T) {
	mux := http.NewServeMux()
	for i := 0; i < 5; i++ {
		path := "/p" + string(rune('0'+i))
		next := "/p" + string(rune('0'+i+1))
		mux.HandleFunc(path, func(nextPath string) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				_, _ = w.Write([]byte(`<a href="` + nextPath + `">next</a>`))
			}
		}(next))
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<a href="/p0">p0</a>`))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New(anpuhttp.NewClientWithLocalNetworkAllowed(true), Limits{MaxPages: 2, MaxDepth: 10})
	endpoints, warnings, err := c.Discover(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(endpoints) < 2 {
		t.Fatalf("expected at least start and first discovered endpoint, got %d", len(endpoints))
	}
	if len(warnings) == 0 {
		t.Fatal("expected page-limit warning")
	}
}

func TestLimitsForProfile(t *testing.T) {
	cases := []struct {
		profile models.Profile
		pages   int
		depth   int
	}{
		{models.ProfileSafe, 1, 0},
		{models.ProfileStandard, 25, 2},
		{models.ProfileDeep, 100, 4},
	}
	for _, tc := range cases {
		got := LimitsForProfile(tc.profile)
		if got.MaxPages != tc.pages || got.MaxDepth != tc.depth {
			t.Errorf("LimitsForProfile(%q) = %+v, want pages=%d depth=%d", tc.profile, got, tc.pages, tc.depth)
		}
	}
}

func findEndpoint(endpoints []models.Endpoint, raw string) (models.Endpoint, bool) {
	for _, ep := range endpoints {
		if ep.URL == raw {
			return ep, true
		}
	}
	return models.Endpoint{}, false
}
