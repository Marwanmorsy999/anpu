package crawler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

func TestDiscover_RespectsScopeAndDepth(t *testing.T) {
	mux := http.NewServeMux()
	var mu sync.Mutex
	hits := map[string]int{}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<a href="/one">one</a><a href="https://example.invalid/outside">external</a>`))
	})
	mux.HandleFunc("/one", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<a href="/two">two</a><img src="/image.png">`))
	})
	mux.HandleFunc("/two", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<a href="/three">three</a>`))
	})
	mux.HandleFunc("/three", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<p>terminal</p>`))
	})
	mux.HandleFunc("/image.png", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
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

	if _, ok := findEndpoint(endpoints, srv.URL); !ok {
		t.Fatal("expected crawl start endpoint")
	}
	if _, ok := findEndpoint(endpoints, srv.URL+"/one"); !ok {
		t.Fatal("expected first-level page to be discovered")
	}
	if _, ok := findEndpoint(endpoints, srv.URL+"/two"); !ok {
		t.Fatal("expected second-level URL to be recorded in the attack surface")
	}
	if _, ok := findEndpoint(endpoints, srv.URL+"/three"); ok {
		t.Fatal("did not expect depth-2 page to be discovered")
	}
	if _, ok := findEndpoint(endpoints, srv.URL+"/image.png"); !ok {
		t.Fatal("expected linked asset to be recorded")
	}
	if _, ok := findEndpoint(endpoints, "https://example.invalid/outside"); ok {
		t.Fatal("did not expect external-domain endpoint")
	}

	mu.Lock()
	defer mu.Unlock()
	if hits["/two"] != 0 {
		t.Fatalf("expected max depth to prevent fetching /two, got %d request(s)", hits["/two"])
	}
	if hits["/image.png"] != 0 {
		t.Fatalf("expected static assets not to be recursively fetched, got %d request(s)", hits["/image.png"])
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
