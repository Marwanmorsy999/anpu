package active

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
)

func soft404Client() *anpuhttp.Client {
	return anpuhttp.NewClientWithLocalNetworkAllowed(true)
}

func soft404Resp(body string) *anpuhttp.Response {
	return &anpuhttp.Response{StatusCode: 200, Body: []byte(body)}
}

// Phase 2 regression: baseline words must be retained outside catch-all
// mode. The old code only stored them when catchAll fired, so
// soft404Score returned 0 and isSoft404 fell into a self-comparison
// dead branch for ordinary (non-catch-all) sites.
func TestDetectorNonCatchAllSimilarity(t *testing.T) {
	const bodyA = "alpha beta gamma delta epsilon zeta eta theta iota kappa"
	const bodyB = "alpha beta gamma lamp light lemon ocean orbit panel quiet"
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_, _ = w.Write([]byte("<html><head><title>Home</title></head><body>welcome to our homepage</body></html>"))
			return
		}
		if atomic.AddInt64(&n, 1)%2 == 1 {
			_, _ = w.Write([]byte(bodyA))
			return
		}
		_, _ = w.Write([]byte(bodyB))
	}))
	defer srv.Close()

	d := newSoft404Detector(context.Background(), soft404Client(), srv.URL)
	if d == nil {
		t.Fatal("detector must build")
	}
	if d.catchAll {
		t.Fatal("parity bodies must not declare catch-all")
	}
	if d.baselineWords == nil {
		t.Fatal("baseline words must be retained outside catch-all")
	}
	// Near-baseline probe (same template + one word): new hash, high
	// similarity — must be caught and must score above the gate.
	probe := soft404Resp(bodyA + " extra")
	if !d.isSoft404(probe) {
		t.Fatal("near-baseline probe must be soft-404")
	}
	if s := d.soft404Score(probe); s < 0.85 {
		t.Fatalf("near-baseline probe must score >= 0.85, got %.2f", s)
	}
	if d.isSoft404(soft404Resp("<html><body>invoice total $1,240 due soon</body></html>")) {
		t.Fatal("genuinely different page must not be soft-404")
	}
}

// Catch-all + SPA shell: every path serves the shell, so shell-like
// probes are suppressed and only foreign content passes.
func TestDetectorCatchAllShell(t *testing.T) {
	const shell = "<html><head><title>Example App</title></head><body><div>loading application shell</div></body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(shell))
	}))
	defer srv.Close()

	d := newSoft404Detector(context.Background(), soft404Client(), srv.URL)
	if d == nil {
		t.Fatal("detector must build")
	}
	if !d.catchAll {
		t.Fatal("uniform shell must declare catch-all")
	}
	if !d.isSoft404(soft404Resp(shell)) {
		t.Fatal("identical shell must be soft-404")
	}
	if s := d.soft404Score(soft404Resp(shell)); s != 1.0 {
		t.Fatalf("identical shell must score 1.0, got %.2f", s)
	}
	if d.isSoft404(soft404Resp("invoice total $1,240 due within thirty days payable now")) {
		t.Fatal("foreign content must pass the gate")
	}
}

// Phase 3 regression: detector baselines must probe random paths even
// when the target URL carries its own query string. Appending randomness
// to the query value would render the endpoint template and suppress it
// as its own baseline.
func TestDetectorStripsTargetQuery(t *testing.T) {
	var uris []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uris = append(uris, r.URL.RequestURI())
		_, _ = w.Write([]byte("lost missing page nowhere"))
	}))
	defer srv.Close()

	d := newSoft404Detector(context.Background(), soft404Client(), srv.URL+"/?q=1#frag")
	if d == nil {
		t.Fatal("detector must build")
	}
	if len(uris) < 2 {
		t.Fatalf("expected baseline fetches, got %d", len(uris))
	}
	for _, u := range uris[:2] {
		if strings.Contains(u, "q=1") || strings.Contains(u, "?") {
			t.Fatalf("baseline must not carry target query, got %q", u)
		}
	}
}

// Nil detector and nil response fail open (never suppress).
func TestDetectorNilFailsOpen(t *testing.T) {
	var d *soft404Detector
	if d.isSoft404(soft404Resp("x")) || d.soft404Score(soft404Resp("x")) != 0 {
		t.Fatal("nil detector must fail open")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "lost")
	}))
	defer srv.Close()
	d2 := newSoft404Detector(context.Background(), soft404Client(), srv.URL)
	if d2.isSoft404(nil) || d2.soft404Score(nil) != 0 {
		t.Fatal("nil response must fail open")
	}
}
