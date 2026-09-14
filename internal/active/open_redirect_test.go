package active

import (
	"context"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

func redirectVector(srv string) models.InputVector {
	return models.InputVector{URL: srv + "/go?url=x", Kind: models.VectorQueryParam, Name: "url", OriginalValue: "x"}
}

// The open-redirect rule must observe the 3xx+Location itself: the
// following client chases the (deliberately unresolvable) canary domain
// and the signal never survives. Regression test for the benchmark
// finding that redirectpack caught what this rule silently missed.
func TestOpenRedirectFiresOnCanary(t *testing.T) {
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
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := anpuhttp.NewClientWithLocalNetworkAllowed(true)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r := &openRedirectRule{}
	res, err := r.Test(ctx, client, redirectVector(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Found {
		t.Fatal("open redirect to canary domain must be found")
	}
	if !strings.Contains(res.Evidence, "anpu-redirect-canary.invalid") {
		t.Fatalf("evidence must cite the canary domain: %q", res.Evidence)
	}
	f := r.ToFinding(res, srv.URL)
	if f.Category != models.CategoryVulnerability || f.Confidence != models.ConfidenceHigh {
		t.Fatalf("finding must stay Medium/High-contract: %+v", f)
	}
}
