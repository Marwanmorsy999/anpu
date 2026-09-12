package active

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

func xssVector(srv string) models.InputVector {
	return models.InputVector{URL: srv + "/?q=1", Kind: models.VectorQueryParam, Name: "q", OriginalValue: "1"}
}

func xssClient() *anpuhttp.Client {
	return anpuhttp.NewClientWithLocalNetworkAllowed(true)
}

// Phase 1: unescaped reflection in element content with clean baseline
// and control keeps High/Medium.
func TestXSSReflectKeepsHigh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body><p>hello " + r.URL.Query().Get("q") + "</p></body></html>"))
	}))
	defer srv.Close()
	res, err := (&xssRule{}).Test(context.Background(), xssClient(), xssVector(srv.URL))
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if !res.Found {
		t.Fatal("expected reflection to be found")
	}
	f := (&xssRule{}).ToFinding(res, srv.URL)
	if f.Severity != models.SeverityHigh || f.Confidence != models.ConfidenceMedium {
		t.Fatalf("executable context must stay High/Medium, got %s/%s", f.Severity, f.Confidence)
	}
	if f.EvidenceBundle != nil {
		t.Fatal("fully corroborated finding must not carry a review bundle")
	}
}

// Phase 3: ultra second family — both benign tags reflected unescaped
// earns High confidence.
func TestXSSUltraSecondFamily(t *testing.T) {
	SetUltraConfirm(true)
	defer SetUltraConfirm(false)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body><p>hello " + r.URL.Query().Get("q") + "</p></body></html>"))
	}))
	defer srv.Close()
	res, _ := (&xssRule{}).Test(context.Background(), xssClient(), xssVector(srv.URL))
	if !res.Found {
		t.Fatal("expected reflection to be found")
	}
	if !strings.Contains(res.Evidence, "ultra second-family") {
		t.Fatalf("ultra must confirm second family: %q", res.Evidence)
	}
	if res.RequestsMade > 4 {
		t.Fatalf("ultra XSS must fit budget 4, used %d", res.RequestsMade)
	}
	f := (&xssRule{}).ToFinding(res, srv.URL)
	if f.Severity != models.SeverityHigh || f.Confidence != models.ConfidenceHigh {
		t.Fatalf("ultra-confirmed must be High/High, got %s/%s", f.Severity, f.Confidence)
	}
}

// Phase 3: when the second family does not reflect, ultra degrades to
// the advanced claim instead of inventing corroboration.
func TestXSSUltraFamily2Absent(t *testing.T) {
	SetUltraConfirm(true)
	defer SetUltraConfirm(false)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("q")
		v = strings.ReplaceAll(v, "<u ", "<span ")
		_, _ = w.Write([]byte("<html><body><p>" + v + "</p></body></html>"))
	}))
	defer srv.Close()
	res, _ := (&xssRule{}).Test(context.Background(), xssClient(), xssVector(srv.URL))
	if !res.Found {
		t.Fatal("first family must still be found")
	}
	if strings.Contains(res.Evidence, "ultra second-family") {
		t.Fatalf("must not claim unobserved family: %q", res.Evidence)
	}
	f := (&xssRule{}).ToFinding(res, srv.URL)
	if f.Severity != models.SeverityHigh || f.Confidence != models.ConfidenceMedium {
		t.Fatalf("must degrade to High/Medium, got %s/%s", f.Severity, f.Confidence)
	}
}

// Escaped reflection must not be found at all.
func TestXSSEscapedNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := strings.ReplaceAll(r.URL.Query().Get("q"), "<", "&lt;")
		v = strings.ReplaceAll(v, ">", "&gt;")
		_, _ = w.Write([]byte("<html><body><p>" + v + "</p></body></html>"))
	}))
	defer srv.Close()
	res, _ := (&xssRule{}).Test(context.Background(), xssClient(), xssVector(srv.URL))
	if res.Found {
		t.Fatal("escaped reflection must not be found")
	}
}

// Reflection inside an HTML comment is capped at Medium + review.
func TestXSSCommentCapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><!-- " + r.URL.Query().Get("q") + " --><p>hi</p></html>"))
	}))
	defer srv.Close()
	res, _ := (&xssRule{}).Test(context.Background(), xssClient(), xssVector(srv.URL))
	if !res.Found {
		t.Fatal("comment reflection must still be found (capped, not dropped)")
	}
	if !strings.Contains(res.Evidence, SingleTechnique) {
		t.Fatalf("comment path must be single-technique: %q", res.Evidence)
	}
	f := (&xssRule{}).ToFinding(res, srv.URL)
	if f.Severity != models.SeverityMedium || f.EvidenceBundle == nil || !f.EvidenceBundle.NeedsReview {
		t.Fatalf("comment path must be Medium + review bundle, got %s %+v", f.Severity, f.EvidenceBundle)
	}
}
