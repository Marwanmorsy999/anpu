package nosqlexpand

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

func testClient() *anpuhttp.Client {
	return anpuhttp.NewClientWithLocalNetworkAllowed(true)
}

func testContext(srv string) *scanner.ScanContext {
	u, _ := url.Parse(srv)
	host := ""
	if u != nil {
		host = u.Hostname()
	}
	return &scanner.ScanContext{Target: &scanner.ValidatedTarget{Raw: srv, URL: u, Host: host}}
}

// Raw differentials with no backend marker must stay LOW with the
// unconfirmed label — same-family probe count alone does not corroborate.
func TestRawDifferentialCappedAtLow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if len(q) > 0 && !q.Has("anpucontrolxyz") {
			_, _ = w.Write([]byte("hello DIFFERENT framework response"))
			return
		}
		_, _ = w.Write([]byte("hello baseline"))
	}))
	defer srv.Close()
	res, err := New(testClient()).Run(context.Background(), testContext(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected a differential finding")
	}
	f := res.Findings[0]
	if f.Severity != models.SeverityLow || f.Confidence != models.ConfidenceLow {
		t.Fatalf("raw differential must be Low/Low, got %s/%s", f.Severity, f.Confidence)
	}
	if !strings.Contains(f.Evidence.Observed, "unconfirmed differential, manual verification required") {
		t.Fatalf("must carry unconfirmed label, got %q", f.Evidence.Observed)
	}
	if !strings.Contains(f.Evidence.Observed, "probes:") {
		t.Fatalf("must carry per-probe verdicts, got %q", f.Evidence.Observed)
	}
}

// A backend error marker is the independent second signal → Medium.
func TestMarkerCorroborationEarnsMedium(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Has("anpune") {
			_, _ = w.Write([]byte("MongoError: bad operator"))
			return
		}
		if len(q) > 0 && !q.Has("anpucontrolxyz") {
			_, _ = w.Write([]byte("hello DIFFERENT"))
			return
		}
		_, _ = w.Write([]byte("hello baseline"))
	}))
	defer srv.Close()
	res, err := New(testClient()).Run(context.Background(), testContext(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected a differential finding")
	}
	f := res.Findings[0]
	if f.Severity != models.SeverityMedium || f.Confidence != models.ConfidenceMedium {
		t.Fatalf("marker-backed differential must be Medium/Medium, got %s/%s", f.Severity, f.Confidence)
	}
	if !strings.Contains(f.Evidence.Observed, "mongoerror") {
		t.Fatalf("must name the marker, got %q", f.Evidence.Observed)
	}
}
