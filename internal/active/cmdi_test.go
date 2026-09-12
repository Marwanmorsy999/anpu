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

func cmdiVector(srv string) models.InputVector {
	return models.InputVector{URL: srv + "/?cmd=1", Kind: models.VectorQueryParam, Name: "cmd", OriginalValue: "1"}
}

func cmdiClient() *anpuhttp.Client {
	return anpuhttp.NewClientWithLocalNetworkAllowed(true)
}

// Phase 1: bare shell error strings are baseline-subtracted and capped
// at Medium + review — never Critical.
func TestCmdInjectionErrorCapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("cmd")
		if strings.ContainsAny(q, "|;`") {
			_, _ = w.Write([]byte("sh: syntax error near unexpected token"))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	res, _ := (&cmdInjectionRule{}).Test(context.Background(), cmdiClient(), cmdiVector(srv.URL))
	if !res.Found {
		t.Fatal("expected error-signal differential to be found")
	}
	if !strings.Contains(res.Evidence, "signal=error") {
		t.Fatalf("error path must be tagged signal=error: %q", res.Evidence)
	}
	f := (&cmdInjectionRule{}).ToFinding(res, srv.URL)
	if f.Severity != models.SeverityMedium {
		t.Fatalf("error strings must cap at Medium, got %s", f.Severity)
	}
	if f.Severity == models.SeverityCritical {
		t.Fatal("string matches must never be Critical")
	}
	if f.EvidenceBundle == nil || !f.EvidenceBundle.NeedsReview || f.EvidenceBundle.Technique != SingleTechnique {
		t.Fatalf("error path needs review bundle, got %+v", f.EvidenceBundle)
	}
}

// A canary marker differential (execution output, echo-guarded) earns High.
func TestCmdInjectionCanaryEarnsHigh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("cmd")
		if strings.Contains(q, "echo ") {
			// Simulated command output: canary WITHOUT the metacharacters.
			_, _ = w.Write([]byte("anpu-cmdi-canary"))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	res, _ := (&cmdInjectionRule{}).Test(context.Background(), cmdiClient(), cmdiVector(srv.URL))
	if !res.Found {
		t.Fatal("expected canary marker to be found")
	}
	if !strings.Contains(res.Evidence, "marker=canary") {
		t.Fatalf("canary path must be tagged marker=canary: %q", res.Evidence)
	}
	f := (&cmdInjectionRule{}).ToFinding(res, srv.URL)
	if f.Severity != models.SeverityHigh {
		t.Fatalf("canary marker must earn High, got %s", f.Severity)
	}
}

// Verbatim echo of the full payload is input reflection, not execution.
func TestCmdInjectionEchoGuard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("you sent: " + r.URL.Query().Get("cmd")))
	}))
	defer srv.Close()
	res, _ := (&cmdInjectionRule{}).Test(context.Background(), cmdiClient(), cmdiVector(srv.URL))
	if res.Found {
		t.Fatalf("verbatim echo must not be a finding: %q", res.Evidence)
	}
}

// Phase 3: ultra second family — the same error class from a
// different metacharacter family clears review and raises confidence.
func TestCmdInjectionUltraSecondFamily(t *testing.T) {
	SetUltraConfirm(true)
	defer SetUltraConfirm(false)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("cmd")
		if strings.ContainsAny(q, "|;`") {
			_, _ = w.Write([]byte("sh: syntax error near unexpected token"))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	res, _ := (&cmdInjectionRule{}).Test(context.Background(), cmdiClient(), cmdiVector(srv.URL))
	if !res.Found {
		t.Fatal("expected error-signal differential to be found")
	}
	if !strings.Contains(res.Evidence, "ultra second-family") {
		t.Fatalf("ultra must confirm second family: %q", res.Evidence)
	}
	if res.RequestsMade > 5 {
		t.Fatalf("ultra cmdi must fit budget 5, used %d", res.RequestsMade)
	}
	f := (&cmdInjectionRule{}).ToFinding(res, srv.URL)
	if f.Severity != models.SeverityMedium || f.Confidence != models.ConfidenceMedium {
		t.Fatalf("ultra-confirmed error path must be Medium/Medium, got %s/%s", f.Severity, f.Confidence)
	}
	if f.EvidenceBundle != nil {
		t.Fatalf("ultra confirmation must clear review bundle, got %+v", f.EvidenceBundle)
	}
}

// Phase 3: a single-family error signal stays capped even in ultra.
func TestCmdInjectionUltraSingleFamilyStaysCapped(t *testing.T) {
	SetUltraConfirm(true)
	defer SetUltraConfirm(false)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("cmd")
		// Only pipe-family payloads trigger; ';' and backtick do not.
		if strings.Contains(q, "|") {
			_, _ = w.Write([]byte("sh: syntax error near unexpected token"))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	res, _ := (&cmdInjectionRule{}).Test(context.Background(), cmdiClient(), cmdiVector(srv.URL))
	if !res.Found {
		t.Fatal("expected error-signal differential to be found")
	}
	if strings.Contains(res.Evidence, "ultra second-family") {
		t.Fatalf("must not claim unobserved family: %q", res.Evidence)
	}
	f := (&cmdInjectionRule{}).ToFinding(res, srv.URL)
	if f.Severity != models.SeverityMedium || f.Confidence != models.ConfidenceLow {
		t.Fatalf("must stay Medium/Low + review, got %s/%s", f.Severity, f.Confidence)
	}
	if f.EvidenceBundle == nil || !f.EvidenceBundle.NeedsReview {
		t.Fatal("single family must keep review bundle")
	}
}

// Pre-existing error text is page chrome, not proof.
func TestCmdInjectionBaselineSubtract(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("sh: this page always mentions shells"))
	}))
	defer srv.Close()
	res, _ := (&cmdInjectionRule{}).Test(context.Background(), cmdiClient(), cmdiVector(srv.URL))
	if res.Found {
		t.Fatalf("baseline-present signal must be subtracted: %q", res.Evidence)
	}
}
