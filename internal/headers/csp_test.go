package headers

import (
	"testing"

	"github.com/anpu-project/anpu/pkg/models"
)

// --- parser unit tests ---

func TestParseCSP_Directives(t *testing.T) {
	policy := "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.com; object-src 'none'"
	dm := directiveMap(parseCSP(policy))

	for _, want := range []string{"default-src", "script-src", "object-src"} {
		if _, ok := dm[want]; !ok {
			t.Errorf("expected directive %q", want)
		}
	}
	if !hasSource(dm["script-src"].sources, "'unsafe-inline'") {
		t.Error("expected 'unsafe-inline' in script-src")
	}
	if !hasSource(dm["object-src"].sources, "'none'") {
		t.Error("expected 'none' in object-src")
	}
}

func TestParseCSP_Empty(t *testing.T) {
	if len(parseCSP("")) != 0 {
		t.Error("expected 0 directives for empty policy")
	}
}

func TestEffectiveSources_Inherited(t *testing.T) {
	dm := directiveMap(parseCSP("default-src 'self' https://cdn.example.com"))
	srcs, explicit := effectiveSources(dm, "script-src")
	if explicit {
		t.Error("script-src should not be explicit when inherited from default-src")
	}
	if !hasSource(srcs, "'self'") {
		t.Error("expected 'self' inherited from default-src")
	}
}

func TestEffectiveSources_Explicit(t *testing.T) {
	dm := directiveMap(parseCSP("default-src 'self'; script-src https://cdn.example.com"))
	_, explicit := effectiveSources(dm, "script-src")
	if !explicit {
		t.Error("script-src should be explicit when directly set")
	}
}

func TestHasWildcard(t *testing.T) {
	cases := []struct {
		sources []string
		want    bool
	}{
		{[]string{"'self'", "*"}, true},
		{[]string{"'self'", "http:"}, true},
		{[]string{"'self'", "https:"}, true},
		{[]string{"'self'", "https://cdn.example.com"}, false},
		{[]string{"'none'"}, false},
	}
	for _, tc := range cases {
		if got := hasWildcard(tc.sources); got != tc.want {
			t.Errorf("hasWildcard(%v) = %v, want %v", tc.sources, got, tc.want)
		}
	}
}

// --- checkCSPQuality integration tests ---

type fakeHeader string

func (f fakeHeader) Get(_ string) string { return string(f) }

func cspFindings(policy string) []models.Finding {
	return checkCSPQuality(policy, "https://example.com", "https://example.com", fakeHeader(policy))
}

func TestCSPQuality_UnsafeInline(t *testing.T) {
	f := cspFindings("default-src 'self'; script-src 'self' 'unsafe-inline'")
	if !hasFindingID(f, "headers-csp-unsafe-inline") {
		t.Errorf("expected headers-csp-unsafe-inline, got %v", ids(f))
	}
}

func TestCSPQuality_UnsafeEval(t *testing.T) {
	f := cspFindings("default-src 'self'; script-src 'self' 'unsafe-eval'")
	if !hasFindingID(f, "headers-csp-unsafe-eval") {
		t.Errorf("expected headers-csp-unsafe-eval, got %v", ids(f))
	}
}

func TestCSPQuality_WildcardDefaultSrc(t *testing.T) {
	f := cspFindings("default-src *")
	if !hasFindingID(f, "headers-csp-wildcard-script-src") {
		t.Errorf("expected headers-csp-wildcard-script-src, got %v", ids(f))
	}
}

func TestCSPQuality_MissingObjectSrc(t *testing.T) {
	f := cspFindings("default-src 'self'; script-src 'self'")
	if !hasFindingID(f, "headers-csp-missing-object-src-none") {
		t.Errorf("expected headers-csp-missing-object-src-none, got %v", ids(f))
	}
}

func TestCSPQuality_MissingBaseURI(t *testing.T) {
	f := cspFindings("default-src 'self'; object-src 'none'")
	if !hasFindingID(f, "headers-csp-missing-base-uri") {
		t.Errorf("expected headers-csp-missing-base-uri, got %v", ids(f))
	}
}

func TestCSPQuality_MissingDefaultSrc(t *testing.T) {
	f := cspFindings("script-src 'self'; object-src 'none'; base-uri 'self'")
	if !hasFindingID(f, "headers-csp-missing-default-src") {
		t.Errorf("expected headers-csp-missing-default-src, got %v", ids(f))
	}
}

func TestCSPQuality_StrictPolicy_NoFindings(t *testing.T) {
	// A well-formed strict policy should produce no weak-policy findings.
	f := cspFindings("default-src 'self'; script-src 'self' 'nonce-abc123'; object-src 'none'; base-uri 'self'")
	for _, finding := range f {
		t.Errorf("strict policy produced unexpected finding: %s — %s", finding.ID, finding.Title)
	}
}

func TestCSPQuality_MultipleIssues(t *testing.T) {
	f := cspFindings("default-src * 'unsafe-inline' 'unsafe-eval'")
	if len(f) < 3 {
		t.Errorf("expected at least 3 findings for a very weak policy, got %d: %v", len(f), ids(f))
	}
}

func TestCSPQuality_ObjectSrcNoneSkipsFinding(t *testing.T) {
	f := cspFindings("default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'")
	if hasFindingID(f, "headers-csp-missing-object-src-none") {
		t.Error("should not emit missing-object-src-none when object-src 'none' is set")
	}
}

func ids(findings []models.Finding) []string {
	out := make([]string, len(findings))
	for i, f := range findings {
		out[i] = f.ID
	}
	return out
}
