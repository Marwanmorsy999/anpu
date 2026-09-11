package active

import (
	"strings"
	"testing"
)

// Phase 1: the corroboration vocabulary must be stable — engines,
// dedup, and reports share these technique tags.
func TestCorroborationConstants(t *testing.T) {
	if SingleTechnique != "single-technique" || DisputedSources != "disputed-sources" {
		t.Fatal("technique tags changed — reports and dedup depend on them")
	}
}

func TestClassifyReflectionContext(t *testing.T) {
	marker := `<b id="anpucanary">`
	cases := []struct {
		name string
		body string
		want string
	}{
		{"element", `<html><body><p>hello ` + marker + ` world</p></body></html>`, CtxElementContent},
		{"attribute", `<html><body><input value="hello ` + marker + `"></body></html>`, CtxAttribute},
		{"script", `<html><script>var x="` + marker + `";</script></body></html>`, CtxScript},
		{"comment", `<html><!-- ` + marker + ` --><p>hi</p></html>`, CtxHTMLComment},
	}
	for _, c := range cases {
		if got := classifyReflectionContext(strings.ToLower(c.body), strings.ToLower(marker)); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
	if got := classifyReflectionContext("no marker here", strings.ToLower(marker)); got != CtxUnknown {
		t.Errorf("absent marker must be unknown, got %q", got)
	}
}

func TestIsExecutableContext(t *testing.T) {
	if !isExecutableContext(CtxElementContent) || !isExecutableContext(CtxAttribute) {
		t.Fatal("element/attribute must be executable")
	}
	if isExecutableContext(CtxScript) || isExecutableContext(CtxHTMLComment) || isExecutableContext(CtxUnknown) {
		t.Fatal("script/comment/unknown must not be executable")
	}
}

func TestSignalAbsentInBaseline(t *testing.T) {
	if !signalAbsentInBaseline("all quiet here", "sh:") {
		t.Fatal("absent signal must be true")
	}
	// Callers pass an already-lowercased baseline; the signal match
	// itself is case-insensitive.
	if signalAbsentInBaseline("sh: something failed", "SH:") {
		t.Fatal("present signal (case-insensitive) must be false")
	}
}

func TestSingleTechniqueBundle(t *testing.T) {
	b := singleTechniqueBundle("curl -s x", "GET", "https://example.com", 200, []string{"s"})
	if !b.NeedsReview || b.Technique != SingleTechnique || b.RequestURL != "https://example.com" {
		t.Fatalf("bundle wrong: %+v", b)
	}
}
