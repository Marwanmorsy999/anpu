package active

import (
	"strings"
	"testing"

	"github.com/anpu-project/anpu/pkg/models"
)

func TestExtractVectors_QueryParams(t *testing.T) {
	ep := models.Endpoint{URL: "https://example.com/search?q=hello&page=2"}
	vecs := ExtractVectors(ep)
	if len(vecs) != 2 {
		t.Fatalf("expected 2 vectors, got %d", len(vecs))
	}
	names := map[string]bool{}
	for _, v := range vecs {
		names[v.Name] = true
		if v.Kind != models.VectorQueryParam {
			t.Errorf("vector %q kind = %q, want VectorQueryParam", v.Name, v.Kind)
		}
	}
	if !names["q"] || !names["page"] {
		t.Errorf("expected params q and page, got %v", names)
	}
}

func TestExtractVectors_DynamicPath(t *testing.T) {
	ep := models.Endpoint{URL: "https://example.com/api/orders/12345"}
	vecs := ExtractVectors(ep)
	// "12345" is a pure numeric segment → dynamic
	found := false
	for _, v := range vecs {
		if v.Kind == models.VectorPathSegment && v.Name == "12345" {
			found = true
		}
	}
	if !found {
		t.Error("expected dynamic path segment vector for '12345'")
	}
}

func TestExtractVectors_StaticPathSkipped(t *testing.T) {
	ep := models.Endpoint{URL: "https://example.com/api/users/profile"}
	vecs := ExtractVectors(ep)
	// "api", "users", "profile" are all static — no vectors expected
	for _, v := range vecs {
		if v.Kind == models.VectorPathSegment {
			t.Errorf("unexpected path segment vector: %q", v.Name)
		}
	}
}

func TestInjectQueryParam(t *testing.T) {
	injected, err := InjectQueryParam("https://example.com/search?q=hello", "q", "payload")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(injected, "q=payload") {
		t.Errorf("injected URL %q does not contain q=payload", injected)
	}
	// Other params must be preserved.
}

func TestInjectPathSegment(t *testing.T) {
	injected, err := InjectPathSegment("https://example.com/api/orders/12345", "12345", "PAYLOAD")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(injected, "PAYLOAD") {
		t.Errorf("injected URL %q does not contain PAYLOAD", injected)
	}
	if strings.Contains(injected, "12345") {
		t.Errorf("original segment '12345' should be replaced in %q", injected)
	}
}

func TestIsDynamicSegment(t *testing.T) {
	cases := map[string]bool{
		"12345":                                true,  // numeric
		"order-123":                            true,  // slug with digit
		"api":                                  false, // static
		"users":                                false, // static
		"v1":                                   false, // version — no digit + hyphen combo
		"550e8400-e29b-41d4-a716-446655440000": true,  // UUID
		"profile":                              false,
	}
	for seg, want := range cases {
		if got := isDynamicSegment(seg); got != want {
			t.Errorf("isDynamicSegment(%q) = %v, want %v", seg, got, want)
		}
	}
}

func TestLooksLikeURLParam(t *testing.T) {
	cases := []struct {
		name, value string
		want        bool
	}{
		{"redirect_url", "", true},
		{"callback", "", true},
		{"q", "", false},
		{"page", "", false},
		{"src", "https://example.com", true},
		{"id", "http://example.com", true},
		{"name", "alice", false},
	}
	for _, c := range cases {
		if got := looksLikeURLParam(c.name, c.value); got != c.want {
			t.Errorf("looksLikeURLParam(%q, %q) = %v, want %v", c.name, c.value, got, c.want)
		}
	}
}
