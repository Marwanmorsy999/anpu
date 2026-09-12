package scope

import (
	"testing"
)

func TestRedirectAliasApexToWWW(t *testing.T) {
	alias, ok := RedirectAlias("https://vondera.app", "https://www.vondera.app/")
	if !ok || alias != "www.vondera.app" {
		t.Fatalf("apex→www must expand, got %q,%v", alias, ok)
	}
}

func TestRedirectAliasRejects(t *testing.T) {
	cases := [][2]string{
		{"https://vondera.app", "https://vondera.app/home"},      // same host
		{"https://vondera.app", "https://evil.com/"},             // cross-domain
		{"https://vondera.app", "https://vondera.app.evil.com/"}, // lookalike suffix
		{"https://vondera.app", ""},                              // empty final
		{"", "https://www.vondera.app/"},                         // empty target
		{"https://a.example.co.uk", "https://b.other.co.uk/"},    // different base
	}
	for _, c := range cases {
		if alias, ok := RedirectAlias(c[0], c[1]); ok {
			t.Fatalf("RedirectAlias(%q,%q) must reject, got %q", c[0], c[1], alias)
		}
	}
}

func TestRedirectAliasCountryTLD(t *testing.T) {
	alias, ok := RedirectAlias("https://example.co.uk", "https://www.example.co.uk/")
	if !ok || alias != "www.example.co.uk" {
		t.Fatalf("co.uk apex→www must expand, got %q,%v", alias, ok)
	}
}
