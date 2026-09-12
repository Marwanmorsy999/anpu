package crawler

import (
	"net/url"
	"testing"
)

func mustBase(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

// Scope-expanded aliases (apex → www) crawl like the start host;
// everything else stays out.
func TestNormalizeURLScoped(t *testing.T) {
	base := mustBase(t, "https://vondera.app")
	extra := []string{"www.vondera.app"}
	for _, raw := range []string{
		"https://www.vondera.app/",
		"https://www.vondera.app/pricing",
		"https://vondera.app/blog",
	} {
		if _, ok := normalizeURLScoped(base, raw, extra); !ok {
			t.Fatalf("in-scope %q must be accepted", raw)
		}
	}
	for _, raw := range []string{
		"https://evil.com/",
		"https://blog.vondera.app/", // same base but not the observed alias
		"https://vondera.app.evil.com/",
		"ftp://www.vondera.app/",
	} {
		if _, ok := normalizeURLScoped(base, raw, extra); ok {
			t.Fatalf("out-of-scope %q must be rejected", raw)
		}
	}
}

// Without aliases the behavior is unchanged (exact host only).
func TestNormalizeURLLegacy(t *testing.T) {
	base := mustBase(t, "https://vondera.app")
	if _, ok := normalizeURL(base, "https://www.vondera.app/"); ok {
		t.Fatal("legacy normalize must reject www without aliases")
	}
	if _, ok := normalizeURL(base, "https://vondera.app/x"); !ok {
		t.Fatal("legacy normalize must accept the start host")
	}
}
