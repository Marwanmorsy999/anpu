package dirs

import (
	"os"
	"path/filepath"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", name))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return data
}

// Phase 0: same SPA shell with rotated hash/nonce must match after
// normalization; a genuinely different page must not.
func TestSimilarityShellVsDifferent(t *testing.T) {
	a := wordSet(fixture(t, "soft404-baseline-a.html"))
	b := wordSet(fixture(t, "soft404-baseline-b.html"))
	d := wordSet(fixture(t, "soft404-different.html"))
	if got := similarity(a, b); got < 0.80 {
		t.Fatalf("same shell must match >=0.80, got %.2f", got)
	}
	if got := similarity(a, d); got >= 0.80 {
		t.Fatalf("different page must not match, got %.2f", got)
	}
}

func TestSimilarityEmptyIsZero(t *testing.T) {
	if similarity(nil, wordSet([]byte("abc def ghi"))) != 0 {
		t.Fatal("empty set must be 0")
	}
}

func TestNormalizeBodyStripsHighEntropy(t *testing.T) {
	// The class includes hyphen, so a single long token is removed whole.
	if string(normalizeBody([]byte("app-ABCDEF1234567890abcdef"))) != "" {
		t.Fatalf("long token not stripped: %q", normalizeBody([]byte("app-ABCDEF1234567890abcdef")))
	}
	if string(normalizeBody([]byte("hello world"))) != "hello world" {
		t.Fatalf("short words must survive: %q", normalizeBody([]byte("hello world")))
	}
	if normHash([]byte("a")) == normHash([]byte("b")) {
		t.Fatal("distinct bodies must hash differently")
	}
}

func TestExpectsDataFileAndHTML(t *testing.T) {
	if !expectsDataFile("/.env.txt") || expectsDataFile("/") {
		t.Fatal("expectsDataFile wrong")
	}
	if !isHTMLContent("text/html; charset=utf-8") || isHTMLContent("application/json") {
		t.Fatal("isHTMLContent wrong")
	}
}
