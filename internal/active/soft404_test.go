package active

import "testing"

// Phase 0: Jaccard similarity is the shared FP primitive; lock its
// behavior before Phase 2 unifies engines on it.
func TestSimilarityActiveIdenticalAndDisjoint(t *testing.T) {
	a := wordSetActive([]byte("alpha beta gamma delta"))
	if got := similarityActive(a, a); got != 1.0 {
		t.Fatalf("identical must be 1.0, got %.2f", got)
	}
	b := wordSetActive([]byte("one two three four five six"))
	if got := similarityActive(a, b); got != 0 {
		t.Fatalf("disjoint must be 0, got %.2f", got)
	}
	if similarityActive(nil, a) != 0 {
		t.Fatal("empty must be 0")
	}
}

func TestIsHTMLorJSON(t *testing.T) {
	for _, ct := range []string{"text/html", "application/json", "application/xhtml+xml; charset=utf-8"} {
		if !isHTMLorJSON(ct) {
			t.Fatalf("%q must qualify", ct)
		}
	}
	if isHTMLorJSON("image/png") || isHTMLorJSON("text/plain") {
		t.Fatal("non html/json must not qualify")
	}
}
