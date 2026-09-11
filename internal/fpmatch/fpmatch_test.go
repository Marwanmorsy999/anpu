package fpmatch

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

// Phase 2: the shared primitive must reproduce the dirs reference
// behavior — same shell matches across nonce rotation, different
// pages do not.
func TestSimilarityShellMatrix(t *testing.T) {
	a := WordSet(fixture(t, "soft404-baseline-a.html"))
	b := WordSet(fixture(t, "soft404-baseline-b.html"))
	d := WordSet(fixture(t, "soft404-different.html"))
	if got := Similarity(a, b); got < CatchAllDetect {
		t.Fatalf("same shell must match at catch-all bar, got %.2f", got)
	}
	if got := Similarity(a, d); got >= ShellMatch {
		t.Fatalf("different page must not match at shell bar, got %.2f", got)
	}
	if Similarity(nil, a) != 0 {
		t.Fatal("empty set must score 0")
	}
}

func TestMatchesAndScoreTemplate(t *testing.T) {
	shell := NewTemplate(fixture(t, "soft404-baseline-a.html"))
	if !shell.Has {
		t.Fatal("template must be set")
	}
	if !MatchesTemplate(fixture(t, "soft404-baseline-b.html"), ShellMatch, shell) {
		t.Fatal("rotated shell must match template")
	}
	if MatchesTemplate(fixture(t, "soft404-different.html"), ShellMatch, shell) {
		t.Fatal("different page must not match template")
	}
	if ScoreTemplate(fixture(t, "soft404-baseline-a.html"), shell) != 1.0 {
		t.Fatal("identical body must score 1.0")
	}
	if ScoreTemplate(fixture(t, "soft404-different.html"), shell) >= ShellMatch {
		t.Fatal("different page must score below shell bar")
	}
	if MatchesTemplate([]byte("anything"), ShellMatch, Template{}) {
		t.Fatal("empty template must never match")
	}
}

func TestIsWAFBlockPage(t *testing.T) {
	if !IsWAFBlockPage(fixture(t, "waf-block.html")) {
		t.Fatal("WAF block fixture must be recognized")
	}
	if IsWAFBlockPage(fixture(t, "soft404-different.html")) {
		t.Fatal("normal invoice page must not be a WAF block")
	}
	if IsWAFBlockPage([]byte("<html><body>Please complete the captcha to continue</body></html>")) {
		t.Fatal("generic captcha text alone must not veto")
	}
}

func TestClassifyDenial(t *testing.T) {
	if ClassifyDenial(403, fixture(t, "waf-block.html")) != DenialWAF {
		t.Fatal("WAF 403 must be waf-block")
	}
	if ClassifyDenial(403, []byte("Forbidden")) != DenialApp {
		t.Fatal("bare 403 must be app-denied")
	}
	if ClassifyDenial(401, []byte("Unauthorized")) != DenialApp {
		t.Fatal("bare 401 must be app-denied")
	}
	if ClassifyDenial(404, []byte("not found")) != DenialOther {
		t.Fatal("404 must be other")
	}
	if ClassifyDenial(200, []byte("ok")) != DenialOther {
		t.Fatal("200 must be other")
	}
}

func TestIsCDNName(t *testing.T) {
	for _, n := range []string{"Cloudflare", "Amazon CloudFront", "Vercel", "Fastly", "AkamaiGHost", "Sucuri", "BunnyCDN"} {
		if !IsCDNName(n) {
			t.Errorf("%q must be a CDN name", n)
		}
	}
	for _, n := range []string{"Nginx", "Apache", "WordPress", "jQuery", ""} {
		if IsCDNName(n) {
			t.Errorf("%q must not be a CDN name", n)
		}
	}
}
