package dirs

import (
	"testing"

	"github.com/anpu-project/anpu/pkg/models"
)

func TestSimilarity(t *testing.T) {
	a := wordSet([]byte("the quick brown fox jumps over the lazy dog"))
	same := wordSet([]byte("the quick brown fox jumps over the lazy dog"))
	if got := similarity(a, same); got != 1.0 {
		t.Fatalf("identical sets: got %v, want 1.0", got)
	}

	shell := `<!DOCTYPE html> <html lang="en"> <head> <meta charset="utf-8">
	<meta name="viewport" content="width=device-width initial-scale=1">
	<title>Welcome to the Example Application Portal Home</title>
	<link rel="stylesheet" href="/assets/main.css"> <body> <div id="app">
	<header class="site-header">Example Application Portal</header>
	<nav><ul><li>Home</li><li>About</li><li>Contact</li><li>Pricing</li></ul></nav>
	<main class="content"><p>This is the main landing page content area
	with plenty of ordinary words that any application shell would render
	for its visitors on every request regardless of routing outcome.</p>
	<footer class="site-footer">Copyright Example All rights reserved</footer>`
	page1 := []byte(shell + `<script nonce="Abc123Def456Ghi789">window.__ROUTE="/x8y7z6"</script>`)
	page2 := []byte(shell + `<script nonce="Fff000Eee111Ddd222">window.__ROUTE="/qq9w8r7t"</script>`)
	if got := similarity(wordSet(page1), wordSet(page2)); got < 0.85 {
		t.Fatalf("near-identical shells with dynamic tokens: got %v, want >= 0.85", got)
	}

	different := wordSet([]byte("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7 secret_key database password"))
	if got := similarity(a, different); got > 0.3 {
		t.Fatalf("unrelated bodies: got %v, want <= 0.3", got)
	}

	empty := wordSet(nil)
	if got := similarity(a, empty); got != 0 {
		t.Fatalf("empty set: got %v, want 0", got)
	}
}

func TestWordSetIgnoresDigitsAndShortTokens(t *testing.T) {
	w := wordSet([]byte("ab 123 the x9y8z7 CONFIG-value_42"))
	for _, want := range []string{"the", "config", "value"} {
		if _, ok := w[want]; !ok {
			t.Errorf("word set missing %q (got %d entries)", want, len(w))
		}
	}
	for _, unwanted := range []string{"ab"} {
		if _, ok := w[unwanted]; ok {
			t.Errorf("word set should exclude short token %q", unwanted)
		}
	}
	if _, ok := w["123"]; ok {
		t.Error("digit-only tokens must be excluded")
	}
}

func TestRecordableStatus(t *testing.T) {
	cases := []struct {
		status int
		want   bool
	}{
		{200, true},
		{204, true},
		{206, true},
		{301, false},
		{302, false},
		{401, false},
		{403, false},
		{404, false},
		{406, false},
		{500, false},
	}
	for _, tc := range cases {
		if got := recordableStatus(tc.status); got != tc.want {
			t.Errorf("recordableStatus(%d) = %v, want %v", tc.status, got, tc.want)
		}
	}
}

func TestClassifySeverity(t *testing.T) {
	cases := []struct {
		class severityClass
		want  models.Severity
	}{
		{classCriticalExposure, models.SeverityHigh},
		{classServerInfo, models.SeverityMedium},
		{classAdmin, models.SeverityLow},
		{classInteresting, models.SeverityInfo},
	}
	for _, c := range cases {
		sev, _ := classify(c.class)
		if sev != c.want {
			t.Errorf("classify(%d) = %v, want %v", c.class, sev, c.want)
		}
	}
}
