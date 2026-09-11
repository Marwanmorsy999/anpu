package main

import (
	"strings"
	"testing"

	"github.com/anpu-project/anpu/internal/storage"
	"github.com/anpu-project/anpu/pkg/models"
)

// Phase 5: query/history/show helpers are pure and pinned — the split
// data sources (DB vs report files) already caused one harness race;
// wrong filtering must never silently drop rows.
func TestQueryMatchFloors(t *testing.T) {
	f := models.Finding{Severity: models.SeverityHigh, Confidence: models.ConfidenceMedium,
		Category: models.CategoryVulnerability, ID: "a", Title: "XSS here", Description: "d", URL: "https://example.com/s"}
	if !queryMatch(f, "medium", "", "", "") {
		t.Fatal("high must pass medium floor")
	}
	if queryMatch(f, "critical", "", "", "") {
		t.Fatal("high must not pass critical floor")
	}
	if !queryMatch(f, "", "low", "vuln", "xss") {
		t.Fatal("matching conf/category/text must pass")
	}
	if queryMatch(f, "", "high", "", "") {
		t.Fatal("medium must not pass high confidence floor")
	}
	if queryMatch(f, "bogus", "", "", "") {
		t.Fatal("invalid severity floor must reject, not match-all")
	}
	if !queryMatch(f, "", "", "", "EXAMPLE.COM/S") {
		t.Fatal("text match must be case-insensitive")
	}
}

func TestNormalizeCompareTarget(t *testing.T) {
	a := normalizeCompareTarget("https://Example.com/")
	b := normalizeCompareTarget("https://example.com")
	c := normalizeCompareTarget("https://example.com:443/app/")
	d := normalizeCompareTarget("https://example.com/app")
	if a != b {
		t.Fatalf("trailing slash/case must normalize: %q vs %q", a, b)
	}
	if c != d {
		t.Fatalf("default port must normalize: %q vs %q", c, d)
	}
	if normalizeCompareTarget("https://example.com/App") == "https://example.com/app" {
		t.Fatal("path case must be preserved")
	}
	if normalizeCompareTarget("http://example.com:8080/") != "http://example.com:8080" {
		t.Fatal("non-default port must survive")
	}
}

func TestFilterFindingsBySeverity(t *testing.T) {
	fs := []models.Finding{
		{ID: "l", Severity: models.SeverityLow, Confidence: models.ConfidenceLow},
		{ID: "c", Severity: models.SeverityCritical, Confidence: models.ConfidenceHigh},
		{ID: "m", Severity: models.SeverityMedium, Confidence: models.ConfidenceMedium},
	}
	got := filterFindingsBySeverity(fs, "medium")
	if len(got) != 2 || got[0].ID != "c" || got[1].ID != "m" {
		t.Fatalf("must keep medium+ sorted critical-first, got %+v", got)
	}
	if got := filterFindingsBySeverity(fs, "bogus"); len(got) != 3 {
		t.Fatal("invalid floor must keep everything")
	}
	if got := filterFindingsBySeverity(fs, ""); len(got) != 3 {
		t.Fatal("empty floor must keep everything")
	}
}

func TestFilterScans(t *testing.T) {
	rows := []storage.ScanListItem{
		{ID: "1", Target: "https://example.com/app"},
		{ID: "2", Target: "https://other.org/"},
	}
	if got := filterScans(rows, "EXAMPLE"); len(got) != 1 || got[0].ID != "1" {
		t.Fatalf("target filter must be case-insensitive substring, got %+v", got)
	}
	if got := filterScans(rows, ""); len(got) != 2 {
		t.Fatal("empty filter must keep everything")
	}
	if got := filterScans(rows, "nomatch"); len(got) != 0 {
		t.Fatal("non-matching filter must yield nothing")
	}
}

func TestTruncateHelpers(t *testing.T) {
	if truncate("abcdef", 4) != "abc…" {
		t.Fatalf("truncate wrong: %q", truncate("abcdef", 4))
	}
	if truncateStr("abcdef", 10) != "abcdef" {
		t.Fatal("short strings must pass through")
	}
	if !strings.Contains(oneLineFinding("a\nb  c", 100), "a b c") {
		t.Fatal("oneLineFinding must collapse whitespace")
	}
}
