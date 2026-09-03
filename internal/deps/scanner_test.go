package deps

import (
	"testing"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"3.4.1", "3.5.0", -1},
		{"3.5.0", "3.5.0", 0},
		{"3.6.0", "3.5.0", 1},
		{"1.12.4", "2.0.0", -1},
		{"4.17.21", "4.17.21", 0},
		{"4.17.20", "4.17.21", -1},
		{"4.17.22", "4.17.21", 1},
		{"3.5", "3.5.0", 0},    // short form equals three-part
		{"10.0.0", "9.9.9", 1}, // double-digit major
	}
	for _, tc := range cases {
		got := compareVersions(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestVersionInRange(t *testing.T) {
	// jQuery CVE-2019-11358: affected 1.0.0–3.4.x, fixed in 3.5.0
	if !versionInRange("3.4.1", "1.0.0", "3.5.0") {
		t.Error("3.4.1 should be in range [1.0.0, 3.5.0)")
	}
	if versionInRange("3.5.0", "1.0.0", "3.5.0") {
		t.Error("3.5.0 should NOT be in range (it is the fix)")
	}
	if versionInRange("3.6.0", "1.0.0", "3.5.0") {
		t.Error("3.6.0 should NOT be in range (patched version)")
	}
	if versionInRange("0.9.0", "1.0.0", "3.5.0") {
		t.Error("0.9.0 should NOT be in range (below AffectedFrom)")
	}
}

func TestAdvisoriesFor(t *testing.T) {
	// Vulnerable jQuery
	advisories := advisoriesFor("jquery", "3.4.1")
	if len(advisories) == 0 {
		t.Error("expected advisories for jquery 3.4.1")
	}
	for _, a := range advisories {
		if a.CVE == "" {
			t.Error("advisory missing CVE")
		}
	}

	// Patched jQuery
	advisories = advisoriesFor("jquery", "3.5.0")
	if len(advisories) != 0 {
		t.Errorf("expected no advisories for jquery 3.5.0, got %d", len(advisories))
	}

	// Unknown library
	advisories = advisoriesFor("some-unknown-lib", "1.0.0")
	if len(advisories) != 0 {
		t.Error("expected no advisories for unknown library")
	}

	// Empty version — should never match
	advisories = advisoriesFor("jquery", "")
	if len(advisories) != 0 {
		t.Error("expected no advisories when version is empty")
	}

	// Vulnerable lodash
	advisories = advisoriesFor("lodash", "4.17.20")
	if len(advisories) == 0 {
		t.Error("expected advisories for lodash 4.17.20")
	}
}

func TestURLVersionPatterns(t *testing.T) {
	cases := []struct {
		url     string
		library string
		version string
	}{
		{"https://example.com/js/jquery-3.4.1.min.js", "jQuery", "3.4.1"},
		{"https://cdn.example.com/jquery-3.6.0.js", "jQuery", "3.6.0"},
		{"https://example.com/assets/bootstrap-4.2.1.min.js", "Bootstrap", "4.2.1"},
		{"https://example.com/lodash-4.17.20.min.js", "lodash", "4.17.20"},
		{"https://example.com/moment-2.29.1.js", "moment", "2.29.1"},
	}
	for _, tc := range cases {
		found := false
		for _, p := range urlVersionPatterns {
			if canonical(p.Library) != canonical(tc.library) {
				continue
			}
			m := p.Pattern.FindStringSubmatch(tc.url)
			if len(m) >= 2 && m[1] == tc.version {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("URL %q: expected to extract %s version %s", tc.url, tc.library, tc.version)
		}
	}
}
