// Package deps detects known-vulnerable third-party JavaScript library
// versions from data already collected by earlier pipeline stages.
//
// Two sources are checked — no extra HTTP requests are made:
//
//  1. sc.Technologies — version strings extracted by the technology detector
//     from HTTP headers or page content.
//
//  2. sc.Endpoints — asset URLs (.js) whose filenames embed a version string
//     (e.g. "jquery-3.4.1.min.js"). These are matched with a small set of
//     per-library regex patterns.
//
// Both sources are checked against a built-in vulnerability table. The table
// covers the JS libraries most commonly found on web surfaces and the CVEs
// that are most widely exploited or carry CVSS ≥ 6.0. It is intentionally
// compact; a future phase can replace it with an OSV/NVD feed.
package deps

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// vulnEntry describes a known-vulnerable version range for a library.
type vulnEntry struct {
	// Library is the Technology.Name to match (case-insensitive).
	Library string
	// AffectedBelow is the first fixed version; any version below this is
	// considered vulnerable. Empty means "all known versions".
	AffectedBelow string
	// AffectedFrom optionally constrains the lower bound (inclusive).
	// Empty means "any version up to AffectedBelow".
	AffectedFrom string
	CVE          string
	CVSS         string // e.g. "6.1"
	Severity     models.Severity
	Summary      string
	Fix          string
	Ref          string
}

// vulnTable is the built-in advisory list.
// Entries are ordered: highest severity first, then alphabetically by library.
// ponytail: static table, update when a new critical advisory ships.
var vulnTable = []vulnEntry{
	// jQuery — prototype pollution / XSS
	{"jQuery", "3.5.0", "1.0.0", "CVE-2019-11358", "6.1", models.SeverityMedium,
		"Prototype pollution via jQuery.extend(true, ...)", "Upgrade to jQuery ≥ 3.5.0",
		"https://nvd.nist.gov/vuln/detail/CVE-2019-11358"},
	{"jQuery", "3.5.0", "1.0.0", "CVE-2020-11022", "6.1", models.SeverityMedium,
		"XSS via HTML passed to jQuery manipulation methods when using cross-origin content", "Upgrade to jQuery ≥ 3.5.0",
		"https://nvd.nist.gov/vuln/detail/CVE-2020-11022"},
	{"jQuery", "3.5.0", "1.0.0", "CVE-2020-11023", "6.1", models.SeverityMedium,
		"XSS via <option> HTML passed to jQuery manipulation methods", "Upgrade to jQuery ≥ 3.5.0",
		"https://nvd.nist.gov/vuln/detail/CVE-2020-11023"},
	// jQuery UI
	{"jQuery UI", "1.13.0", "1.0.0", "CVE-2021-41184", "6.1", models.SeverityMedium,
		"XSS in the 'of' option of the .position() widget", "Upgrade to jQuery UI ≥ 1.13.0",
		"https://nvd.nist.gov/vuln/detail/CVE-2021-41184"},
	{"jQuery UI", "1.13.2", "1.0.0", "CVE-2022-31160", "6.1", models.SeverityMedium,
		"XSS via the 'altField' option of the Datepicker widget", "Upgrade to jQuery UI ≥ 1.13.2",
		"https://nvd.nist.gov/vuln/detail/CVE-2022-31160"},
	// Bootstrap
	{"Bootstrap", "3.4.0", "3.0.0", "CVE-2018-14040", "6.1", models.SeverityMedium,
		"XSS via the collapse data-parent attribute", "Upgrade Bootstrap 3.x to ≥ 3.4.0",
		"https://nvd.nist.gov/vuln/detail/CVE-2018-14040"},
	{"Bootstrap", "4.3.1", "4.0.0", "CVE-2019-8331", "6.1", models.SeverityMedium,
		"XSS in the tooltip or popover data-template attribute", "Upgrade Bootstrap 4.x to ≥ 4.3.1",
		"https://nvd.nist.gov/vuln/detail/CVE-2019-8331"},
	// lodash
	{"lodash", "4.17.21", "1.0.0", "CVE-2021-23337", "7.2", models.SeverityHigh,
		"Command injection via lodash.template with sourceURL", "Upgrade to lodash ≥ 4.17.21",
		"https://nvd.nist.gov/vuln/detail/CVE-2021-23337"},
	{"lodash", "4.17.21", "1.0.0", "CVE-2020-28500", "6.5", models.SeverityMedium,
		"ReDoS via crafted string to trim methods", "Upgrade to lodash ≥ 4.17.21",
		"https://nvd.nist.gov/vuln/detail/CVE-2020-28500"},
	// moment.js
	{"moment", "2.29.4", "1.0.0", "CVE-2022-24785", "7.5", models.SeverityHigh,
		"Path traversal in moment.locale() with attacker-controlled locale", "Upgrade to moment ≥ 2.29.4",
		"https://nvd.nist.gov/vuln/detail/CVE-2022-24785"},
	{"moment", "2.29.2", "1.0.0", "CVE-2022-31129", "7.5", models.SeverityHigh,
		"ReDoS via crafted date string passed to rfc2822 parser", "Upgrade to moment ≥ 2.29.2",
		"https://nvd.nist.gov/vuln/detail/CVE-2022-31129"},
	// Handlebars
	{"Handlebars", "4.7.7", "1.0.0", "CVE-2021-23369", "9.8", models.SeverityCritical,
		"Remote code execution via prototype pollution in Handlebars.compile()", "Upgrade to Handlebars ≥ 4.7.7",
		"https://nvd.nist.gov/vuln/detail/CVE-2021-23369"},
	// highlight.js
	{"highlight.js", "10.7.1", "9.0.0", "CVE-2021-23346", "5.3", models.SeverityLow,
		"ReDoS via specially crafted CSS value", "Upgrade to highlight.js ≥ 10.7.1",
		"https://nvd.nist.gov/vuln/detail/CVE-2021-23346"},
}

// urlVersionPatterns extracts (libraryName, version) from a JS asset URL.
// Covers the most common CDN and local filename conventions.
var urlVersionPatterns = []struct {
	Library string
	Pattern *regexp.Regexp
}{
	{"jQuery", regexp.MustCompile(`(?i)jquery[/\-_](\d+\.\d+\.?\d*)(\.min)?\.js`)},
	{"jQuery UI", regexp.MustCompile(`(?i)jquery[.\-_]ui[/\-_](\d+\.\d+\.?\d*)(\.min)?\.js`)},
	{"Bootstrap", regexp.MustCompile(`(?i)bootstrap[/\-_](\d+\.\d+\.?\d*)(\.min)?\.js`)},
	{"lodash", regexp.MustCompile(`(?i)lodash[/\-_](\d+\.\d+\.?\d*)(\.min)?\.js`)},
	{"moment", regexp.MustCompile(`(?i)moment[/\-_](\d+\.\d+\.?\d*)(\.min)?\.js`)},
	{"Handlebars", regexp.MustCompile(`(?i)handlebars[/\-_](\d+\.\d+\.?\d*)(\.min)?\.js`)},
	{"highlight.js", regexp.MustCompile(`(?i)highlight[/\-_](\d+\.\d+\.?\d*)(\.min)?\.js`)},
}

// Scanner is the pipeline stage for dependency vulnerability detection.
type Scanner struct{}

func New() *Scanner                                 { return &Scanner{} }
func (s *Scanner) Name() string                     { return "deps-scanner" }
func (s *Scanner) Available(_ context.Context) bool { return true }

// Run checks known-vulnerable library versions against both sc.Technologies
// and JS asset URLs already in sc.Endpoints.
func (s *Scanner) Run(_ context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	// Collect (library → version) from both sources. Later entries overwrite
	// earlier ones only if they carry a version; versionless detections are
	// kept as a fallback so we can still produce an advisory.
	type detection struct {
		version  string
		evidence string
	}
	seen := map[string]detection{}

	// Source 1: technology detector results.
	for _, t := range sc.Technologies {
		name := canonical(t.Name)
		if _, ok := seen[name]; !ok || (seen[name].version == "" && t.Version != "") {
			seen[name] = detection{
				version:  t.Version,
				evidence: t.Evidence.Observed,
			}
		}
	}

	// Source 2: JS asset URLs — extract version from the filename.
	for _, ep := range sc.Endpoints {
		if ep.Category != models.EndpointAsset {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(ep.URL), ".js") {
			continue
		}
		for _, p := range urlVersionPatterns {
			m := p.Pattern.FindStringSubmatch(ep.URL)
			if len(m) < 2 {
				continue
			}
			ver := m[1]
			name := canonical(p.Library)
			existing := seen[name]
			if existing.version == "" {
				seen[name] = detection{
					version:  ver,
					evidence: fmt.Sprintf("version %s detected in asset URL: %s", ver, ep.URL),
				}
			}
		}
	}

	var findings []models.Finding
	for lib, det := range seen {
		matching := advisoriesFor(lib, det.version)
		for _, vuln := range matching {
			findings = append(findings, toFinding(vuln, det.version, det.evidence, sc.Target.Raw))
		}
	}

	return scanner.StageResult{Findings: findings}, nil
}

// advisoriesFor returns all vuln entries that apply to the given library and
// version. If version is empty, no findings are emitted — we can't be sure.
func advisoriesFor(lib, version string) []vulnEntry {
	if version == "" {
		return nil
	}
	var out []vulnEntry
	for _, v := range vulnTable {
		if canonical(v.Library) != lib {
			continue
		}
		if versionInRange(version, v.AffectedFrom, v.AffectedBelow) {
			out = append(out, v)
		}
	}
	return out
}

// canonical lowercases and strips non-alphanumeric for loose matching
// ("jQuery" == "jquery", "jQuery UI" == "jquery ui").
func canonical(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// versionInRange returns true when version >= from (if set) and < below.
func versionInRange(version, from, below string) bool {
	if below != "" && compareVersions(version, below) >= 0 {
		return false // already patched
	}
	if from != "" && compareVersions(version, from) < 0 {
		return false // too old to be in this range (different major)
	}
	return true
}

// compareVersions compares dot-separated version strings.
// Returns -1, 0, or 1 like strings.Compare.
func compareVersions(a, b string) int {
	partsA := splitVersion(a)
	partsB := splitVersion(b)
	max := len(partsA)
	if len(partsB) > max {
		max = len(partsB)
	}
	for i := 0; i < max; i++ {
		na := partAt(partsA, i)
		nb := partAt(partsB, i)
		if na < nb {
			return -1
		}
		if na > nb {
			return 1
		}
	}
	return 0
}

func splitVersion(v string) []string {
	// Strip any non-numeric suffix (e.g. "4.17.21-0")
	v = strings.Split(v, "-")[0]
	return strings.Split(v, ".")
}

func partAt(parts []string, i int) int {
	if i >= len(parts) {
		return 0
	}
	n := 0
	for _, c := range parts[i] {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func toFinding(v vulnEntry, detectedVersion, evidence, target string) models.Finding {
	desc := fmt.Sprintf(
		"%s version %s is affected by %s (CVSS %s): %s. %s.",
		v.Library, detectedVersion, v.CVE, v.CVSS, v.Summary, v.Fix,
	)
	return models.Finding{
		ID:              fmt.Sprintf("dep-%s-%d", strings.ToLower(v.CVE), time.Now().UnixNano()),
		Title:           fmt.Sprintf("Vulnerable dependency: %s %s (%s)", v.Library, detectedVersion, v.CVE),
		Description:     desc,
		Severity:        v.Severity,
		Confidence:      models.ConfidenceHigh, // version is detected directly from URL or header
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-1395",
		OWASP:           "A06:2021 - Vulnerable and Outdated Components",
		Target:          target,
		Source:          models.SourceDeps,
		DetectionMethod: fmt.Sprintf("version %s detected; matched against built-in advisory table", detectedVersion),
		Evidence: models.Evidence{
			Observed: evidence,
		},
		Impact:      fmt.Sprintf("Attackers can exploit %s against users of this site. CVSS score: %s.", v.CVE, v.CVSS),
		Remediation: v.Fix,
		References:  []string{v.Ref, "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"},
		FirstSeen:   time.Now(),
	}
}
