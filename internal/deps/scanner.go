// Package deps detects known-vulnerable third-party JavaScript library
// versions from data already collected by earlier pipeline stages.
//
// Three sources are checked:
//
//  1. sc.Technologies — version strings extracted by the technology detector
//     from HTTP headers or page content (no extra requests).
//
//  2. sc.Endpoints — asset URLs (.js) whose filenames embed a version string
//     (e.g. "jquery-3.4.1.min.js"). These are matched with a small set of
//     per-library regex patterns (no extra requests).
//
//  3. Manifests (Master P2, opt-in via NewWithClient) — requirements.txt,
//     package.json, pom.xml, and go.mod discovered by the crawler are
//     fetched (max 3 per scan) and parsed for pinned versions across
//     npm/PyPI/Maven/Go ecosystems.
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

	anpuhttp "github.com/anpu-project/anpu/internal/http"
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
	// ---- web servers (Server header version disclosure → CVE) ----
	{"nginx", "1.25.3", "1.0.0", "CVE-2023-44487", "7.5", models.SeverityHigh,
		"HTTP/2 Rapid Reset — unauthenticated DoS via stream multiplexing", "Upgrade to nginx ≥ 1.25.3 (or apply vendor patch)",
		"https://nvd.nist.gov/vuln/detail/CVE-2023-44487"},
	{"nginx", "1.20.1", "1.0.0", "CVE-2021-23017", "7.5", models.SeverityHigh,
		"DNS resolver off-by-one heap write via crafted UDP response", "Upgrade to nginx ≥ 1.20.1",
		"https://nvd.nist.gov/vuln/detail/CVE-2021-23017"},
	{"Apache", "2.4.58", "2.4.0", "CVE-2023-25690", "9.8", models.SeverityCritical,
		"HTTP request smuggling via mod_proxy_ajp", "Upgrade Apache to ≥ 2.4.58",
		"https://nvd.nist.gov/vuln/detail/CVE-2023-25690"},
	{"Apache", "2.4.59", "2.4.0", "CVE-2024-38476", "9.8", models.SeverityCritical,
		"Apache HTTP Server proxy encoding bypass → RCE/SSRF", "Upgrade Apache to ≥ 2.4.59",
		"https://nvd.nist.gov/vuln/detail/CVE-2024-38476"},
	{"Apache", "2.4.56", "2.4.0", "CVE-2023-27522", "7.5", models.SeverityHigh,
		"mod_proxy_uwsgi HTTP response smuggling", "Upgrade Apache to ≥ 2.4.56",
		"https://nvd.nist.gov/vuln/detail/CVE-2023-27522"},
	// Alias: technology detector sometimes reports "Apache httpd"
	{"Apache httpd", "2.4.58", "2.4.0", "CVE-2023-25690", "9.8", models.SeverityCritical,
		"HTTP request smuggling via mod_proxy_ajp (alias)", "Upgrade Apache to ≥ 2.4.58",
		"https://nvd.nist.gov/vuln/detail/CVE-2023-25690"},
	{"Apache httpd", "2.4.59", "2.4.0", "CVE-2024-38476", "9.8", models.SeverityCritical,
		"Apache HTTP Server proxy encoding bypass (alias)", "Upgrade Apache to ≥ 2.4.59",
		"https://nvd.nist.gov/vuln/detail/CVE-2024-38476"},
	{"IIS", "10.0", "6.0", "CVE-2017-7269", "9.8", models.SeverityCritical,
		"Buffer overflow in IIS WebDAV (ScStoragePathFromUrl) — RCE", "Upgrade IIS and disable WebDAV if unused",
		"https://nvd.nist.gov/vuln/detail/CVE-2017-7269"},
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
// An optional HTTP client (NewWithClient) enables manifest harvesting
// (requirements.txt / package.json / pom.xml / go.mod); without it the
// scanner stays fully passive on already-collected data.
type Scanner struct {
	client *anpuhttp.Client
}

func New() *Scanner { return &Scanner{} }

// NewWithClient returns a Scanner that also harvests dependency manifests
// discovered by the crawler (bounded: 3 fetches, silent on failure).
func NewWithClient(c *anpuhttp.Client) *Scanner {
	return &Scanner{client: c}
}

func (s *Scanner) Name() string                     { return "deps-scanner" }
func (s *Scanner) Available(_ context.Context) bool { return true }

// Run checks known-vulnerable library versions against both sc.Technologies
// and JS asset URLs already in sc.Endpoints. Detections hit the built-in
// advisory table first, then anything with a version is looked up live
// against OSV.dev (free, keyless, one batched request) for advisories
// newer than the table.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
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
	staticCVEs := map[string]map[string]bool{}
	for lib, det := range seen {
		matching := advisoriesFor(lib, det.version)
		if len(matching) > 0 && staticCVEs[lib] == nil {
			staticCVEs[lib] = map[string]bool{}
		}
		for _, vuln := range matching {
			staticCVEs[lib][strings.ToUpper(vuln.CVE)] = true
			findings = append(findings, toFinding(vuln, det.version, det.evidence, sc.Target.Raw))
		}
	}

	// Master: harvest requirements.txt / package.json / pom.xml / go.mod
	// endpoints discovered via crawler (bounded fetches, silent on failure).
	// Runs before package resolution so manifest versions join the same
	// batch as tech/asset detections.
	if s.client != nil {
		var manifestURLs []string
		for _, ep := range sc.Endpoints {
			if manifestKind(ep.URL) != "" {
				manifestURLs = append(manifestURLs, ep.URL)
			}
		}
		for _, dep := range harvestManifests(ctx, s.client, manifestURLs) {
			lib := canonical(dep.name)
			if existing, ok := seen[lib]; !ok || existing.version == "" {
				seen[lib] = detection{
					version:  dep.version,
					evidence: fmt.Sprintf("version %s detected in manifest for %s", dep.version, dep.name),
				}
			}
		}
	}

	// Live OSV.dev lookup for versioned detections across ecosystems (Master: pypi/maven/go via
	// requirements.txt/pom.xml parsing osv.go:24 ecosystem PyPI same batch 20 cap 150 sort before cap).
	// Single batch + up to 10 detail hydrations, silent on failure so offline scans keep working.
	var pkgs []osvPackage
	for lib, det := range seen {
		if det.version == "" {
			continue
		}
		if pkg, ok := resolveManifestDep(lib, det.version); ok {
			pkgs = append(pkgs, pkg)
		}
	}
	osvResults, osvWarnings := queryOSV(ctx, pkgs)
	for lib, vulns := range osvResults {
		for _, v := range vulns {
			if f := osvFinding(osvPackage{display: lib, version: versionOf(pkgs, lib)}, v, staticCVEs[lib], sc.Target.Raw); f != nil {
				findings = append(findings, *f)
			}
		}
	}

	// SBOM: emit a CycloneDX inventory of every resolved package@version
	// into the report output dir (best-effort; warn, never fail).
	if len(pkgs) > 0 && strings.TrimSpace(sc.Config.OutputDir) != "" {
		if sbomPath, serr := writeSBOM(sc.Config.OutputDir, sc.Target.Raw, pkgs); serr != nil {
			osvWarnings = append(osvWarnings, fmt.Sprintf("deps: SBOM write failed: %v", serr))
		} else if sc.Verbose {
			osvWarnings = append(osvWarnings, fmt.Sprintf("deps: SBOM written to %s", sbomPath))
		}
	}

	return scanner.StageResult{Findings: findings, Warnings: osvWarnings}, nil
}

// versionOf returns the detected version for a display name.
func versionOf(pkgs []osvPackage, display string) string {
	for _, p := range pkgs {
		if p.display == display {
			return p.version
		}
	}
	return ""
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
