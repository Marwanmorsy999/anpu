package deps

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// osvBaseURL is the OSV.dev API endpoint (free, no key). Package var so
// tests can point it at a fixture server.
var osvBaseURL = "https://api.osv.dev"

// npmPackage maps a canonical ANPU library name to its npm package name.
// Only libraries with reliable npm naming are listed; servers and
// ambiguous names stay on the static table.
func npmPackage(canonicalName string) (string, bool) {
	switch canonicalName {
	case "jquery":
		return "jquery", true
	case "jquery ui":
		return "jquery-ui", true
	case "bootstrap":
		return "bootstrap", true
	case "lodash":
		return "lodash", true
	case "moment":
		return "moment", true
	case "handlebars":
		return "handlebars", true
	case "highlight.js":
		return "highlight.js", true
	case "axios":
		return "axios", true
	case "vue.js", "vue":
		return "vue", true
	case "react":
		return "react", true
	case "angular":
		return "@angular/core", true
	case "ember.js", "ember":
		return "ember-source", true
	case "chart.js":
		return "chart.js", true
	case "three.js", "three":
		return "three", true
	case "alpine.js", "alpine":
		return "alpinejs", true
	case "swiper":
		return "swiper", true
	default:
		return "", false
	}
}

// pypiPackage maps canonical names to PyPI packages (P2: Master deps expansion).
func pypiPackage(canonicalName string) (string, bool) {
	switch canonicalName {
	case "django":
		return "Django", true
	case "flask":
		return "Flask", true
	case "requests":
		return "requests", true
	case "numpy":
		return "numpy", true
	case "pillow":
		return "Pillow", true
	case "pyyaml":
		return "PyYAML", true
	default:
		return "", false
	}
}

// mavenPackage maps canonical names to Maven coordinates (group:artifact).
func mavenPackage(canonicalName string) (string, bool) {
	switch canonicalName {
	case "log4j", "log4j-core":
		return "org.apache.logging.log4j:log4j-core", true
	case "spring-core":
		return "org.springframework:spring-core", true
	case "jackson-databind":
		return "com.fasterxml.jackson.core:jackson-databind", true
	case "commons-text":
		return "org.apache.commons:commons-text", true
	default:
		return "", false
	}
}

// goPackage maps canonical names to Go module paths.
func goPackage(canonicalName string) (string, bool) {
	switch canonicalName {
	case "gin":
		return "github.com/gin-gonic/gin", true
	case "echo":
		return "github.com/labstack/echo", true
	case "gorilla/mux":
		return "github.com/gorilla/mux", true
	default:
		return "", false
	}
}

// cratesPackage maps canonical names to crates.io packages (Wave 3
// item 138: OSV Rust ecosystem).
func cratesPackage(canonicalName string) (string, bool) {
	switch canonicalName {
	case "serde", "tokio", "rand", "regex", "hyper", "reqwest",
		"actix-web", "rocket", "openssl", "log", "anyhow":
		return canonicalName, true
	default:
		return "", false
	}
}

// rubygemsPackage maps canonical names to RubyGems packages (Wave 3
// item 138: OSV RubyGems ecosystem).
func rubygemsPackage(canonicalName string) (string, bool) {
	switch canonicalName {
	case "rails", "nokogiri", "rack", "devise", "puma", "sidekiq",
		"sinatra", "jwt":
		return canonicalName, true
	default:
		return "", false
	}
}

// osvPackage is one detected package@version to look up.
type osvPackage struct {
	display   string // ANPU library name for finding titles
	npm       string // npm package name for the query
	ecosystem string // osv ecosystem: npm, PyPI, Maven, Go
	version   string
}

// osvVuln is the normalized subset of an OSV vulnerability record.
type osvVuln struct {
	id      string
	cve     string
	summary string
	score   float64
	fixed   string
}

// osvRawVuln is the wire subset shared by querybatch results and
// full /v1/vulns/{id} records.
type osvRawVuln struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

func parseOsvRawVuln(v osvRawVuln) osvVuln {
	ov := osvVuln{id: v.ID, summary: v.Summary}
	if ov.summary == "" {
		ov.summary = v.Details
	}
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			ov.cve = a
			break
		}
	}
	for _, s := range v.Severity {
		if strings.HasPrefix(s.Type, "CVSS") {
			if f, err := strconv.ParseFloat(s.Score, 64); err == nil && f > ov.score {
				ov.score = f
			}
		}
	}
outer:
	for _, a := range v.Affected {
		for _, rg := range a.Ranges {
			for _, ev := range rg.Events {
				if ev.Fixed != "" {
					ov.fixed = ev.Fixed
					break outer
				}
			}
		}
	}
	return ov
}

func (v osvRawVuln) hasDetails() bool {
	return len(v.Aliases) > 0 || v.Summary != "" || v.Details != "" || len(v.Severity) > 0 || len(v.Affected) > 0
}

// queryOSV looks up package versions against OSV.dev in a single
// batched request (free, keyless), then hydrates up to 10 IDs via
// GET /v1/vulns/{id} (8s total budget, sequential, fail-silent).
// Failure is silent — the static table still runs — so offline scans
// are unaffected. It returns findings grouped by display name plus any
// truncation warnings.
func queryOSV(ctx context.Context, pkgs []osvPackage) (map[string][]osvVuln, []string) {
	out := map[string][]osvVuln{}
	var warnings []string
	if len(pkgs) == 0 {
		return out, nil
	}
	// Deterministic order before cap (Master: 150 sorted before cap, same batch 20 style).
	sorted := append([]osvPackage(nil), pkgs...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].ecosystem != sorted[j].ecosystem {
			return sorted[i].ecosystem < sorted[j].ecosystem
		}
		if sorted[i].display != sorted[j].display {
			return sorted[i].display < sorted[j].display
		}
		if sorted[i].version != sorted[j].version {
			return sorted[i].version < sorted[j].version
		}
		return sorted[i].npm < sorted[j].npm
	})
	pkgs = sorted
	if len(pkgs) > 150 {
		warnings = append(warnings, fmt.Sprintf("osv: truncated package list from %d to 150 (sorted)", len(pkgs)))
		pkgs = pkgs[:150]
	} else if len(pkgs) > 20 {
		warnings = append(warnings, fmt.Sprintf("osv: truncated package list from %d to 20 (sorted)", len(pkgs)))
		pkgs = pkgs[:20]
	}
	type pkgQuery struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Version string `json:"version"`
	}
	type batchReq struct {
		Queries   []pkgQuery `json:"queries"`
		PageToken string     `json:"page_token,omitempty"`
	}
	buildRaw := func(pageToken string) ([]byte, error) {
		body := batchReq{}
		if pageToken != "" {
			body.PageToken = pageToken
		}
		for _, p := range pkgs {
			q := pkgQuery{Version: p.version}
			// Master: support npm, PyPI, Maven, Go ecosystems via osv.go:24
			ecos := p.ecosystem
			if ecos == "" {
				ecos = "npm"
			}
			q.Package.Ecosystem = ecos
			if p.npm != "" {
				q.Package.Name = p.npm
			} else {
				q.Package.Name = p.display
			}
			body.Queries = append(body.Queries, q)
		}
		return json.Marshal(body)
	}
	type batchResult struct {
		Vulns         []osvRawVuln `json:"vulns"`
		NextPageToken string       `json:"next_page_token"`
	}
	var batchDoc struct {
		Results       []batchResult `json:"results"`
		NextPageToken string        `json:"next_page_token"`
	}

	client := anpuhttp.NewClientWithLocalNetworkAllowed(scanner.AllowLocalNetwork)
	doBatch := func(rctx context.Context, pageToken string) bool {
		raw, err := buildRaw(pageToken)
		if err != nil {
			return false
		}
		resp, err := client.PostJSON(rctx, osvBaseURL+"/v1/querybatch", string(raw), map[string]string{
			"Content-Type": "application/json",
		})
		if err != nil || resp == nil || resp.StatusCode != 200 {
			return false
		}
		var doc struct {
			Results       []batchResult `json:"results"`
			NextPageToken string        `json:"next_page_token"`
		}
		if err := json.Unmarshal(resp.Body, &doc); err != nil {
			return false
		}
		if pageToken == "" {
			batchDoc = doc
		} else {
			// Merge follow-up page into the first page, index-aligned.
			for i, r := range doc.Results {
				if i >= len(batchDoc.Results) {
					break
				}
				batchDoc.Results[i].Vulns = append(batchDoc.Results[i].Vulns, r.Vulns...)
			}
			if doc.NextPageToken != "" {
				batchDoc.NextPageToken = doc.NextPageToken
			} else {
				batchDoc.NextPageToken = ""
			}
		}
		return true
	}

	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if !doBatch(rctx, "") {
		return out, warnings
	}
	// Honor next_page_token with one follow-up page max.
	nextToken := batchDoc.NextPageToken
	if nextToken == "" {
		for _, r := range batchDoc.Results {
			if r.NextPageToken != "" {
				nextToken = r.NextPageToken
				break
			}
		}
	}
	if nextToken != "" {
		_ = doBatch(rctx, nextToken)
	}

	// Collect per-package IDs in batch order, plus batch fallback details.
	type idRef struct {
		pkgIdx int
		id     string
		raw    osvRawVuln
	}
	var refs []idRef
	seenID := map[string]bool{}
	var hydrateIDs []string
	for i, r := range batchDoc.Results {
		if i >= len(pkgs) {
			break
		}
		for _, v := range r.Vulns {
			if v.ID == "" {
				continue
			}
			refs = append(refs, idRef{pkgIdx: i, id: v.ID, raw: v})
			if !seenID[v.ID] {
				seenID[v.ID] = true
				if len(hydrateIDs) < 10 {
					hydrateIDs = append(hydrateIDs, v.ID)
				}
			}
		}
	}
	if len(refs) == 0 {
		return out, warnings
	}

	// Hydrate up to 10 IDs via GET /v1/vulns/{id}, 8s total budget,
	// sequential, fail-silent.
	hydrated := map[string]osvVuln{}
	if len(hydrateIDs) > 0 {
		hctx, hcancel := context.WithTimeout(ctx, 8*time.Second)
		defer hcancel()
		for _, id := range hydrateIDs {
			if hctx.Err() != nil {
				break
			}
			resp, err := client.Get(hctx, osvBaseURL+"/v1/vulns/"+id)
			if err != nil || resp == nil || resp.StatusCode != 200 || len(resp.Body) == 0 {
				continue
			}
			var full osvRawVuln
			if err := json.Unmarshal(resp.Body, &full); err != nil || full.ID == "" {
				continue
			}
			hydrated[id] = parseOsvRawVuln(full)
		}
	}

	for _, ref := range refs {
		if hv, ok := hydrated[ref.id]; ok {
			out[pkgs[ref.pkgIdx].display] = append(out[pkgs[ref.pkgIdx].display], hv)
			continue
		}
		// Fallback to batch details when hydration missed but the batch
		// record already carried a full advisory (back-compat with
		// fixtures that embed summary/severity/etc).
		if ref.raw.hasDetails() {
			out[pkgs[ref.pkgIdx].display] = append(out[pkgs[ref.pkgIdx].display], parseOsvRawVuln(ref.raw))
		}
		// Else: ids-only batch without hydration stays silent (fail-silent).
	}
	return out, warnings
}

// osvSeverity maps a CVSS score to an ANPU severity.
func osvSeverity(score float64) models.Severity {
	switch {
	case score >= 9.0:
		return models.SeverityCritical
	case score >= 7.0:
		return models.SeverityHigh
	case score >= 4.0:
		return models.SeverityMedium
	case score > 0:
		return models.SeverityLow
	default:
		return models.SeverityInfo
	}
}

// osvFinding converts one OSV record into a Finding. staticCVEs holds
// CVE IDs already reported from the built-in table for this library so
// the same advisory is not reported twice.
func osvFinding(p osvPackage, v osvVuln, staticCVEs map[string]bool, target string) *models.Finding {
	ref := v.id
	if v.cve != "" {
		if staticCVEs[strings.ToUpper(v.cve)] {
			return nil // already covered by the static table
		}
		ref = v.cve
	}
	title := fmt.Sprintf("Vulnerable dependency: %s %s (%s, via OSV)", p.display, p.version, ref)
	fix := "Upgrade to a patched release"
	if v.fixed != "" {
		fix = fmt.Sprintf("Upgrade to %s ≥ %s", p.display, v.fixed)
	}
	desc := v.summary
	if desc == "" {
		desc = fmt.Sprintf("%s %s has a known vulnerability recorded as %s.", p.display, p.version, ref)
	}
	return &models.Finding{
		ID:          fmt.Sprintf("dep-osv-%s-%d", strings.ToLower(strings.ReplaceAll(ref, " ", "")), time.Now().UnixNano()),
		Title:       title,
		Description: fmt.Sprintf("%s %s is affected by %s (CVSS %.1f): %s. %s.", p.display, p.version, ref, v.score, desc, fix),
		Severity:    osvSeverity(v.score),
		Confidence:  models.ConfidenceHigh,
		Category:    models.CategoryVulnerability,
		CWE:         "CWE-1395",
		OWASP:       "A06:2021 - Vulnerable and Outdated Components",
		Target:      target,
		Source:      models.SourceDeps,
		DetectionMethod: fmt.Sprintf(
			"version %s detected; matched live against OSV.dev (no static-table hit)",
			p.version,
		),
		Evidence: models.Evidence{
			Observed: fmt.Sprintf("OSV %s: %s (fixed in %s)", v.id, firstLine(v.summary, 200), v.fixed),
		},
		Impact:      fmt.Sprintf("Attackers can exploit %s against users of this site.", ref),
		Remediation: fix,
		References:  []string{"https://osv.dev/vulnerability/" + v.id},
		FirstSeen:   time.Now(),
	}
}

func firstLine(s string, n int) string {
	if i := strings.Index(s, "\n"); i >= 0 {
		s = s[:i]
	}
	if len(s) > n {
		return s[:n] + "…"
	}
	if s == "" {
		return "(no summary)"
	}
	return s
}
