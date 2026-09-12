// Package cvepack runs CVE-behavior safe probes (Wave 1 item 40):
// (a) an inert Spring classLoader-prefix differential (benign property
// name, no persistence, no expression evaluation — a handled prefix
// surfaces as a behavioral difference vs baseline and random control);
// (b) version-signature mapping of already-fingerprinted technologies
// against a small table of notorious server-side CVEs (no requests).
// Findings are Info/Medium with manual-confirm notes — version-only
// matches never claim exploitability. 3 requests max.
package cvepack

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// maxRequests bounds all HTTP traffic: baseline + probe + control.
const maxRequests = 3

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "cvepack" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

type cveSig struct {
	product  string
	below    string // vulnerable when version < below (empty = any version note)
	cve      string
	title    string
	severity models.Severity
}

// notorious server-side version signatures (conservative, famous CVEs).
func cveSigs() []cveSig {
	return []cveSig{
		{"spring", "5.2.20", "CVE-2022-22965", "Spring Framework < 5.2.20 (Spring4Shell class)", models.SeverityMedium},
		{"spring", "5.3.18", "CVE-2022-22965", "Spring Framework < 5.3.18 (Spring4Shell class)", models.SeverityMedium},
		{"apache", "2.4.53", "CVE-2022-22719", "Apache httpd < 2.4.53 (request-smuggling class)", models.SeverityMedium},
		{"nginx", "1.21.6", "CVE-2021-23017", "nginx < 1.21.6 (resolver off-by-one class)", models.SeverityLow},
		{"php", "8.1.0", "CVE-2021-21703", "PHP < 8.1 (filter/FPM hardening gap class)", models.SeverityLow},
	}
}

// cmpVersion compares dotted versions (pure, tested): -1/0/1.
func cmpVersion(a, b string) int {
	pa := splitVer(a)
	pb := splitVer(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func splitVer(v string) []int {
	var out []int
	for _, f := range strings.Split(v, ".") {
		digits := ""
		for _, c := range f {
			if c < '0' || c > '9' {
				break
			}
			digits += string(c)
		}
		n, _ := strconv.Atoi(digits)
		out = append(out, n)
	}
	return out
}

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	var findings []models.Finding
	// (b) Version-signature mapping over fingerprinted technologies.
	for _, t := range sc.Technologies {
		if t.Version == "" {
			continue
		}
		for _, sig := range cveSigs() {
			if !strings.Contains(strings.ToLower(t.Name), sig.product) {
				continue
			}
			if cmpVersion(t.Version, sig.below) >= 0 {
				continue
			}
			findings = append(findings, models.Finding{
				ID: "cvepack-" + strings.ToLower(sig.cve), Title: sig.title + " (version match, unconfirmed)",
				Description: fmt.Sprintf("Fingerprinted %s %s falls below %s (%s). Version-only signal — confirm the exact build and patch level before acting; no exploit was attempted. Reproduce: check the version banner and vendor advisory.", t.Name, t.Version, sig.below, sig.cve),
				Severity:    sig.severity, Confidence: models.ConfidenceMedium, Category: models.CategoryVulnerability,
				CWE: "CWE-1104", Target: sc.Target.Raw,
				Evidence: models.Evidence{Observed: fmt.Sprintf("%s %s < %s", t.Name, t.Version, sig.below), Location: "technology fingerprint"},
				Source:   models.SourceCustom, DetectionMethod: "CVE version-signature mapping (cvepack, 0 requests)",
				Remediation: "Upgrade to a patched release per the vendor advisory.",
			})
			break
		}
		if len(findings) >= 3 {
			break
		}
	}
	// (a) Inert Spring classLoader-prefix differential. Skipped when the
	// stack confidently says Next.js: a Node framework cannot process
	// Spring data-binding prefixes, so any differential there is edge
	// behavior, not Spring surface. Weak/unknown stacks fail open.
	if confidentNextJS(sc.Technologies) {
		return scanner.StageResult{
			Findings: findings,
			Warnings: []string{"cvepack: skipped Spring classLoader probe — confident Next.js stack cannot process Spring prefixes"},
		}, nil
	}
	made := 0
	get := func(u string) string {
		if made >= maxRequests {
			return ""
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		made++
		resp, err := s.client.Get(cctx, u)
		if err != nil || resp == nil {
			return ""
		}
		return string(resp.Body)
	}
	base := get(sc.Target.Raw)
	if base != "" {
		probe := get(withParam(sc.Target.Raw, "class.module.classLoader.anpuProbe", "anputest9"))
		control := get(withParam(sc.Target.Raw, "anpucontrolxyz", "anputest9"))
		if probe != "" && probe != base && probe != control {
			findings = append(findings, models.Finding{
				ID: "cvepack-spring-prefix", Title: "Spring classLoader prefix handled (possible Spring CVE surface)",
				Description: "An inert classLoader-prefixed parameter alters the response vs baseline and random control: the Spring data-binding prefix is processed. This is a behavioral signal only — confirm the Spring version and patch level manually. Inert property name, no persistence, no expression evaluation.",
				Severity:    models.SeverityInfo, Confidence: models.ConfidenceLow, Category: models.CategoryExposure,
				Target: sc.Target.Raw, URL: sc.Target.Raw,
				Evidence: models.Evidence{Observed: "inert classLoader probe differs from baseline + control", Location: "query parameter"},
				Source:   models.SourceCustom, DetectionMethod: "Spring prefix behavioral differential (cvepack, ≤3 requests)",
			})
		}
	}
	return scanner.StageResult{Findings: findings}, nil
}

// confidentNextJS reports whether the fingerprinted stack confidently
// says Next.js (header/CDN-tier confidence only — never body-text
// mentions), in which case Spring probes are meaningless.
func confidentNextJS(techs []models.Technology) bool {
	for _, t := range techs {
		if t.Confidence < 0.8 {
			continue
		}
		n := strings.ToLower(t.Name)
		if strings.Contains(n, "next.js") || strings.Contains(n, "nextjs") {
			return true
		}
	}
	return false
}

func withParam(raw, name, value string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	q.Set(name, value)
	u.RawQuery = q.Encode()
	return u.String()
}
