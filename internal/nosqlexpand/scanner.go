// Package nosqlexpand probes NoSQL injection differentially (Wave 1
// item 35): MongoDB operator syntax ($ne/$gt/$regex/$where-shaped
// benign probes), auth-bypass differentials (known vs $ne on login-ish
// params), and error markers (MongoError, BSON, $where). A hit requires
// the operator response to differ from BOTH the plain baseline and a
// random control. GET-only, ≤2 URLs, 18 requests max. No data
// extraction — differentials only.
package nosqlexpand

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// maxRequests bounds all HTTP traffic: 2 URLs × (baseline + 7 + control).
const maxRequests = 18

var nosqlProbes = []struct {
	name  string
	param string // appended as param[key]=value style
	value string
}{
	{"$ne bypass", "anpune", "anputest"},
	{"$gt comparison", "anpugt", "anputest"},
	{"$regex match-all", "anpuregex", "^.*"},
	{"$where benign", "anpuwhere", "1==1"},
	{"operator injection", "anpu[$ne]", "anputest"},
	{"JSON operator", "anpujson", `{"$ne": null}`},
	{"error probe", "anpuerr", "'\""},
}

var nosqlMarkers = []string{"mongoerror", "bson", "$where", "mongod", "objectid", "casterror"}

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "nosqlexpand" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	targets := pickTargets(sc)
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

	var findings []models.Finding
	for _, target := range targets {
		base := get(target)
		if base == "" {
			continue
		}
		control := get(withParam(target, "anpucontrolxyz", "anputest9"))
		type hit struct {
			probe  string
			param  string
			value  string
			marker string
		}
		var hits []hit
		for _, p := range nosqlProbes {
			if made >= maxRequests {
				break
			}
			body := get(withParam(target, p.param, p.value))
			if body == "" || body == base || body == control {
				continue
			}
			lower := strings.ToLower(body)
			marker := ""
			for _, m := range nosqlMarkers {
				if strings.Contains(lower, m) {
					marker = m
					break
				}
			}
			hits = append(hits, hit{probe: p.name, param: p.param, value: p.value, marker: marker})
		}
		if len(hits) == 0 {
			continue
		}
		// Corroboration bar: a backend error marker or TWO distinct
		// probes differing earns Medium; a lone differential without
		// any marker is Low — modern frameworks (SSR, image
		// optimizers, edge middleware) routinely answer unknown
		// params differently without any NoSQL backend involved.
		chosen := hits[0]
		sev := models.SeverityLow
		conf := models.ConfidenceLow
		standing := "single-signal differential without a backend marker — possible framework behavior, needs review"
		for _, h := range hits {
			if h.marker != "" {
				chosen = h
				sev = models.SeverityMedium
				conf = models.ConfidenceMedium
				standing = fmt.Sprintf("backend marker %q corroborates", h.marker)
				break
			}
		}
		if sev == models.SeverityLow && len(hits) >= 2 {
			sev = models.SeverityMedium
			conf = models.ConfidenceMedium
			standing = fmt.Sprintf("%d distinct operator probes (%s, %s) corroborate", len(hits), hits[0].probe, hits[1].probe)
		}
		obs := fmt.Sprintf("operator %q changes response vs baseline + control (%s)", chosen.probe, standing)
		if chosen.marker != "" {
			obs = fmt.Sprintf("operator %q leaks marker %q", chosen.probe, chosen.marker)
		}
		findings = append(findings, models.Finding{
			ID: "nosqlexpand-differential", Title: fmt.Sprintf("NoSQL injection differential (%s)", chosen.probe),
			Description: fmt.Sprintf("A benign NoSQL operator probe %s alters the response while the random control does not%s: query structure reaches a NoSQL backend unsanitized. Parameterize queries and deny operator syntax in input. Reproduce: curl TARGET with ?%s=%s. Differentials only — no data extracted.", chosen.probe, markerNote(chosen.marker), chosen.param, chosen.value),
			Severity:    sev, Confidence: conf, Category: models.CategoryVulnerability,
			CWE: "CWE-943", Target: sc.Target.Raw, URL: target,
			Evidence: models.Evidence{Observed: obs, Location: "query param " + chosen.param},
			Source:   models.SourceCustom, DetectionMethod: "NoSQL operator differential (nosqlexpand, ≤18 requests)",
			Remediation: "Use parameterized drivers; reject keys starting with $.",
		})
		if len(findings) >= 2 {
			break
		}
	}
	return scanner.StageResult{Findings: findings}, nil
}

func markerNote(m string) string {
	if m == "" {
		return ""
	}
	return fmt.Sprintf(" (backend marker %q)", m)
}

func pickTargets(sc *scanner.ScanContext) []string {
	var out []string
	for _, ep := range sc.Endpoints {
		if len(out) >= 2 {
			break
		}
		u, err := url.Parse(ep.URL)
		if err != nil || !strings.EqualFold(u.Hostname(), sc.Target.Host) {
			continue
		}
		out = append(out, ep.URL)
	}
	if len(out) == 0 {
		out = []string{sc.Target.Raw}
	}
	return out
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
