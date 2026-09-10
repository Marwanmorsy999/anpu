// Package exposedconfig probes for exposed VCS metadata and environment
// files (Wave 1 item 12): /.svn/entries, /.hg/requires, /.bzr/README,
// /.env, /.env.local, /.DS_Store. At most 7 requests (control + 6
// probes), GET-only, read-only. A 200 whose body carries the expected
// marker — and differs from the soft-404 control — is a finding.
//
// Severity: .env content with KEY= assignments is High (secret
// exposure); other markers are Medium.
package exposedconfig

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

// maxRequests bounds all HTTP traffic: 1 control + 6 probes.
const maxRequests = 7

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "exposedconfig" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

type probe struct {
	path   string
	marker *regexp.Regexp
	title  string
	env    bool // .env-style: KEY= assignments raise severity
}

var probes = []probe{
	{"/.svn/entries", regexp.MustCompile(`(?m)^(dir|file)\s*$|svn:this_dir`), "Exposed Subversion metadata (/.svn/entries)", false},
	{"/.hg/requires", regexp.MustCompile(`(?m)^(revlogv1|generaldelta|store|fncache)`), "Exposed Mercurial metadata (/.hg/requires)", false},
	{"/.bzr/README", regexp.MustCompile(`(?i)bazaar`), "Exposed Bazaar metadata (/.bzr/README)", false},
	{"/.env", regexp.MustCompile(`(?m)^[A-Z][A-Z0-9_]+\s*=`), "Exposed environment file (/.env)", true},
	{"/.env.local", regexp.MustCompile(`(?m)^[A-Z][A-Z0-9_]+\s*=`), "Exposed environment file (/.env.local)", true},
	{"/.DS_Store", regexp.MustCompile(`Bud1|DS_Store`), "Exposed macOS .DS_Store", false},
}

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	made := 0
	get := func(path string) *anpuhttp.Response {
		if made >= maxRequests {
			return nil
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		made++
		resp, err := s.client.Get(cctx, strings.TrimSuffix(sc.Target.Raw, "/")+path)
		if err != nil || resp == nil {
			return nil
		}
		return resp
	}

	controlWords := map[string]struct{}{}
	if control := get("/anpu-exposedconfig-control-404"); control != nil {
		controlWords = wordSet(control.Body)
	}

	var findings []models.Finding
	for _, p := range probes {
		if made >= maxRequests {
			break
		}
		resp := get(p.path)
		if resp == nil || resp.StatusCode != 200 || len(resp.Body) == 0 {
			continue
		}
		body := string(resp.Body)
		if !p.marker.MatchString(body) {
			continue
		}
		if overlap(wordSet(resp.Body), controlWords) > 0.85 {
			continue // baseline-subtract: same page as control
		}
		sev := models.SeverityMedium
		if p.env {
			sev = models.SeverityHigh
		}
		obs := "marker matched (" + p.marker.String() + ")"
		if len(body) < 200 {
			obs = snippet(body)
		}
		findings = append(findings, models.Finding{
			ID:              "exposedconfig-" + slug(p.path),
			Title:           p.title,
			Description:     fmt.Sprintf("The path %s is publicly readable and carries %s content. VCS metadata leaks paths and history; .env files leak secrets; .DS_Store leaks filenames. Deny these paths at the edge and rotate any exposed secret. Reproduce: curl -s TARGET%s.", p.path, kind(p), p.path),
			Severity:        sev,
			Confidence:      models.ConfidenceHigh,
			Category:        models.CategoryExposure,
			CWE:             "CWE-538",
			Target:          sc.Target.Raw,
			URL:             strings.TrimSuffix(sc.Target.Raw, "/") + p.path,
			Evidence:        models.Evidence{Observed: obs, Location: p.path},
			Source:          models.SourceRecon,
			DetectionMethod: "VCS/env marker probe with 404 baseline (exposedconfig, ≤7 requests)",
			Remediation:     "Deny dotfile metadata paths at the edge; rotate exposed secrets.",
		})
		if len(findings) >= 4 {
			break
		}
	}
	return scanner.StageResult{Findings: findings}, nil
}

func kind(p probe) string {
	if p.env {
		return "environment-secret"
	}
	return "version-control"
}

func slug(path string) string {
	s := strings.ToLower(strings.Trim(path, "/"))
	s = strings.ReplaceAll(s, ".", "")
	s = strings.ReplaceAll(s, "/", "-")
	return s
}

func snippet(body string) string {
	s := strings.Join(strings.Fields(body), " ")
	if len(s) > 160 {
		s = s[:160] + "..."
	}
	return s
}

func wordSet(b []byte) map[string]struct{} {
	out := map[string]struct{}{}
	for _, w := range strings.Fields(strings.ToLower(string(b))) {
		if len(w) > 2 {
			out[w] = struct{}{}
		}
	}
	return out
}

func overlap(a, b map[string]struct{}) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	n := 0
	for w := range a {
		if _, ok := b[w]; ok {
			n++
		}
	}
	return float64(n) / float64(len(a))
}
