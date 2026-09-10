// Package debugpages probes framework debug endpoints (Wave 1 item 14):
// Laravel Telescope, phpinfo variants, /server-status, /server-info,
// ASP.NET trace/elmah, Go pprof index (listing only — profiles are
// never fetched). At most 9 requests (control + 8 probes), GET-only,
// read-only. Marker match + control-difference required.
//
// Severity: debug consoles with content → Medium; version-revealing
// stubs → Low.
package debugpages

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// maxRequests bounds all HTTP traffic: 1 control + 8 probes.
const maxRequests = 9

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "debugpages" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

type debugProbe struct {
	path   string
	marker string
	title  string
	sev    models.Severity
}

var debugProbes = []debugProbe{
	{"/telescope", "telescope", "Laravel Telescope exposed", models.SeverityMedium},
	{"/phpinfo.php", "phpinfo()", "phpinfo() page exposed", models.SeverityMedium},
	{"/info.php", "PHP Version", "PHP info page exposed (/info.php)", models.SeverityMedium},
	{"/server-status", "Apache Status", "Apache server-status exposed", models.SeverityMedium},
	{"/server-info", "Apache Server Information", "Apache server-info exposed", models.SeverityMedium},
	{"/trace.axd", "trace.axd", "ASP.NET trace viewer exposed", models.SeverityMedium},
	{"/elmah.axd", "elmah", "ELMAH error log exposed", models.SeverityMedium},
	{"/debug/pprof/", "profiles:", "Go pprof index exposed (profiles not fetched)", models.SeverityLow},
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
	if control := get("/anpu-debugpages-control-404"); control != nil {
		controlWords = wordSet(control.Body)
	}

	var findings []models.Finding
	for _, p := range debugProbes {
		if made >= maxRequests {
			break
		}
		resp := get(p.path)
		if resp == nil || resp.StatusCode != 200 || len(resp.Body) == 0 {
			continue
		}
		if !strings.Contains(strings.ToLower(string(resp.Body)), strings.ToLower(p.marker)) {
			continue
		}
		if overlap(wordSet(resp.Body), controlWords) > 0.85 {
			continue // baseline-subtract
		}
		findings = append(findings, models.Finding{
			ID:              "debugpages-" + slug(p.path),
			Title:           p.title,
			Description:     fmt.Sprintf("The debug endpoint %s is publicly reachable and returns debug content. Debug consoles leak configuration, routes, queries, and errors. Disable debug mode in production and restrict these paths. Reproduce: curl -s TARGET%s | grep -i %q.", p.path, p.path, p.marker),
			Severity:        p.sev,
			Confidence:      models.ConfidenceHigh,
			Category:        models.CategoryExposure,
			CWE:             "CWE-215",
			Target:          sc.Target.Raw,
			URL:             strings.TrimSuffix(sc.Target.Raw, "/") + p.path,
			Evidence:        models.Evidence{Observed: fmt.Sprintf("200 + marker %q (%d bytes)", p.marker, len(resp.Body)), Location: p.path},
			Source:          models.SourceRecon,
			DetectionMethod: "debug-page marker probe with 404 baseline (debugpages, ≤9 requests)",
			Remediation:     "Disable debug consoles in production; gate by IP/auth.",
		})
		if len(findings) >= 4 {
			break
		}
	}
	return scanner.StageResult{Findings: findings}, nil
}

func slug(path string) string {
	s := strings.ToLower(strings.Trim(path, "/"))
	s = strings.ReplaceAll(s, ".", "")
	s = strings.ReplaceAll(s, "/", "-")
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
