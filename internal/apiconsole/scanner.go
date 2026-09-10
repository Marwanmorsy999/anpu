// Package apiconsole deep-walks interactive API consoles (Wave 1 item
// 29): GraphiQL, Altair, RapiDoc, ReDoc, Swagger UI, and their backing
// schema documents at well-known paths. 1 control + 10 probes max,
// GET-only. Marker match + control-difference required; schema URLs
// are harvested as Endpoints for AuthZ/Active. A live console is a
// Medium finding (full API map + in-browser request sender); a bare
// schema document is Info.
package apiconsole

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// maxRequests bounds all HTTP traffic: 1 control + 10 probes.
const maxRequests = 11

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "apiconsole" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

type consoleProbe struct {
	path   string
	marker string // lowercase body marker
	schema bool   // backing document (Info) vs interactive console (Medium)
	title  string
}

var consoleProbes = []consoleProbe{
	{"/graphiql", "graphiql", false, "GraphiQL console exposed"},
	{"/graphql/console", "graphiql", false, "GraphiQL console exposed"},
	{"/altair", "altair", false, "Altair GraphQL console exposed"},
	{"/rapidoc", "rapi-doc", false, "RapiDoc console exposed"},
	{"/redoc", "redoc", false, "ReDoc console exposed"},
	{"/swagger", "swagger", false, "Swagger UI exposed"},
	{"/swagger-ui.html", "swagger", false, "Swagger UI exposed"},
	{"/openapi.json", "\"openapi\"", true, "OpenAPI document exposed"},
	{"/swagger.json", "\"swagger\"", true, "Swagger document exposed"},
	{"/api-docs", "openapi", true, "API docs bundle exposed"},
}

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	made := 0
	get := func(path string) *anpuhttp.Response {
		if made >= maxRequests {
			return nil
		}
		// Charge the global per-tool ledger (Wave 4 item 151); a nil
		// ledger (unit tests) means uncapped.
		if sc.Ledger != nil {
			if err := sc.Ledger.Record("apiconsole"); err != nil {
				return nil
			}
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
	if control := get("/anpu-apiconsole-control-404"); control != nil {
		controlWords = wordSet(control.Body)
	}

	var findings []models.Finding
	var endpoints []models.Endpoint
	for _, p := range consoleProbes {
		if made >= maxRequests {
			break
		}
		resp := get(p.path)
		if resp == nil || resp.StatusCode != 200 || len(resp.Body) < 32 {
			continue
		}
		if !strings.Contains(strings.ToLower(string(resp.Body)), p.marker) {
			continue
		}
		if overlap(wordSet(resp.Body), controlWords) > 0.85 {
			continue // baseline-subtract
		}
		sev := models.SeverityMedium
		if p.schema {
			sev = models.SeverityInfo
		}
		u := strings.TrimSuffix(sc.Target.Raw, "/") + p.path
		findings = append(findings, models.Finding{
			ID:              "apiconsole-" + slug(p.path),
			Title:           p.title,
			Description:     fmt.Sprintf("The path %s serves %s content: an attacker gets the full API map plus (for consoles) an in-browser request sender. Disable consoles in production; gate schema docs by auth. Reproduce: curl -s TARGET%s.", p.path, kind(p), p.path),
			Severity:        sev,
			Confidence:      models.ConfidenceHigh,
			Category:        models.CategoryExposure,
			Target:          sc.Target.Raw,
			URL:             u,
			Evidence:        models.Evidence{Observed: fmt.Sprintf("200 + marker %q (%d bytes)", p.marker, len(resp.Body)), Location: p.path},
			Source:          models.SourceRecon,
			DetectionMethod: "API console deep-walk (apiconsole, ≤11 requests)",
			Remediation:     "Remove consoles from production; restrict schema docs.",
		})
		endpoints = append(endpoints, models.Endpoint{URL: u, Category: models.EndpointAPI, Sources: []string{"apiconsole"}})
		if len(findings) >= 3 {
			break
		}
	}
	return scanner.StageResult{Findings: findings, Endpoints: endpoints}, nil
}

func kind(p consoleProbe) string {
	if p.schema {
		return "schema-document"
	}
	return "interactive-console"
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
