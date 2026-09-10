// Package graphqlfp fingerprints GraphQL endpoints (Wave 1 item 31):
// POST {"query":"{__typename}"} plus GET ?query={__typename} against
// /graphql, /api/graphql, /v1/graphql, /query (8 requests max). Engine
// identification from error shapes and headers (Apollo, Hasura,
// Graphene, Lighthouse, Mercurius, Yoga, WPGraphQL). Confirmed
// endpoints are harvested; engine reported as Technology. GET/POST
// read-only introspection probe — no mutations.
package graphqlfp

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// maxRequests bounds all HTTP traffic: 4 paths × (POST + GET).
const maxRequests = 8

var graphqlPaths = []string{"/graphql", "/api/graphql", "/v1/graphql", "/query"}

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "graphqlfp" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

// identifyEngine matches engine from body/headers (pure, tested).
func identifyEngine(body string, headers map[string]string) string {
	b := strings.ToLower(body)
	switch {
	case strings.Contains(b, "hasura") || headers["x-hasura-request-id"] != "":
		return "Hasura"
	case strings.Contains(b, "persistedquerynotfound") || strings.Contains(b, "apollo"):
		return "Apollo Server"
	case strings.Contains(b, "graphene") || strings.Contains(b, "must provide query string"):
		return "Graphene"
	case strings.Contains(b, "lighthouse") || strings.Contains(b, "nuwave"):
		return "Lighthouse"
	case strings.Contains(b, "mercurius"):
		return "Mercurius"
	case strings.Contains(b, "yoga") || strings.Contains(b, "@graphql-yoga"):
		return "GraphQL Yoga"
	case strings.Contains(b, "wpgraphql"):
		return "WPGraphQL"
	}
	return ""
}

// looksGraphQL reports GraphQL-shaped responses (pure, tested).
func looksGraphQL(body string) bool {
	b := strings.ToLower(body)
	return strings.Contains(b, "__typename") || strings.Contains(b, "\"data\"") || strings.Contains(b, "\"errors\"")
}

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	made := 0
	post := func(u string) *anpuhttp.Response {
		if made >= maxRequests {
			return nil
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		made++
		resp, err := s.client.PostJSON(cctx, u, `{"query":"{__typename}"}`, map[string]string{"Accept": "application/json"})
		if err != nil || resp == nil {
			return nil
		}
		return resp
	}
	get := func(u string) *anpuhttp.Response {
		if made >= maxRequests {
			return nil
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		made++
		resp, err := s.client.Get(cctx, u)
		if err != nil || resp == nil {
			return nil
		}
		return resp
	}

	var findings []models.Finding
	var endpoints []models.Endpoint
	var techs []models.Technology
	for _, p := range graphqlPaths {
		if made >= maxRequests {
			break
		}
		u := strings.TrimSuffix(sc.Target.Raw, "/") + p
		resp := post(u)
		if resp == nil || !looksGraphQL(string(resp.Body)) {
			// GET fallback for GET-enabled endpoints.
			resp = get(u + "?query=%7B__typename%7D")
			if resp == nil || !looksGraphQL(string(resp.Body)) {
				continue
			}
		}
		hdrs := map[string]string{
			"x-hasura-request-id": resp.Header.Get("X-Hasura-Request-Id"),
		}
		engine := identifyEngine(string(resp.Body), hdrs)
		title := "GraphQL endpoint confirmed: " + p
		if engine != "" {
			title += " (" + engine + ")"
			techs = append(techs, models.Technology{Name: engine, Category: "api", Confidence: 0.8,
				Evidence: models.Evidence{Observed: "GraphQL error/header shape at " + p, Location: p}})
		}
		findings = append(findings, models.Finding{
			ID: "graphqlfp-endpoint", Title: title,
			Description: fmt.Sprintf("POST {__typename} to %s returns a GraphQL-shaped response. Harden depth/complexity limits, disable introspection in production, and test authorization per field. Reproduce: curl -s -X POST %q -H 'Content-Type: application/json' -d '{\"query\":\"{__typename}\"}'. Read-only probe — no mutations sent.", p, u),
			Severity:    models.SeverityInfo, Confidence: models.ConfidenceHigh, Category: models.CategoryExposure,
			Target: sc.Target.Raw, URL: u,
			Evidence: models.Evidence{Observed: "GraphQL-shaped response to {__typename}", Location: p},
			Source:   models.SourceRecon, DetectionMethod: "GraphQL typename probe (graphqlfp, ≤8 requests)",
		})
		endpoints = append(endpoints, models.Endpoint{URL: u, Category: models.EndpointAPI, Sources: []string{"graphqlfp"}})
		break // one confirmed endpoint is enough
	}
	return scanner.StageResult{Findings: findings, Endpoints: endpoints, Technologies: techs}, nil
}
