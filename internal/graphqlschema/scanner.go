// Package graphqlschema tests GraphQL introspection exposure (Wave 1
// item 32): a single bounded POST {__schema{queryType{name}}} against
// each GraphQL endpoint already discovered (plus /graphql fallback).
// Full schema disclosure is a Medium finding with the type count;
// disabled introspection is silent (good). 3 requests max, read-only,
// never a mutation or alias flood (those live behind explicit flags).
package graphqlschema

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// maxRequests bounds all HTTP traffic.
const maxRequests = 3

const introspectionQuery = `{"query":"{__schema{queryType{name}types{name}}}"}`

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "graphqlschema" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

// typeNames extracts schema type names (pure, tested).
func typeNames(body []byte) []string {
	var doc struct {
		Data struct {
			Schema struct {
				Types []struct {
					Name string `json:"name"`
				} `json:"types"`
			} `json:"__schema"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, t := range doc.Data.Schema.Types {
		if t.Name == "" || seen[t.Name] || strings.HasPrefix(t.Name, "__") {
			continue
		}
		seen[t.Name] = true
		out = append(out, t.Name)
	}
	sort.Strings(out)
	return out
}

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	var urls []string
	for _, ep := range sc.Endpoints {
		if ep.Category != models.EndpointAPI {
			continue
		}
		if strings.Contains(strings.ToLower(ep.URL), "graphql") {
			urls = append(urls, ep.URL)
		}
	}
	urls = append(urls, strings.TrimSuffix(sc.Target.Raw, "/")+"/graphql")
	made := 0
	for _, u := range urls {
		if made >= maxRequests {
			break
		}
		cctx, cancel := context.WithTimeout(ctx, 12*time.Second)
		made++
		resp, err := s.client.PostJSON(cctx, u, introspectionQuery, map[string]string{"Accept": "application/json"})
		cancel()
		if err != nil || resp == nil || resp.StatusCode != 200 {
			continue
		}
		names := typeNames(resp.Body)
		if len(names) == 0 {
			continue // introspection disabled or non-schema response — silent
		}
		shown := names
		if len(shown) > 12 {
			shown = shown[:12]
		}
		return scanner.StageResult{Findings: []models.Finding{{
			ID: "graphqlschema-introspection", Title: fmt.Sprintf("GraphQL introspection enabled (%d types disclosed)", len(names)),
			Description: fmt.Sprintf("Full introspection is on: the entire schema (%d user types, e.g. %s) is enumerable for field-level authz probing. Disable introspection in production. Reproduce: POST {__schema{queryType{name}}} to %s. Read-only — no mutations.", len(names), strings.Join(shown, ", "), u),
			Severity:    models.SeverityMedium, Confidence: models.ConfidenceHigh, Category: models.CategoryExposure,
			Target: sc.Target.Raw, URL: u,
			Evidence: models.Evidence{Observed: fmt.Sprintf("%d types: %s", len(names), strings.Join(shown, ", ")), Location: "introspection query"},
			Source:   models.SourceRecon, DetectionMethod: "introspection probe (graphqlschema, ≤3 requests)",
			Remediation: "Disable introspection in production; enforce per-field authz.",
		}}}, nil
	}
	return scanner.StageResult{}, nil
}
