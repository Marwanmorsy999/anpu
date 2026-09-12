package api

import (
	"context"
	"fmt"
	"time"

	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// Config holds the Phase 5 options supplied via CLI / YAML config.
type Config struct {
	// OpenAPISource is a file path or URL to an OpenAPI 3.x or
	// Swagger 2.x document.  Empty means OpenAPI scanning is disabled.
	OpenAPISource string

	// GraphQLURL is the GraphQL endpoint to introspect.
	// Empty means GraphQL scanning is disabled.
	GraphQLURL string

	// BaseURL overrides the server URL detected from the OpenAPI document.
	// Useful when the schema describes "production" but you are scanning
	// a staging host.  Leave empty to auto-detect.
	BaseURL string
}

// Scanner is the Phase 5 API security pipeline stage.
//
// It runs after endpoint discovery and before the active engine, injecting
// API-derived endpoints into the ScanContext so that:
//   - Phase 3 (authz) probes every schema operation under both identities.
//   - Phase 4 (active) tests query/path/body params with its 8 rules.
//   - New Phase 5 checks (introspection disclosure, etc.) produce findings
//     directly.
type Scanner struct {
	cfg Config
}

// New returns an api.Scanner with the given config.
func New(cfg Config) *Scanner {
	return &Scanner{cfg: cfg}
}

func (s *Scanner) Name() string { return "api-scanner" }

// Available always returns true: with zero configuration the scanner
// auto-discovers schemas at well-known locations, so there is always
// something useful to attempt.
func (s *Scanner) Available(_ context.Context) bool {
	return true
}

// Run executes the API scanning stage. Per-stage deadline ≤30s for
// discovery; abuse checks keep 10s each but run max 3 when introspection
// fails.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	rctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	ctx = rctx
	var findings []models.Finding
	var warnings []string
	var newEndpoints []models.Endpoint

	openAPISource := s.cfg.OpenAPISource
	graphQLURL := s.cfg.GraphQLURL

	// anpuhttp client for all GraphQL probes (redirect guards, proxy,
	// limiter, local-net policy).
	apiClient := discoveryClient()

	// Zero-config discovery: hunt well-known schema locations when the
	// user supplied nothing. Read-only probes, bounded cost (≤30s).
	if openAPISource == "" && graphQLURL == "" {
		openAPISource, graphQLURL = DiscoverSchemas(ctx, apiClient, sc.Target.Raw)
		if sc.Verbose && (openAPISource != "" || graphQLURL != "") {
			warnings = append(warnings, fmt.Sprintf(
				"api-scanner: auto-discovered schema openapi=%q graphql=%q", openAPISource, graphQLURL))
		}
	}

	// --- OpenAPI / Swagger ---
	if openAPISource != "" {
		authHeaders := sc.Auth.RequestHeaders()
		apiEPs, err := LoadOpenAPIWithAuth(ctx, openAPISource, s.cfg.BaseURL, authHeaders, apiClient)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("api-scanner: openapi load failed: %v", err))
		} else {
			converted := APIEndpointsToEndpoints(apiEPs)
			newEndpoints = append(newEndpoints, converted...)
			// Emit an info finding summarising the schema import.
			findings = append(findings, schemaImportFinding(sc.Target.Raw, openAPISource, len(apiEPs)))
			if sc.Verbose {
				warnings = append(warnings, fmt.Sprintf(
					"api-scanner: loaded %d operations from %s", len(apiEPs), openAPISource))
			}
		}
	}

	// --- GraphQL ---
	if graphQLURL != "" {
		authHeaders := sc.Auth.RequestHeaders()
		gqlSchema, gqlEndpoints, err := IntrospectGraphQL(ctx, graphQLURL, authHeaders, apiClient, 15*time.Second)
		introspectOK := err == nil
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("api-scanner: graphql introspect failed: %v", err))
		} else {
			// Emit a finding if introspection succeeded (misconfiguration signal).
			if f := CheckGraphQLIntrospectionEnabled(graphQLURL, gqlSchema); f != nil {
				findings = append(findings, *f)
			}
			// Depth limits only testable against a live schema.
			if f := CheckGraphQLDepthLimit(ctx, graphQLURL, authHeaders, apiClient, 10*time.Second); f != nil {
				findings = append(findings, *f)
			}
			converted := APIEndpointsToEndpoints(gqlEndpoints)
			newEndpoints = append(newEndpoints, converted...)
			if sc.Verbose {
				warnings = append(warnings, fmt.Sprintf(
					"api-scanner: graphql introspection discovered %d operations (%d queries, %d mutations)",
					len(gqlEndpoints), len(gqlSchema.QueryFields), len(gqlSchema.MutationFields),
				))
			}
		}
		// Schema-independent abuse checks (10s each, max 3 when
		// introspection failed): batching, suggestions, GET, alias flood.
		// Budget: 3 when introspection failed, 4 when ok (depth already ok).
		budget := 3
		if introspectOK {
			budget = 4
		}
		abuseRun := 0
		if abuseRun < budget {
			if f := CheckGraphQLBatching(ctx, graphQLURL, authHeaders, apiClient, 10*time.Second); f != nil {
				findings = append(findings, *f)
			}
			abuseRun++
		}
		if abuseRun < budget {
			if f := CheckGraphQLFieldSuggestions(ctx, graphQLURL, authHeaders, apiClient, 10*time.Second); f != nil {
				findings = append(findings, *f)
			}
			abuseRun++
		}
		if abuseRun < budget {
			if f := CheckGraphQLGetQueries(ctx, graphQLURL, authHeaders, apiClient, 10*time.Second); f != nil {
				findings = append(findings, *f)
			}
			abuseRun++
		}
		if abuseRun < budget {
			if f := CheckGraphQLAliasFlood(ctx, graphQLURL, authHeaders, apiClient, 10*time.Second); f != nil {
				findings = append(findings, *f)
			}
		}
	}

	// --- gRPC (Master P2) ---
	// Probe for gRPC reflection exposure (application/grpc, ListServices)
	// Keep openapi.yaml/swagger.yaml/v3/api-docs handling via yaml pre-pass already in openapi.go:112.
	// gRPC is probed via reflection ListServices application/grpc probe, vectors.go:81 add VectorGRPC.
	if f := GRPCProbe(ctx, sc.Target.Raw, apiClient); f != nil {
		findings = append(findings, *f)
		newEndpoints = append(newEndpoints, ProbeGRPC(ctx, sc.Target.Raw, apiClient)...)
	}

	return scanner.StageResult{
		Findings:  findings,
		Endpoints: newEndpoints,
		Warnings:  warnings,
	}, nil
}

// schemaImportFinding returns an informational finding that records the
// successful import of an API schema.  It serves as an audit trail so
// operators know which schema was used in each scan.
func schemaImportFinding(target, source string, count int) models.Finding {
	return models.Finding{
		ID:    fmt.Sprintf("api-schema-import-%d", time.Now().UnixNano()),
		Title: fmt.Sprintf("API schema imported: %d operations from %s", count, source),
		Description: fmt.Sprintf(
			"ANPU imported an OpenAPI/Swagger schema from %q and added %d API operations to the scan surface of %s. "+
				"All discovered operations will be probed by the authorization comparison engine (Phase 3) and the active testing engine (Phase 4).",
			source, count, target,
		),
		Severity:        models.SeverityInfo,
		Confidence:      models.ConfidenceConfirmed,
		Category:        models.CategoryEndpoint,
		Target:          target,
		Source:          models.SourceAPI,
		DetectionMethod: "OpenAPI/Swagger schema import",
		FirstSeen:       time.Now(),
		Evidence: models.Evidence{
			Observed: fmt.Sprintf("%d operations imported from %s", count, source),
			Location: source,
		},
	}
}
