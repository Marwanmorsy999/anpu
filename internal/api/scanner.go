package api

import (
	"context"
	"fmt"
	"time"

	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
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

// Available returns true when at least one API source is configured.
func (s *Scanner) Available(_ context.Context) bool {
	return s.cfg.OpenAPISource != "" || s.cfg.GraphQLURL != ""
}

// Run executes the API scanning stage.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	var findings []models.Finding
	var warnings []string
	var newEndpoints []models.Endpoint

	// --- OpenAPI / Swagger ---
	if s.cfg.OpenAPISource != "" {
		apiEPs, err := LoadOpenAPI(s.cfg.OpenAPISource, s.cfg.BaseURL)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("api-scanner: openapi load failed: %v", err))
		} else {
			converted := APIEndpointsToEndpoints(apiEPs)
			newEndpoints = append(newEndpoints, converted...)
			// Emit an info finding summarising the schema import.
			findings = append(findings, schemaImportFinding(sc.Target.Raw, s.cfg.OpenAPISource, len(apiEPs)))
			if sc.Verbose {
				warnings = append(warnings, fmt.Sprintf(
					"api-scanner: loaded %d operations from %s", len(apiEPs), s.cfg.OpenAPISource))
			}
		}
	}

	// --- GraphQL ---
	if s.cfg.GraphQLURL != "" {
		authHeaders := sc.Auth.RequestHeaders()
		gqlSchema, gqlEndpoints, err := IntrospectGraphQL(ctx, s.cfg.GraphQLURL, authHeaders, 15*time.Second)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("api-scanner: graphql introspect failed: %v", err))
		} else {
			// Emit a finding if introspection succeeded (misconfiguration signal).
			if f := CheckGraphQLIntrospectionEnabled(s.cfg.GraphQLURL, gqlSchema); f != nil {
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
