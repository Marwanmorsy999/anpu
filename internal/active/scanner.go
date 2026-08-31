package active

import (
	"context"
	"fmt"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// Scanner is the pipeline stage for Phase 4 safe active testing.
// It extracts input vectors from discovered endpoints, runs every
// registered rule against every vector, and emits findings.
type Scanner struct {
	client   *anpuhttp.Client
	registry *Registry
}

// New returns an active.Scanner with the default rule registry.
func New(client *anpuhttp.Client) *Scanner {
	return &Scanner{
		client:   client,
		registry: DefaultRegistry(),
	}
}

func (s *Scanner) Name() string                       { return "active-tester" }
func (s *Scanner) Available(_ context.Context) bool   { return true }

// Run iterates over all discovered endpoints, extracts input vectors,
// and runs every rule against every vector within its declared budget.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	if len(sc.Endpoints) == 0 {
		return scanner.StageResult{
			Warnings: []string{"active-tester: no endpoints discovered; nothing to probe"},
		}, nil
	}

	var findings []models.Finding
	var warnings []string
	totalVectors := 0
	totalProbes := 0

	for _, ep := range sc.Endpoints {
		// Skip static assets — low value for active testing.
		if ep.Category == models.EndpointAsset {
			continue
		}

		select {
		case <-ctx.Done():
			warnings = append(warnings, "active-tester: context cancelled, stopped early")
			return scanner.StageResult{Findings: findings, Warnings: warnings}, nil
		default:
		}

		vectors := ExtractVectors(ep)
		if len(vectors) == 0 {
			continue
		}

		totalVectors += len(vectors)

		for _, vec := range vectors {
			for _, rule := range s.registry.Rules() {
				select {
				case <-ctx.Done():
					return scanner.StageResult{Findings: findings, Warnings: warnings}, nil
				default:
				}

				result, err := rule.Test(ctx, s.client.WithAuth(sc.Auth.RequestHeaders()), vec)
				totalProbes += result.RequestsMade
				if err != nil {
					warnings = append(warnings, fmt.Sprintf(
						"active-tester: rule %s on %s[%s]: %v",
						rule.ID(), ep.URL, vec.Name, err,
					))
					continue
				}
				if result.Found {
					findings = append(findings, rule.ToFinding(result, sc.Target.Raw))
				}
			}
		}
	}

	if sc.Verbose {
		warnings = append(warnings, fmt.Sprintf(
			"active-tester: tested %d vectors across %d endpoints (%d HTTP probes)",
			totalVectors, len(sc.Endpoints), totalProbes,
		))
	}

	return scanner.StageResult{Findings: findings, Warnings: warnings}, nil
}
