package authz

import (
	"context"
	"fmt"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// Scanner implements scanner.Scanner for authorization comparison testing.
// It requires two AuthContexts (A = baseline, B = challenger) and a list
// of endpoints to probe, which it takes from sc.Endpoints (populated by
// the Endpoints stage that runs before it in the pipeline).
type Scanner struct {
	client   *anpuhttp.Client
	contextB models.AuthContext
}

// New returns an authz.Scanner.  contextB is the challenger identity;
// the baseline (context A) is taken from sc.Auth at Run time.
func New(client *anpuhttp.Client, contextB models.AuthContext) *Scanner {
	return &Scanner{client: client, contextB: contextB}
}

func (s *Scanner) Name() string { return "authz-tester" }

// Available returns true when a non-anonymous challenger context has been
// configured.  Without a second identity there is nothing to compare.
func (s *Scanner) Available(_ context.Context) bool {
	return s.contextB.IsAuthenticated() || s.contextB.Method == models.AuthMethodNone
}

// Run probes every discovered endpoint under both identity contexts and
// produces findings for any authorization anomalies detected.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	contextA := sc.Auth
	contextB := s.contextB

	// Need at least one real identity to compare; two anonymous contexts
	// would produce nothing useful.
	if !contextA.IsAuthenticated() && !contextB.IsAuthenticated() {
		return scanner.StageResult{
			Warnings: []string{
				"authz-tester: skipped — both contexts are anonymous; " +
					"supply --authz-token / --authz-cookie / --authz-header for a second identity",
			},
		}, nil
	}

	endpoints := sc.Endpoints
	if len(endpoints) == 0 {
		return scanner.StageResult{
			Warnings: []string{"authz-tester: no endpoints discovered; nothing to probe"},
		}, nil
	}

	var findings []models.Finding
	var warnings []string
	probed := 0

	for _, ep := range endpoints {
		// Skip assets — probing JS/CSS/images for authz issues is noise.
		if ep.Category == models.EndpointAsset {
			continue
		}

		select {
		case <-ctx.Done():
			warnings = append(warnings, "authz-tester: context cancelled, stopped early")
			return scanner.StageResult{Findings: findings, Warnings: warnings}, nil
		default:
		}

		probeA, errA := Probe(ctx, s.client, contextA, ep.URL)
		if errA != nil {
			warnings = append(warnings, fmt.Sprintf("authz-tester: probe A failed for %s: %v", ep.URL, errA))
			continue
		}

		probeB, errB := Probe(ctx, s.client, contextB, ep.URL)
		if errB != nil {
			warnings = append(warnings, fmt.Sprintf("authz-tester: probe B failed for %s: %v", ep.URL, errB))
			continue
		}

		probed++

		if anomaly := Compare(ep.URL, "GET", probeA, probeB); anomaly != nil {
			findings = append(findings, ToFinding(anomaly, sc.Target.Raw))
		}
	}

	if probed == 0 {
		warnings = append(warnings, "authz-tester: no non-asset endpoints were reachable for both contexts")
	}

	return scanner.StageResult{Findings: findings, Warnings: warnings}, nil
}
