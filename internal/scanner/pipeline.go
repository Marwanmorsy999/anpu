package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

// StageProgress is emitted after each pipeline stage completes, for the
// terminal UI to render progress.
type StageProgress struct {
	StageName        string
	Done             bool
	Skipped          bool
	Err              error
	NewFindingsCount int
	WarningsCount    int
}

// ProgressFunc is called after each stage. It may be nil.
type ProgressFunc func(StageProgress)

// Stage pairs a named pipeline step with the module toggle that governs
// whether it runs, and the Scanner that implements it.
type Stage struct {
	Label   string
	Enabled bool
	Scanner Scanner
}

// Pipeline runs an ordered list of Stages against a validated target and
// aggregates their output into a ScanSummary.
type Pipeline struct {
	Client *anpuhttp.Client
	Stages []Stage
}

// Run executes every enabled, available stage in order, aggregates
// their findings/technologies/endpoints, deduplicates and scores the
// result. Deduplication and scoring are injected as function parameters
// so this package doesn't need to import findings/scoring directly
// (keeping the dependency graph acyclic and each package independently
// testable).
func (p *Pipeline) Run(
	ctx context.Context,
	target *ValidatedTarget,
	cfg models.ScanConfig,
	dedup func([]models.Finding) []models.Finding,
	score func([]models.Finding) []models.Finding,
	aggregateScore func([]models.Finding) float64,
	progress ProgressFunc,
) (*models.ScanSummary, error) {
	sc := &ScanContext{
		Target:  target,
		Config:  cfg,
		Verbose: cfg.Verbose,
	}

	summary := &models.ScanSummary{
		ID:        newScanID(),
		Target:    target.Raw,
		Profile:   cfg.Profile,
		StartedAt: time.Now(),
		Status:    "running",
	}

	if p.Client != nil && !cfg.SkipPreCheck {
		ctxTimeout, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		_, err := p.Client.HeadOrGet(ctxTimeout, target.Raw.String())
		if err != nil && isNetworkError(err) {
			summary.Status = "failed"
			summary.StatusReason = fmt.Sprintf("connectivity check failed: %v", err)
			return nil, fmt.Errorf("target is unreachable: %v", err)
		}
	}

	for _, stage := range p.Stages {
		if !stage.Enabled {
			if progress != nil {
				progress(StageProgress{StageName: stage.Label, Skipped: true})
			}
			continue
		}
		if !stage.Scanner.Available(ctx) {
			summary.Warnings = append(summary.Warnings, fmt.Sprintf("%s: scanner unavailable, stage skipped", stage.Label))
			if progress != nil {
				progress(StageProgress{StageName: stage.Label, Skipped: true})
			}
			continue
		}

		preDedupCount := len(dedup(summary.Findings))

		result, err := stage.Scanner.Run(ctx, sc)
		if err != nil {
			summary.Warnings = append(summary.Warnings, fmt.Sprintf("%s: %v", stage.Label, err))
			if progress != nil {
				progress(StageProgress{StageName: stage.Label, Err: err})
			}
			continue
		}

		summary.Findings = append(summary.Findings, result.Findings...)
		summary.Technologies = append(summary.Technologies, result.Technologies...)
		summary.Endpoints = append(summary.Endpoints, result.Endpoints...)
		summary.Warnings = append(summary.Warnings, result.Warnings...)

		// Make discoveries so far available to later stages (e.g. so a
		// future custom analyzer could target discovered endpoints).
		sc.Technologies = summary.Technologies
		sc.Endpoints = summary.Endpoints

		if progress != nil {
			postDedupCount := len(dedup(summary.Findings))
			progress(StageProgress{
				StageName:        stage.Label, 
				Done:             true,
				NewFindingsCount: postDedupCount - preDedupCount,
				WarningsCount:    len(result.Warnings),
			})
		}
	}

	summary.Findings = dedup(summary.Findings)
	summary.Findings = score(summary.Findings)
	summary.RiskScore = aggregateScore(summary.Findings)
	summary.RecomputeSeverityCounts()
	summary.Technologies = dedupTechs(summary.Technologies)
	summary.Endpoints = dedupEndpoints(summary.Endpoints)

	summary.CompletedAt = time.Now()
	summary.Status = "completed"

	return summary, nil
}

func dedupTechs(in []models.Technology) []models.Technology {
	seen := map[string]bool{}
	var out []models.Technology
	for _, t := range in {
		key := t.Name + "|" + t.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, t)
	}
	return out
}

func dedupEndpoints(in []models.Endpoint) []models.Endpoint {
	seen := map[string]int{}
	var out []models.Endpoint
	for _, e := range in {
		if idx, ok := seen[e.URL]; ok {
			existing := &out[idx]
			for _, src := range e.Sources {
				found := false
				for _, s := range existing.Sources {
					if s == src {
						found = true
						break
					}
				}
				if !found {
					existing.Sources = append(existing.Sources, src)
				}
			}
			continue
		}
		seen[e.URL] = len(out)
		out = append(out, e)
	}
	return out
}

var scanIDCounter int64

func newScanID() string {
	scanIDCounter++
	return fmt.Sprintf("scan-%d-%d", time.Now().Unix(), scanIDCounter)
}

func isNetworkError(err error) bool {
	s := err.Error()
	return strings.Contains(s, "no such host") ||
		strings.Contains(s, "connection refused") ||
		strings.Contains(s, "all resolved addresses failed") ||
		strings.Contains(s, "i/o timeout") ||
		strings.Contains(s, "network is unreachable") ||
		strings.Contains(s, "context deadline exceeded") ||
		strings.Contains(s, "refusing connection") ||
		strings.Contains(s, "dial tcp")
}
