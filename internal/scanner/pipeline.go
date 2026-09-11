package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

// StageProgress is emitted after each pipeline stage completes, for the
// terminal UI to render progress.
type StageProgress struct {
	StageName string
	Done      bool
	Skipped   bool
	// Reason explains a skip in human terms (e.g. "deep profile only").
	// Empty when the stage ran.
	Reason           string
	Err              error
	NewFindingsCount int
	WarningsCount    int
	// Phase carries the stage's pipeline phase so the UI can print
	// phase headers when the phase changes.
	Phase Phase
}

// ProgressFunc is called after each stage. It may be nil.
type ProgressFunc func(StageProgress)

// Phase is a pipeline execution phase. Stages run phase by phase
// (Foundation → Discovery → Targeted → Active) so every stage's
// inputs (fingerprints, endpoints, parameters) are produced before
// its consumers run. Within a phase, snapshot-safe stages may run
// concurrently; ordering inside a phase is deterministic.
type Phase string

const (
	PhaseFoundation Phase = "foundation"
	PhaseDiscovery  Phase = "discovery"
	PhaseTargeted   Phase = "targeted"
	PhaseActive     Phase = "active"
)

// PhaseOrder ranks phases for sorting (stable sort keeps the
// declaration order inside each phase, preserving every documented
// stage-ordering constraint).
var PhaseOrder = map[Phase]int{
	PhaseFoundation: 0,
	PhaseDiscovery:  1,
	PhaseTargeted:   2,
	PhaseActive:     3,
}

// Stage pairs a named pipeline step with the module toggle that governs
// whether it runs, and the Scanner that implements it.
type Stage struct {
	Label   string
	Enabled bool
	// SkipReason is reported when Enabled is false so the terminal can
	// say why instead of printing a bare dash.
	SkipReason string
	Scanner    Scanner
	// Phase gates sequencing: a stage never runs before all stages of
	// earlier phases. Empty means Targeted (the default bucket).
	Phase Phase
	// Concurrent marks snapshot-safe stages (no reads of accumulated
	// Endpoints/Technologies/Subdomains): contiguous enabled runs of
	// these execute in parallel when MaxParallel > 1, merged back in
	// stage order so output stays deterministic.
	Concurrent bool
}

// Pipeline runs an ordered list of Stages against a validated target and
// aggregates their output into a ScanSummary.
type Pipeline struct {
	Client *anpuhttp.Client
	Stages []Stage
	// MaxParallel caps concurrent workers for Concurrent stage runs
	// (0/1 = legacy sequential). CheckpointFile, when set, receives a
	// JSON snapshot after every completed stage; ResumeFile loads such
	// a snapshot and skips already-completed stages.
	MaxParallel    int
	CheckpointFile string
	ResumeFile     string
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
	confidenceFilter func([]models.Finding) ([]models.Finding, []models.Finding),
	progress ProgressFunc,
) (*models.ScanSummary, error) {
	sess := NewSession()
	pool := NewArtifactPool()
	if p.Client != nil && sess.Jar != nil {
		p.Client = p.Client.WithJar(sess.Jar)
	}
	// Global per-tool budget ledger (Wave 4 item 151): bounded miners
	// charge here and stop at their caps; everything else is uncapped
	// but still counted toward the global total.
	ledger := anpuhttp.NewLedger(anpuhttp.DefaultMaxTotal)
	ledger.SetCap("hiddenparams", 64)
	ledger.SetCap("backupplus", 61)
	ledger.SetCap("apiversion", 11)
	ledger.SetCap("apiconsole", 11)
	sc := &ScanContext{
		Target:       target,
		Config:       cfg,
		Verbose:      cfg.Verbose,
		Auth:         cfg.Auth,
		Session:      sess,
		ArtifactPool: pool,
		Ledger:       ledger,
	}

	summary := &models.ScanSummary{
		ID:        newScanID(),
		Target:    target.Raw,
		Profile:   cfg.Profile,
		StartedAt: time.Now(),
		Status:    "running",
		// Store the role label only — never credential values.
		AuthRole: string(cfg.Auth.EffectiveRole()),
	}

	// Phase sequencing: default empty phases to Targeted, then stable-sort
	// so Foundation → Discovery → Targeted → Active while preserving the
	// declaration order (and every documented ordering constraint) inside
	// each phase. --only selections keep their relative order.
	for i := range p.Stages {
		if p.Stages[i].Phase == "" {
			p.Stages[i].Phase = PhaseTargeted
		}
	}
	sort.SliceStable(p.Stages, func(i, j int) bool {
		return PhaseOrder[p.Stages[i].Phase] < PhaseOrder[p.Stages[j].Phase]
	})

	// Phase timing ledger: wall time + stage count per phase, plus
	// every executed stage's own wall time for the slowest-5 ledger.
	phaseTime := map[Phase]time.Duration{}
	phaseStages := map[Phase]int{}
	stageDur := map[string]time.Duration{}
	charge := func(ph Phase, d time.Duration) {
		phaseTime[ph] += d
		phaseStages[ph]++
	}

	if p.Client != nil && !cfg.SkipPreCheck {
		ctxTimeout, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		_, err := p.Client.HeadOrGet(ctxTimeout, target.Raw)
		if err != nil && isNetworkError(err) {
			summary.Status = "failed"
			summary.StatusReason = fmt.Sprintf("connectivity check failed: %v", err)
			return nil, fmt.Errorf("target is unreachable: %v", err)
		}
	}

	// Resume: preload completed stage results; matching stages merge
	// without running (progress reports them as resumed skips).
	resumed := map[string]StageResult{}
	if p.ResumeFile != "" {
		if loaded, rerr := loadCheckpoint(p.ResumeFile); rerr != nil {
			summary.Warnings = append(summary.Warnings, fmt.Sprintf("resume: %v (starting fresh)", rerr))
		} else {
			if loaded.Target != "" && loaded.Target != target.Raw {
				summary.Warnings = append(summary.Warnings, fmt.Sprintf("resume: checkpoint target %q != %q", loaded.Target, target.Raw))
			}
			resumed = loaded.Stages
		}
	}

	workers := p.MaxParallel
	if workers < 1 {
		workers = 1
	}
	if workers > 32 {
		workers = 32
	}

	// completed tracks per-stage results in stage order for checkpoints.
	completed := map[string]StageResult{}
	// merge folds one completed stage into the summary + scan context
	// (shared by the sequential path and parallel-group merges, so
	// ordering semantics stay identical). Local-code findings are
	// partitioned into the unscored appendix at merge time so stage
	// progress, dedup, scoring, and counts below only ever see the
	// target finding set.
	merge := func(stage Stage, result StageResult) {
		completed[stage.Label] = result
		for _, f := range result.Findings {
			if f.IsLocalCode() {
				summary.CodeFindings = append(summary.CodeFindings, f)
			} else {
				summary.Findings = append(summary.Findings, f)
			}
		}
		summary.Technologies = append(summary.Technologies, result.Technologies...)
		summary.Endpoints = append(summary.Endpoints, result.Endpoints...)
		summary.Warnings = appendWarningsDeduped(summary.Warnings, result.Warnings...)
		sc.Technologies = summary.Technologies
		sc.Endpoints = summary.Endpoints
		sc.Subdomains = append(sc.Subdomains, result.Subdomains...)
		if stage.Label == "Recon" && len(result.Endpoints) > 0 && sc.ArtifactPool != nil {
			var eps []string
			for _, ep := range result.Endpoints {
				eps = append(eps, ep.URL)
			}
			sc.ArtifactPool.Add("endpoints", eps...)
		}
		if sc.Session == nil {
			sc.Session = sess
		}
		if sc.ArtifactPool == nil {
			sc.ArtifactPool = pool
		}
		if p.CheckpointFile != "" {
			saveCheckpoint(p.CheckpointFile, target.Raw, string(cfg.Profile), completed)
		}
	}

	// runOne executes a single stage against a context snapshot.
	runOne := func(ctx context.Context, stage Stage, snap *ScanContext) (StageResult, error) {
		isGhostActive := anpuhttp.IsGhost() && anpuhttp.GhostWorkers > 1 && stage.Label == "Active"
		if isGhostActive && len(snap.Endpoints) > 0 {
			return p.runGhostSharded(ctx, stage, snap)
		}
		return stage.Scanner.Run(ctx, snap)
	}

	i := 0
	for i < len(p.Stages) {
		stage := p.Stages[i]
		if !stage.Enabled {
			if progress != nil {
				progress(StageProgress{StageName: stage.Label, Skipped: true, Reason: stage.SkipReason, Phase: stage.Phase})
			}
			i++
			continue
		}
		if !stage.Scanner.Available(ctx) {
			if progress != nil {
				progress(StageProgress{StageName: stage.Label, Skipped: true, Reason: "optional — not installed", Phase: stage.Phase})
			}
			i++
			continue
		}
		if prev, ok := resumed[stage.Label]; ok {
			merge(stage, prev)
			if progress != nil {
				progress(StageProgress{StageName: stage.Label, Skipped: true, Reason: "resumed from checkpoint", Phase: stage.Phase})
			}
			i++
			continue
		}

		// Parallel group: maximal contiguous run of enabled, available,
		// concurrent stages. Each gets a snapshot; results merge back
		// in stage order for deterministic output.
		if workers > 1 && stage.Concurrent {
			j := i
			for j < len(p.Stages) && p.Stages[j].Enabled && p.Stages[j].Concurrent && p.Stages[j].Scanner.Available(ctx) {
				if _, ok := resumed[p.Stages[j].Label]; ok {
					break
				}
				j++
			}
			if j-i > 1 {
				group := p.Stages[i:j]
				results := p.runGroup(ctx, group, sc, workers, runOne)
				for k, st := range group {
					preDedupCount := len(dedup(summary.Findings))
					res, rerr := results[k].res, results[k].err
					charge(st.Phase, results[k].dur)
					stageDur[st.Label] = results[k].dur
					if rerr != nil {
						summary.Warnings = append(summary.Warnings, fmt.Sprintf("%s: %v", st.Label, rerr))
						if progress != nil {
							progress(StageProgress{StageName: st.Label, Err: rerr, Phase: st.Phase})
						}
						continue
					}
					if res.Skipped != "" {
						completed[st.Label] = res
						if progress != nil {
							progress(StageProgress{StageName: st.Label, Skipped: true, Reason: res.Skipped, Phase: st.Phase})
						}
						continue
					}
					merge(st, res)
					if progress != nil {
						postDedupCount := len(dedup(summary.Findings))
						progress(StageProgress{
							StageName:        st.Label,
							Done:             true,
							NewFindingsCount: postDedupCount - preDedupCount,
							WarningsCount:    len(res.Warnings),
							Phase:            st.Phase,
						})
					}
				}
				i = j
				continue
			}
		}

		preDedupCount := len(dedup(summary.Findings))

		t0 := time.Now()
		result, err := runOne(ctx, stage, sc)
		d := time.Since(t0)
		charge(stage.Phase, d)
		stageDur[stage.Label] = d
		if err != nil {
			summary.Warnings = append(summary.Warnings, fmt.Sprintf("%s: %v", stage.Label, err))
			if progress != nil {
				progress(StageProgress{StageName: stage.Label, Err: err, Phase: stage.Phase})
			}
			i++
			continue
		}

		if result.Skipped != "" {
			completed[stage.Label] = result
			if progress != nil {
				progress(StageProgress{StageName: stage.Label, Skipped: true, Reason: result.Skipped, Phase: stage.Phase})
			}
			i++
			continue
		}

		merge(stage, result)

		if progress != nil {
			postDedupCount := len(dedup(summary.Findings))
			progress(StageProgress{
				StageName:        stage.Label,
				Done:             true,
				NewFindingsCount: postDedupCount - preDedupCount,
				WarningsCount:    len(result.Warnings),
				Phase:            stage.Phase,
			})
		}
		i++
	}

	summary.Findings = dedup(summary.Findings)
	summary.Findings = score(summary.Findings)
	if confidenceFilter != nil {
		kept, suppressed := confidenceFilter(summary.Findings)
		summary.Findings = kept
		summary.SuppressedByConfidence = len(suppressed)
	}
	summary.RiskScore = aggregateScore(summary.Findings)
	summary.RecomputeSeverityCounts()
	// Phase ledger, ordered foundation → active.
	for _, ph := range []Phase{PhaseFoundation, PhaseDiscovery, PhaseTargeted, PhaseActive} {
		if phaseStages[ph] == 0 && phaseTime[ph] == 0 {
			continue
		}
		summary.PhaseTimings = append(summary.PhaseTimings, models.PhaseTiming{
			Phase:   string(ph),
			Seconds: math.Round(phaseTime[ph].Seconds()*10) / 10,
			Stages:  phaseStages[ph],
		})
	}
	// Slowest-5 stages, slowest first (cap 5, 0.1s resolution).
	type stageCost struct {
		label string
		dur   time.Duration
	}
	var costs []stageCost
	for label, d := range stageDur {
		costs = append(costs, stageCost{label, d})
	}
	sort.Slice(costs, func(i, j int) bool {
		if costs[i].dur == costs[j].dur {
			return costs[i].label < costs[j].label
		}
		return costs[i].dur > costs[j].dur
	})
	for i, c := range costs {
		if i >= 5 {
			break
		}
		summary.SlowestStages = append(summary.SlowestStages, models.StageTiming{
			Stage:   c.label,
			Seconds: math.Round(c.dur.Seconds()*10) / 10,
		})
	}
	// Local-code appendix: scored for display with the same functions,
	// but never confidence-filtered out silently, never counted, and
	// never aggregated into RiskScore.
	summary.CodeFindings = dedup(summary.CodeFindings)
	summary.CodeFindings = score(summary.CodeFindings)
	summary.Technologies = dedupTechs(summary.Technologies)
	summary.Endpoints = dedupEndpoints(summary.Endpoints)

	summary.CompletedAt = time.Now()
	summary.Status = "completed"

	return summary, nil
}

// stageOutcome carries one concurrent stage result back in order.
type stageOutcome struct {
	res StageResult
	err error
	// dur is the stage's own wall time (for the phase timing ledger).
	dur time.Duration
}

// snapshotContext copies the ScanContext shell for concurrent stages.
// Slices are shared read-only (no scanner mutates them — verified by
// grep over sc.Endpoints/Technologies/Subdomains assignments); Session,
// ArtifactPool, Ledger, and Client stay shared pointers and are all
// mutex-guarded internally.
func snapshotContext(sc *ScanContext) *ScanContext {
	cp := *sc
	return &cp
}

// runGroup executes a Concurrent stage run with at most workers stages
// in flight, returning outcomes in stage order.
func (p *Pipeline) runGroup(ctx context.Context, group []Stage, sc *ScanContext, workers int, runOne func(context.Context, Stage, *ScanContext) (StageResult, error)) []stageOutcome {
	if workers > len(group) {
		workers = len(group)
	}
	out := make([]stageOutcome, len(group))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for k, st := range group {
		// Availability was checked when forming the group, but re-check
		// cheaply per stage for safety.
		if !st.Scanner.Available(ctx) {
			out[k] = stageOutcome{err: fmt.Errorf("optional — not installed")}
			continue
		}
		wg.Add(1)
		go func(idx int, stage Stage) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			t0 := time.Now()
			res, err := runOne(ctx, stage, snapshotContext(sc))
			out[idx] = stageOutcome{res: res, err: err, dur: time.Since(t0)}
		}(k, st)
	}
	wg.Wait()
	return out
}

// runGhostSharded runs the Active stage sharded across ghost workers
// (extracted unchanged from the sequential path).
func (p *Pipeline) runGhostSharded(ctx context.Context, stage Stage, sc *ScanContext) (StageResult, error) {
	numWorkers := anpuhttp.GhostWorkers
	if numWorkers > len(sc.Endpoints) {
		numWorkers = len(sc.Endpoints)
	}
	shards := make([][]models.Endpoint, numWorkers)
	for i, ep := range sc.Endpoints {
		shards[i%numWorkers] = append(shards[i%numWorkers], ep)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var combined StageResult
	var combinedErr error
	for _, shard := range shards {
		if len(shard) == 0 {
			continue
		}
		wg.Add(1)
		go func(sh []models.Endpoint) {
			defer wg.Done()
			shardSC := &ScanContext{
				Target:       sc.Target,
				Config:       sc.Config,
				Verbose:      sc.Verbose,
				Auth:         sc.Auth,
				Session:      sc.Session,
				ArtifactPool: sc.ArtifactPool,
				Technologies: sc.Technologies,
				Endpoints:    sh,
				Subdomains:   sc.Subdomains,
			}
			res, e := stage.Scanner.Run(ctx, shardSC)
			mu.Lock()
			if e != nil && combinedErr == nil {
				combinedErr = e
			} else if e == nil {
				combined.Findings = append(combined.Findings, res.Findings...)
				combined.Technologies = append(combined.Technologies, res.Technologies...)
				combined.Endpoints = append(combined.Endpoints, res.Endpoints...)
				combined.Subdomains = append(combined.Subdomains, res.Subdomains...)
				combined.Warnings = appendWarningsDeduped(combined.Warnings, res.Warnings...)
			}
			mu.Unlock()
		}(shard)
	}
	wg.Wait()
	return combined, combinedErr
}

// checkpointFile is the on-disk resume format: completed stage results
// keyed by stage label, plus target/profile for mismatch warnings.
// Version guards resume across renames: a stage renamed between the
// checkpoint write and the resume would otherwise merge stale results
// under a dead label while the renamed stage re-ran — silent double
// counting. Bump CheckpointVersion whenever stage labels change
// meaningfully; mismatched files restart fresh with a warning.
type checkpointFile struct {
	Version int                    `json:"version"`
	Target  string                 `json:"target"`
	Profile string                 `json:"profile"`
	Stages  map[string]StageResult `json:"stages"`
}

// CheckpointVersion is the current checkpoint schema version.
const CheckpointVersion = 1

// saveCheckpoint persists completed stages so far (best-effort: write
// errors are silently dropped so checkpointing never fails a scan).
func saveCheckpoint(path, target, profile string, completed map[string]StageResult) {
	data, err := json.Marshal(checkpointFile{Version: CheckpointVersion, Target: target, Profile: profile, Stages: completed})
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0o600)
}

// loadCheckpoint reads a checkpoint file for --resume. Unknown or
// legacy-unversioned files are rejected (not merged) so resume can
// never silently mix incompatible stage results.
func loadCheckpoint(path string) (checkpointFile, error) {
	var cp checkpointFile
	data, err := os.ReadFile(path) // #nosec G304 -- CLI reads operator-specified paths (reports, wordlists, checkpoints, code dir).
	if err != nil {
		return cp, err
	}
	if err := json.Unmarshal(data, &cp); err != nil {
		return cp, fmt.Errorf("parsing checkpoint %s: %w", path, err)
	}
	if cp.Version != CheckpointVersion {
		return cp, fmt.Errorf("checkpoint %s is version %d (need %d): re-run with --checkpoint to regenerate", path, cp.Version, CheckpointVersion)
	}
	if cp.Stages == nil {
		cp.Stages = map[string]StageResult{}
	}
	return cp, nil
}

func dedupTechs(in []models.Technology) []models.Technology {
	seen := map[string]bool{}
	var out []models.Technology
	for _, t := range in {
		// Normalize case: "Cloudflare" (headers) and "cloudflare" (nuclei
		// tech-detect) are the same stack, not two technologies.
		key := strings.ToLower(strings.TrimSpace(t.Name)) + "|" + strings.ToLower(strings.TrimSpace(t.Version)) + "|" + strings.ToLower(strings.TrimSpace(t.Category))
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, t)
	}
	return out
}

// appendWarningsDeduped appends stage warnings, dropping exact duplicates
// (e.g. PortScan and its Naabu fallback reporting the same middlebox
// condition). First occurrence order is preserved.
func appendWarningsDeduped(dst []string, src ...string) []string {
	seen := map[string]bool{}
	for _, w := range dst {
		seen[w] = true
	}
	for _, w := range src {
		if seen[w] {
			continue
		}
		seen[w] = true
		dst = append(dst, w)
	}
	return dst
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
			// Union schema params so API-aware probing survives the
			// merge with crawler-discovered copies of the same URL.
			for _, p := range e.Params {
				dup := false
				for _, q := range existing.Params {
					if q.Name == p.Name && q.In == p.In {
						dup = true
						break
					}
				}
				if !dup {
					existing.Params = append(existing.Params, p)
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
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "no such host") ||
		strings.Contains(s, "connection refused") ||
		strings.Contains(s, "all resolved addresses failed") ||
		strings.Contains(s, "could not connect") ||
		strings.Contains(s, "i/o timeout") ||
		strings.Contains(s, "network is unreachable") ||
		strings.Contains(s, "context deadline exceeded") ||
		strings.Contains(s, "refusing connection") ||
		strings.Contains(s, "dial tcp") ||
		// DNS resolution failures (Windows reports these as
		// getaddrinfow / temporary hostname-resolution errors
		// rather than "no such host").
		strings.Contains(s, "getaddrinfo") ||
		strings.Contains(s, "hostname resolution") ||
		strings.Contains(s, "resolving \"") ||
		strings.Contains(s, "lookup ") ||
		strings.Contains(s, "no addresses") ||
		strings.Contains(s, "dns")
}
