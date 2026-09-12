// Package bench implements ANPU's honesty benchmark: measuring detection
// against planted ground-truth signals instead of asserting perfection.
//
// The benchmark deliberately reports what ANPU did NOT detect. A signal
// lists an expectation per profile ("hit" or "miss-expected"); findings
// matching no signal are counted as UNMATCHED, never auto-labeled false
// positives — the harness cannot prove a negative, and it does not try.
//
// Stability: only counts and verdicts enter the Markdown table (no
// timings, no finding IDs), so repeated runs of an unchanged scanner
// produce byte-identical output suitable for freshness gating.
package bench

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// Expectation values for Signal.Profiles entries.
const (
	ExpectHit  = "hit"
	ExpectMiss = "miss-expected"
)

// Verdicts for a signal outcome.
const (
	VerdictOK          = "ok"
	VerdictMISS        = "MISS"
	VerdictSurpriseHit = "surprise-hit"
	OutcomeHIT         = "HIT"
	OutcomeMISS        = "MISS"
	MarkerStart        = "<!-- BENCH:START -->"
	MarkerEnd          = "<!-- BENCH:END -->"
)

// MatchRule selects findings for a signal. All specified keys must hold;
// matching is deliberately loose (substring, case-insensitive titles) so
// the benchmark measures signal detection, not engine identity.
type MatchRule struct {
	TitleContains string `yaml:"title_contains"`
	Category      string `yaml:"category"`
	Path          string `yaml:"path"`
}

// Signal is one planted weakness with per-profile expectations.
type Signal struct {
	ID          string            `yaml:"id"`
	Description string            `yaml:"description"`
	Path        string            `yaml:"path"`
	Match       MatchRule         `yaml:"match"`
	Gate        *bool             `yaml:"gate"`
	Profiles    map[string]string `yaml:"profiles"`
}

// Gated reports whether the signal participates in --check freshness
// comparison. Signals observed flaky during calibration set gate: false:
// still measured and shown, excluded from the gate until root-caused.
func (s Signal) Gated() bool { return s.Gate == nil || *s.Gate }

// effectivePath falls back to the signal-level path when the match rule
// carries no path of its own.
func (s Signal) effectivePath() string {
	if s.Match.Path != "" {
		return s.Match.Path
	}
	return s.Path
}

// GroundTruth is the parsed ground-truth.yml contract.
type GroundTruth struct {
	Version    int      `yaml:"version"`
	TargetHint string   `yaml:"target_hint"`
	Signals    []Signal `yaml:"signals"`
}

// LoadGroundTruth parses and validates a ground-truth file.
func LoadGroundTruth(path string) (*GroundTruth, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-specified bench input path.
	if err != nil {
		return nil, fmt.Errorf("reading ground truth %s: %w", path, err)
	}
	var gt GroundTruth
	if err := yaml.Unmarshal(data, &gt); err != nil {
		return nil, fmt.Errorf("parsing ground truth %s: %w", path, err)
	}
	if gt.Version != 1 {
		return nil, fmt.Errorf("ground truth %s: unsupported version %d (want 1)", path, gt.Version)
	}
	if len(gt.Signals) == 0 {
		return nil, fmt.Errorf("ground truth %s: no signals defined", path)
	}
	seen := map[string]bool{}
	for i, s := range gt.Signals {
		if s.ID == "" {
			return nil, fmt.Errorf("ground truth %s: signal %d has no id", path, i)
		}
		if seen[s.ID] {
			return nil, fmt.Errorf("ground truth %s: duplicate signal id %q", path, s.ID)
		}
		seen[s.ID] = true
		if s.Match.TitleContains == "" && s.Match.Category == "" && s.effectivePath() == "" {
			return nil, fmt.Errorf("ground truth %s: signal %q has an empty match rule (would match everything)", path, s.ID)
		}
		for profile, exp := range s.Profiles {
			if exp != ExpectHit && exp != ExpectMiss {
				return nil, fmt.Errorf("ground truth %s: signal %q profile %q has invalid expectation %q (want %q or %q)",
					path, s.ID, profile, exp, ExpectHit, ExpectMiss)
			}
		}
	}
	return &gt, nil
}

// matches reports whether a finding satisfies every specified match key.
func matches(f models.Finding, s Signal) bool {
	m := s.Match
	if m.TitleContains != "" &&
		!strings.Contains(strings.ToLower(f.Title), strings.ToLower(m.TitleContains)) {
		return false
	}
	if m.Category != "" && string(f.Category) != m.Category {
		return false
	}
	if p := s.effectivePath(); p != "" && !strings.Contains(f.URL, p) {
		return false
	}
	return true
}

// MatchedFinding is the stable identity of a matched finding.
type MatchedFinding struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// SignalOutcome is the evaluated result of one signal under one profile.
type SignalOutcome struct {
	SignalID    string           `json:"signal_id"`
	Description string           `json:"description"`
	Expected    string           `json:"expected"`
	Outcome     string           `json:"outcome"`
	Verdict     string           `json:"verdict"`
	Gated       bool             `json:"gated"`
	Matched     []MatchedFinding `json:"matched"`
}

// ProfileResult aggregates one scan report against ground truth.
// Confirmed means high-or-confirmed confidence; the split is documented
// here rather than reusing scoring internals so the benchmark stays a
// thin, stable measurement layer.
type ProfileResult struct {
	Profile     string           `json:"profile"`
	Total       int              `json:"total_findings"`
	ByCategory  map[string]int   `json:"by_category"`
	Confirmed   int              `json:"confirmed"`
	Unconfirmed int              `json:"unconfirmed"`
	Signals     []SignalOutcome  `json:"signals"`
	Unmatched   []MatchedFinding `json:"unmatched"`
}

// Evaluate matches every ground-truth signal against a scan report.
func Evaluate(report *models.ScanSummary, gt *GroundTruth, profile string) ProfileResult {
	res := ProfileResult{
		Profile:    profile,
		ByCategory: map[string]int{},
	}
	for _, f := range report.Findings {
		res.Total++
		res.ByCategory[string(f.Category)]++
		if f.Confidence == models.ConfidenceHigh || f.Confidence == models.ConfidenceConfirmed {
			res.Confirmed++
		} else {
			res.Unconfirmed++
		}
	}
	for _, s := range gt.Signals {
		exp, ok := s.Profiles[profile]
		if !ok {
			exp = ExpectHit
		}
		out := SignalOutcome{
			SignalID:    s.ID,
			Description: s.Description,
			Expected:    exp,
			Gated:       s.Gated(),
		}
		for _, f := range report.Findings {
			if matches(f, s) {
				out.Matched = append(out.Matched, MatchedFinding{ID: f.ID, Title: f.Title})
			}
		}
		sort.Slice(out.Matched, func(i, j int) bool { return out.Matched[i].ID < out.Matched[j].ID })
		if len(out.Matched) > 0 {
			out.Outcome = OutcomeHIT
		} else {
			out.Outcome = OutcomeMISS
		}
		switch {
		case out.Outcome == OutcomeHIT && exp == ExpectHit:
			out.Verdict = VerdictOK
		case out.Outcome == OutcomeMISS && exp == ExpectMiss:
			out.Verdict = VerdictOK
		case out.Outcome == OutcomeHIT:
			out.Verdict = VerdictSurpriseHit
		default:
			out.Verdict = VerdictMISS
		}
		res.Signals = append(res.Signals, out)
	}
	claimedSet := map[string]bool{}
	for _, o := range res.Signals {
		for _, m := range o.Matched {
			claimedSet[m.ID] = true
		}
	}
	for _, f := range report.Findings {
		if !claimedSet[f.ID] {
			res.Unmatched = append(res.Unmatched, MatchedFinding{ID: f.ID, Title: f.Title})
		}
	}
	sort.Slice(res.Unmatched, func(i, j int) bool { return res.Unmatched[i].ID < res.Unmatched[j].ID })
	return res
}
