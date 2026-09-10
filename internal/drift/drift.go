// Package drift implements the live-fire drift monitor (Wave 4 item
// 152): compare a current scan against an authorized baseline and
// verify parser pins. Parser pins (stage → version) guard against
// silent detection changes: if the running parser set differs from the
// pinned file, the comparison is flagged UNRELIABLE instead of
// silently passing. Pure functions over ScanSummary JSON — unit-tested,
// no network.
package drift

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/anpu-project/anpu/pkg/models"
)

// ParserVersions pins the detection logic that produced a baseline.
// Bump a version whenever that stage's detection changes.
func ParserVersions() map[string]string {
	return map[string]string{
		"headers": "2", "cookies": "2", "tls": "2", "technology": "3",
		"active": "5", "takeover": "2", "takeoverplus": "1",
		"secrets": "3", "jssecrets": "1", "dirs": "2", "backup": "2",
		"backupplus": "1", "cors": "2", "corsplus": "1", "methods": "2",
		"nuclei": "2", "graphqlfp": "1", "graphqlschema": "1",
	}
}

// Result is a baseline-vs-current comparison.
type Result struct {
	Reliable      bool     `json:"reliable"`
	PinDrift      []string `json:"pin_drift,omitempty"`
	Added         []string `json:"added"`
	Removed       []string `json:"removed"`
	RiskBefore    float64  `json:"risk_before"`
	RiskAfter     float64  `json:"risk_after"`
	EndpointDelta int      `json:"endpoint_delta"`
}

// LoadSummary reads a ScanSummary report JSON.
func LoadSummary(path string) (*models.ScanSummary, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- CLI reads operator-specified paths (reports, wordlists, checkpoints, code dir).
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var s models.ScanSummary
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &s, nil
}

// LoadPins reads a parser-pin file (JSON map stage→version). Missing
// path yields nil pins (comparison proceeds, marked unpinned).
func LoadPins(path string) (map[string]string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path) // #nosec G304 -- CLI reads operator-specified paths (reports, wordlists, checkpoints, code dir).
	if err != nil {
		return nil, fmt.Errorf("reading pins %s: %w", path, err)
	}
	var pins map[string]string
	if err := json.Unmarshal(data, &pins); err != nil {
		return nil, fmt.Errorf("parsing pins %s: %w", path, err)
	}
	return pins, nil
}

// Compare diffs current against baseline under pins (nil pins =
// unpinned but still compared; Reliable=false with a note).
func Compare(baseline, current *models.ScanSummary, pins map[string]string) *Result {
	r := &Result{Reliable: true, RiskBefore: baseline.RiskScore, RiskAfter: current.RiskScore,
		EndpointDelta: len(current.Endpoints) - len(baseline.Endpoints)}
	if pins == nil {
		r.Reliable = false
		r.PinDrift = []string{"no pins file: comparison is unpinned"}
	} else {
		running := ParserVersions()
		for stage, want := range pins {
			if got, ok := running[stage]; !ok || got != want {
				r.Reliable = false
				r.PinDrift = append(r.PinDrift, fmt.Sprintf("%s: pinned %s, running %s", stage, want, got))
			}
		}
		sort.Strings(r.PinDrift)
	}
	before := map[string]bool{}
	for _, f := range baseline.Findings {
		before[f.ID] = true
	}
	after := map[string]bool{}
	for _, f := range current.Findings {
		after[f.ID] = true
	}
	for id := range after {
		if !before[id] {
			r.Added = append(r.Added, id)
		}
	}
	for id := range before {
		if !after[id] {
			r.Removed = append(r.Removed, id)
		}
	}
	sort.Strings(r.Added)
	sort.Strings(r.Removed)
	return r
}

// WritePins writes the current parser set for nightly pinning.
func WritePins(path string) error {
	data, err := json.MarshalIndent(ParserVersions(), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}
