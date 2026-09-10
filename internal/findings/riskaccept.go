package findings

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/anpu-project/anpu/pkg/models"
)

// RiskAcceptEntry is one accepted finding: matched by stable finding ID,
// documented with a reason, and automatically re-armed after Expires
// (YYYY-MM-DD, empty means no expiry).
type RiskAcceptEntry struct {
	ID      string `yaml:"id"`
	Reason  string `yaml:"reason"`
	Expires string `yaml:"expires"`
}

// LoadRiskAccept reads a risk-accept file:
//
//	accept:
//	  - id: anpu-abc123def456
//	    reason: "WAF covers this; retest in Q3"
//	    expires: 2026-12-31
func LoadRiskAccept(path string) ([]RiskAcceptEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading risk-accept file: %w", err)
	}
	var doc struct {
		Accept []RiskAcceptEntry `yaml:"accept"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing risk-accept file %s: %w", path, err)
	}
	return doc.Accept, nil
}

// ApplyRiskAccept removes accepted findings (by stable ID) and returns
// the kept findings, the suppressed IDs, and notes for expired entries
// (expired acceptances do NOT suppress — they re-arm with a note).
func ApplyRiskAccept(findings []models.Finding, entries []RiskAcceptEntry, now time.Time) (kept []models.Finding, suppressed []string, notes []string) {
	type rule struct {
		reason  string
		expires time.Time
		hasExp  bool
	}
	active := map[string]rule{}
	for _, e := range entries {
		id := e.ID
		if id == "" {
			continue
		}
		r := rule{reason: e.Reason}
		if e.Expires != "" {
			t, err := time.Parse("2006-01-02", e.Expires)
			if err != nil {
				notes = append(notes, fmt.Sprintf("risk-accept %q has bad expiry %q (expected YYYY-MM-DD) — ignored", id, e.Expires))
				continue
			}
			r.expires, r.hasExp = t, true
		}
		active[id] = r
	}
	today := now.Format("2006-01-02")
	for _, f := range findings {
		r, ok := active[f.ID]
		if !ok {
			kept = append(kept, f)
			continue
		}
		if r.hasExp && today > r.expires.Format("2006-01-02") {
			notes = append(notes, fmt.Sprintf("risk-accept %q expired %s — finding re-armed", f.ID, r.expires.Format("2006-01-02")))
			kept = append(kept, f)
			continue
		}
		suppressed = append(suppressed, f.ID)
	}
	return kept, suppressed, notes
}
