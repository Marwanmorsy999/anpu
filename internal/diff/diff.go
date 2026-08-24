// Package diff compares two completed ANPU scans and summarizes changes in
// attack surface, technologies, findings, and aggregate risk.
package diff

import (
	"fmt"
	"math"
	"net/url"
	"sort"
	"strings"

	"github.com/anpu-project/anpu/pkg/models"
)

// FindingChange describes a finding that was added, removed, or changed.
type FindingChange struct {
	Finding models.Finding `json:"finding"`
	Kind    string         `json:"kind"` // added, removed, changed
}

// TechnologyChange describes a technology addition/removal/change.
type TechnologyChange struct {
	Technology models.Technology `json:"technology"`
	Previous   models.Technology `json:"previous,omitempty"`
	Kind       string            `json:"kind"`
}

// EndpointChange describes an endpoint addition/removal.
type EndpointChange struct {
	Endpoint models.Endpoint `json:"endpoint"`
	Kind     string          `json:"kind"`
}

// Result is a deterministic, machine-readable scan comparison.
type Result struct {
	FromID              string             `json:"from_id"`
	ToID                string             `json:"to_id"`
	Target              string             `json:"target"`
	RiskBefore          float64            `json:"risk_before"`
	RiskAfter           float64            `json:"risk_after"`
	RiskDelta           float64            `json:"risk_delta"`
	FindingsAdded       int                `json:"findings_added"`
	FindingsRemoved     int                `json:"findings_removed"`
	FindingsChanged     int                `json:"findings_changed"`
	EndpointsAdded      int                `json:"endpoints_added"`
	EndpointsRemoved    int                `json:"endpoints_removed"`
	TechnologiesAdded   int                `json:"technologies_added"`
	TechnologiesRemoved int                `json:"technologies_removed"`
	Findings            []FindingChange    `json:"findings,omitempty"`
	Endpoints           []EndpointChange   `json:"endpoints,omitempty"`
	Technologies        []TechnologyChange `json:"technologies,omitempty"`
}

// Compare compares two scans. It treats normalized URLs, finding identity,
// and technology identity as stable keys while preserving meaningful field
// changes as "changed".
func Compare(before, after *models.ScanSummary) *Result {
	r := &Result{
		FromID:     before.ID,
		ToID:       after.ID,
		Target:     after.Target,
		RiskBefore: before.RiskScore,
		RiskAfter:  after.RiskScore,
	}
	r.RiskDelta = round1(after.RiskScore - before.RiskScore)

	beforeFindings := make(map[string]models.Finding, len(before.Findings))
	for _, f := range before.Findings {
		beforeFindings[f.DedupKey()] = f
	}
	afterFindings := make(map[string]models.Finding, len(after.Findings))
	for _, f := range after.Findings {
		afterFindings[f.DedupKey()] = f
	}
	for key, f := range afterFindings {
		prev, ok := beforeFindings[key]
		if !ok {
			r.Findings = append(r.Findings, FindingChange{Finding: f, Kind: "added"})
			r.FindingsAdded++
			continue
		}
		if findingChanged(prev, f) {
			r.Findings = append(r.Findings, FindingChange{Finding: f, Kind: "changed"})
			r.FindingsChanged++
		}
	}
	for key, f := range beforeFindings {
		if _, ok := afterFindings[key]; !ok {
			r.Findings = append(r.Findings, FindingChange{Finding: f, Kind: "removed"})
			r.FindingsRemoved++
		}
	}

	beforeEndpoints := make(map[string]models.Endpoint, len(before.Endpoints))
	for _, e := range before.Endpoints {
		beforeEndpoints[normalizeURL(e.URL)] = e
	}
	afterEndpoints := make(map[string]models.Endpoint, len(after.Endpoints))
	for _, e := range after.Endpoints {
		afterEndpoints[normalizeURL(e.URL)] = e
	}
	for key, e := range afterEndpoints {
		if _, ok := beforeEndpoints[key]; !ok {
			r.Endpoints = append(r.Endpoints, EndpointChange{Endpoint: e, Kind: "added"})
			r.EndpointsAdded++
		}
	}
	for key, e := range beforeEndpoints {
		if _, ok := afterEndpoints[key]; !ok {
			r.Endpoints = append(r.Endpoints, EndpointChange{Endpoint: e, Kind: "removed"})
			r.EndpointsRemoved++
		}
	}

	beforeTech := make(map[string]models.Technology, len(before.Technologies))
	for _, t := range before.Technologies {
		beforeTech[techKey(t)] = t
	}
	afterTech := make(map[string]models.Technology, len(after.Technologies))
	for _, t := range after.Technologies {
		afterTech[techKey(t)] = t
	}
	for key, t := range afterTech {
		prev, ok := beforeTech[key]
		if !ok {
			r.Technologies = append(r.Technologies, TechnologyChange{Technology: t, Kind: "added"})
			r.TechnologiesAdded++
			continue
		}
		if prev.Version != t.Version {
			r.Technologies = append(r.Technologies, TechnologyChange{Technology: t, Previous: prev, Kind: "changed"})
		}
	}
	for key, t := range beforeTech {
		if _, ok := afterTech[key]; !ok {
			r.Technologies = append(r.Technologies, TechnologyChange{Technology: t, Kind: "removed"})
			r.TechnologiesRemoved++
		}
	}

	sortChanges(r)
	return r
}

func findingChanged(a, b models.Finding) bool {
	return a.Severity != b.Severity || a.Confidence != b.Confidence ||
		a.RiskScore != b.RiskScore || a.Evidence.Observed != b.Evidence.Observed ||
		a.Remediation != b.Remediation
}

func techKey(t models.Technology) string {
	return strings.ToLower(strings.TrimSpace(t.Name)) + "|" + strings.ToLower(strings.TrimSpace(t.Category))
}

func normalizeURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if u, err := url.Parse(raw); err == nil {
		u.Scheme = strings.ToLower(u.Scheme)
		u.Host = strings.ToLower(u.Host)
		u.Path = strings.TrimRight(u.Path, "/")
		return u.String()
	}
	return strings.ToLower(strings.TrimRight(raw, "/"))
}

func sortChanges(r *Result) {
	sort.Slice(r.Findings, func(i, j int) bool {
		if r.Findings[i].Kind != r.Findings[j].Kind {
			return r.Findings[i].Kind < r.Findings[j].Kind
		}
		if r.Findings[i].Finding.Severity.Rank() != r.Findings[j].Finding.Severity.Rank() {
			return r.Findings[i].Finding.Severity.Rank() > r.Findings[j].Finding.Severity.Rank()
		}
		return r.Findings[i].Finding.Title < r.Findings[j].Finding.Title
	})
	sort.Slice(r.Endpoints, func(i, j int) bool { return r.Endpoints[i].Endpoint.URL < r.Endpoints[j].Endpoint.URL })
	sort.Slice(r.Technologies, func(i, j int) bool {
		return techKey(r.Technologies[i].Technology) < techKey(r.Technologies[j].Technology)
	})
}

func (r *Result) Summary() string {
	direction := "stable"
	if r.RiskDelta > 0 {
		direction = "worse"
	}
	if r.RiskDelta < 0 {
		direction = "better"
	}
	return fmt.Sprintf("risk %.1f → %.1f (%s, delta %+0.1f); findings +%d/-%d/~%d; endpoints +%d/-%d; technologies +%d/-%d",
		r.RiskBefore, r.RiskAfter, direction, r.RiskDelta,
		r.FindingsAdded, r.FindingsRemoved, r.FindingsChanged,
		r.EndpointsAdded, r.EndpointsRemoved,
		r.TechnologiesAdded, r.TechnologiesRemoved)
}

func round1(v float64) float64 {
	return math.Round(v*10) / 10
}
