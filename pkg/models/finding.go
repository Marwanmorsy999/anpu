// Package models defines the core, scanner-agnostic data structures used
// throughout ANPU: findings, evidence, technologies, endpoints and scan
// metadata. Every internal package and every integration (Nuclei, ZAP,
// custom analyzers) normalizes its output into these types so that the
// rest of the pipeline (dedup, scoring, reporting) never needs to know
// where a result came from.
package models

import "time"

// Severity is the qualitative impact rating of a Finding.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// severityOrder gives severities a total order for sorting/scoring.
var severityOrder = map[Severity]int{
	SeverityInfo:     0,
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

// Rank returns a numeric rank for sorting (higher = more severe).
// Unknown severities rank below info.
func (s Severity) Rank() int {
	if r, ok := severityOrder[s]; ok {
		return r
	}
	return -1
}

// Valid reports whether s is one of the recognized severity levels.
func (s Severity) Valid() bool {
	_, ok := severityOrder[s]
	return ok
}

// Confidence expresses how sure ANPU is that a Finding represents a real
// issue, independent of how bad the issue would be if real.
//
// ANPU never reports "confirmed" unless a finding was actually verified
// (e.g. an authenticated scanner confirmed exploitation, or a signature
// matched with certainty). Heuristic and inferred findings must use
// "low" or "medium".
type Confidence string

const (
	ConfidenceLow       Confidence = "low"
	ConfidenceMedium    Confidence = "medium"
	ConfidenceHigh      Confidence = "high"
	ConfidenceConfirmed Confidence = "confirmed"
)

var confidenceOrder = map[Confidence]int{
	ConfidenceLow:       0,
	ConfidenceMedium:    1,
	ConfidenceHigh:      2,
	ConfidenceConfirmed: 3,
}

// Rank returns a numeric rank for confidence (higher = more certain).
func (c Confidence) Rank() int {
	if r, ok := confidenceOrder[c]; ok {
		return r
	}
	return -1
}

func (c Confidence) Valid() bool {
	_, ok := confidenceOrder[c]
	return ok
}

// Category buckets findings for reporting and dedup grouping.
type Category string

const (
	CategoryHeaders        Category = "security-headers"
	CategoryCookies        Category = "cookies"
	CategoryTLS            Category = "tls"
	CategoryTechnology     Category = "technology-disclosure"
	CategoryExposure       Category = "information-exposure"
	CategoryEndpoint       Category = "endpoint"
	CategoryConfiguration  Category = "misconfiguration"
	CategoryVulnerability  Category = "vulnerability"
	CategoryAuthentication Category = "authentication"
	CategoryOther          Category = "other"
)

// Source identifies which scanner/analyzer produced a finding.
type Source string

const (
	SourceHeaders     Source = "headers-analyzer"
	SourceCookies     Source = "cookie-analyzer"
	SourceTLS         Source = "tls-analyzer"
	SourceTechnology  Source = "technology-detector"
	SourceRecon       Source = "recon"
	SourceEndpoints   Source = "endpoint-discovery"
	SourceNuclei      Source = "nuclei"
	SourceZAP         Source = "zap"
	SourceCustom      Source = "custom-analyzer"
	SourceAggregation Source = "anpu-dedup" // set after merging multiple sources
)

// Evidence captures the concrete, observed proof behind a finding.
// ANPU must never fabricate evidence: if none is available, Observed
// should be empty and Unavailable should be true.
type Evidence struct {
	// Observed is the literal, unmodified data that was seen (a header
	// value, a response snippet, a discovered path, ...).
	Observed string `json:"observed,omitempty"`
	// Location describes where the evidence was found (e.g. "HTTP response
	// header", "JavaScript file: /static/app.js", "robots.txt").
	Location string `json:"location,omitempty"`
	// RequestSummary is a short, non-sensitive description of the request
	// that produced the evidence (method + path only — never full raw
	// requests/response bodies with credentials).
	RequestSummary string `json:"request_summary,omitempty"`
	// Unavailable is true when no concrete evidence could be captured.
	// When true, reports must render "Evidence unavailable" instead of
	// inventing something plausible-looking.
	Unavailable bool `json:"unavailable"`
}

// SourceRef records one contributing scanner result that was merged into
// a deduplicated finding, preserving traceability back to the original.
type SourceRef struct {
	Source       Source   `json:"source"`
	OriginalID   string   `json:"original_id,omitempty"`   // e.g. Nuclei template ID
	OriginalName string   `json:"original_name,omitempty"` // human readable
	Evidence     Evidence `json:"evidence"`
}

// Finding is ANPU's unified representation of a single security
// observation, whether it came from a built-in analyzer, Nuclei, ZAP, or
// a future custom scanner.
type Finding struct {
	ID          string     `json:"id"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Severity    Severity   `json:"severity"`
	Confidence  Confidence `json:"confidence"`
	Category    Category   `json:"category"`
	CWE         string     `json:"cwe,omitempty"`
	OWASP       string     `json:"owasp,omitempty"`

	Target    string `json:"target"`              // scan target (origin)
	URL       string `json:"url,omitempty"`       // specific affected URL
	Parameter string `json:"parameter,omitempty"` // affected parameter, if any

	Evidence Evidence `json:"evidence"`
	Source   Source   `json:"source"`
	// DetectionMethod is a short human-readable description of how the
	// issue was detected (e.g. "passive header inspection",
	// "nuclei template match", "TLS handshake analysis").
	DetectionMethod string `json:"detection_method"`

	Impact      string   `json:"impact,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	References  []string `json:"references,omitempty"`

	// RiskScore is populated by the scoring engine (0-10).
	RiskScore float64 `json:"risk_score"`
	// ScoreExplanation documents why the finding received its score.
	ScoreExplanation string `json:"score_explanation,omitempty"`

	// MergedFrom lists every original scanner result that was folded into
	// this finding during deduplication. A finding produced by a single
	// scanner has exactly one entry here.
	MergedFrom []SourceRef `json:"merged_from,omitempty"`

	FirstSeen time.Time `json:"first_seen"`
}

// DedupKey returns a normalized key used to group findings that likely
// represent the same underlying issue. Two findings with the same key
// (same category + same affected URL/host + similar title) are
// candidates for merging.
func (f Finding) DedupKey() string {
	url := f.URL
	if url == "" {
		url = f.Target
	}
	return string(f.Category) + "|" + normalizeForDedup(url) + "|" + normalizeForDedup(f.Title)
}
