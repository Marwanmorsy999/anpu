package models

import (
	"strings"
	"time"
)

// normalizeForDedup lowercases and trims a string so that superficially
// different but semantically equal values (trailing slash, case, etc.)
// hash to the same dedup key.
func normalizeForDedup(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, "/")
	return s
}

// Profile is a named scan intensity level.
type Profile string

const (
	ProfileSafe     Profile = "safe"
	ProfileStandard Profile = "standard"
	ProfileDeep     Profile = "deep"
)

// Valid reports whether p is a recognized profile name.
func (p Profile) Valid() bool {
	switch p {
	case ProfileSafe, ProfileStandard, ProfileDeep:
		return true
	}
	return false
}

// Technology represents a detected piece of the target's stack.
type Technology struct {
	Name       string   `json:"name"`
	Category   string   `json:"category"` // web-server, framework, cms, cdn, js-framework, backend, other
	Version    string   `json:"version,omitempty"`
	Confidence float64  `json:"confidence"` // 0.0 - 1.0
	Evidence   Evidence `json:"evidence"`
}

// EndpointCategory buckets a discovered endpoint by apparent purpose.
type EndpointCategory string

const (
	EndpointPage      EndpointCategory = "page"
	EndpointAPI       EndpointCategory = "api"
	EndpointAsset     EndpointCategory = "asset"
	EndpointAuth      EndpointCategory = "authentication"
	EndpointAdminLike EndpointCategory = "admin-like"
	EndpointUnknown   EndpointCategory = "unknown"
)

// Endpoint is a normalized, deduplicated URL discovered during recon.
type Endpoint struct {
	URL      string           `json:"url"`
	Method   string           `json:"method,omitempty"` // known only when observed (e.g. form method)
	Category EndpointCategory `json:"category"`
	Sources  []string         `json:"sources"` // e.g. ["html-link", "robots.txt", "javascript"]
}

// ScanConfig captures the resolved options for a single scan run.
type ScanConfig struct {
	Target       string
	Profile      Profile
	OutputDir    string
	JSON         bool
	HTML         bool
	SARIF        bool
	NoZAP        bool
	Verbose      bool
	Quiet        bool // suppress info-severity findings from terminal output
	SkipPreCheck bool
	Modules      ModuleConfig

	// MinConfidence is the lowest confidence level that passes the filter.
	// Findings below this level are excluded from reports and CI gates.
	// An empty value disables the filter (all findings pass).
	MinConfidence Confidence

	// RateLimit is the maximum requests per second across all stages (0 = unlimited).
	RateLimit float64
	// RequestDelay is a fixed inter-request sleep added after every HTTP request.
	RequestDelay time.Duration

	// Auth is the credential context for this scan.  An empty AuthContext
	// (Method == AuthMethodNone) means the scan runs anonymously.
	// Authentication is always opt-in — this field is never populated
	// from environment variables or implicit sources.
	Auth AuthContext
}

// ModuleConfig toggles individual pipeline stages, mirroring the
// `modules:` section of the YAML config file.
type ModuleConfig struct {
	Recon      bool
	Technology bool
	TLS        bool
	Headers    bool
	Cookies    bool
	Endpoints  bool
	Subdomains bool
	PortScan   bool
	Dirs       bool
	Secrets    bool
	CORS       bool
	Methods    bool
	// CSRF enables the Phase 10 CSRF token detection scanner.
	// Only available on Standard and Deep profiles.
	CSRF bool
	// Active enables the Phase 4 safe active testing engine.
	// Only available on Standard and Deep profiles.
	Active bool
	Nuclei bool
	ZAP    bool
}

// DefaultModuleConfig returns the module set enabled for a given profile.
// Profiles form an intensity ladder:
//
//	safe     — passive analysis only (nothing a target would notice)
//	standard — + active but polite checks (sensitive-path probing,
//	           CORS/method audits, secrets scan of discovered assets,
//	           passive subdomain enumeration via CT logs)
//	deep     — everything, including DNS brute-force and a TCP port
//	           scan of common ports (most intrusive)
func DefaultModuleConfig(p Profile) ModuleConfig {
	mc := ModuleConfig{
		Recon:      true,
		Technology: true,
		TLS:        true,
		Headers:    true,
		Cookies:    true,
		Endpoints:  true,
		Nuclei:     true,
		ZAP:        false, // enabled on Deep profile below; off for Safe/Standard by default
	}
	if p == ProfileSafe {
		// Safe profile stays fully passive: Nuclei (which sends templated
		// requests) and every active engine are left off unless the user
		// explicitly re-enables them via config.
		mc.Nuclei = false
		return mc
	}

	// standard and deep both run the active-but-polite engines.
	mc.Secrets = true
	mc.CORS = true
	mc.Methods = true
	mc.CSRF = true
	mc.Dirs = true
	mc.Subdomains = true
	mc.Active = true // enabled on Standard and Deep

	if p == ProfileStandard {
		// Standard stops short of the intrusive engines.
		return mc
	}

	// deep: everything on.
	mc.PortScan = true
	mc.ZAP = true // Deep profile enables ZAP (Docker or local zap.sh required)
	return mc
}

// ScanSummary is the top-level record of a completed (or in-progress)
// scan, as stored in SQLite and rendered in reports.
type ScanSummary struct {
	ID           string    `json:"id"`
	Target       string    `json:"target"`
	Profile      Profile   `json:"profile"`
	StartedAt    time.Time `json:"started_at"`
	CompletedAt  time.Time `json:"completed_at"`
	Status       string    `json:"status"` // running, completed, failed
	StatusReason string    `json:"status_reason,omitempty"`

	// AuthRole is the credential identity used for this scan.
	// Credential values are never stored — only the role label.
	AuthRole string `json:"auth_role,omitempty"`

	Technologies []Technology `json:"technologies"`
	Endpoints    []Endpoint   `json:"endpoints"`
	Findings     []Finding    `json:"findings"`

	SeverityCounts map[Severity]int `json:"severity_counts"`
	RiskScore      float64          `json:"risk_score"` // aggregate 0-10

	Warnings []string `json:"warnings,omitempty"`

	// SuppressedByConfidence is the number of findings that were removed
	// by the --min-confidence filter. They are not in Findings but are
	// counted here so the terminal summary can report them.
	SuppressedByConfidence int `json:"suppressed_by_confidence,omitempty"`
}

// RecomputeSeverityCounts refreshes SeverityCounts from Findings.
func (s *ScanSummary) RecomputeSeverityCounts() {
	counts := map[Severity]int{
		SeverityCritical: 0,
		SeverityHigh:     0,
		SeverityMedium:   0,
		SeverityLow:      0,
		SeverityInfo:     0,
	}
	for _, f := range s.Findings {
		counts[f.Severity]++
	}
	s.SeverityCounts = counts
}
