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
	Target    string
	Profile   Profile
	OutputDir string
	JSON      bool
	HTML      bool
	SARIF     bool
	NoZAP         bool
	Verbose       bool
	SkipPreCheck  bool
	Modules       ModuleConfig
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
	Nuclei     bool
	ZAP        bool
}

// DefaultModuleConfig returns the module set enabled for a given profile.
func DefaultModuleConfig(p Profile) ModuleConfig {
	mc := ModuleConfig{
		Recon:      true,
		Technology: true,
		TLS:        true,
		Headers:    true,
		Cookies:    true,
		Endpoints:  true,
		Nuclei:     true,
		ZAP:        false, // never enabled by default; MVP has no ZAP implementation
	}
	if p == ProfileSafe {
		// Safe profile still runs passive analysis, but Nuclei (which
		// sends templated requests) is left to standard/deep unless the
		// user explicitly re-enables it via config.
		mc.Nuclei = false
	}
	return mc
}

// ScanSummary is the top-level record of a completed (or in-progress)
// scan, as stored in SQLite and rendered in reports.
type ScanSummary struct {
	ID          string    `json:"id"`
	Target      string    `json:"target"`
	Profile     Profile   `json:"profile"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt  time.Time `json:"completed_at"`
	Status       string    `json:"status"` // running, completed, failed
	StatusReason string    `json:"status_reason,omitempty"`

	Technologies []Technology `json:"technologies"`
	Endpoints    []Endpoint   `json:"endpoints"`
	Findings     []Finding    `json:"findings"`

	SeverityCounts map[Severity]int `json:"severity_counts"`
	RiskScore      float64          `json:"risk_score"` // aggregate 0-10

	Warnings []string `json:"warnings,omitempty"`
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
