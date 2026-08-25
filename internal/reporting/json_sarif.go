// Package reporting generates ANPU's output reports: JSON (full
// machine-readable scan summary), SARIF (for CI/code-scanning
// integration), and a polished HTML report for human review.
package reporting

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/anpu-project/anpu/pkg/models"
	"github.com/anpu-project/anpu/pkg/version"
)

// WriteJSON marshals the full scan summary to indented JSON at path.
func WriteJSON(summary *models.ScanSummary, path string) error {
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling JSON report: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing JSON report to %s: %w", path, err)
	}
	return nil
}

// SARIF types implement just enough of the SARIF 2.1.0 schema for
// static-analysis findings, per https://sarifweb.azurewebsites.net/.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	ShortDescription sarifMultiformatMsg    `json:"shortDescription"`
	FullDescription  sarifMultiformatMsg    `json:"fullDescription"`
	Help             sarifMultiformatMsg    `json:"help"`
	Properties       map[string]interface{} `json:"properties,omitempty"`
}

type sarifMultiformatMsg struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID  string              `json:"ruleId"`
	Level   string              `json:"level"`
	Message sarifMultiformatMsg `json:"message"`
	// Locations is intentionally omitted (omitempty) rather than always
	// present. ANPU's findings are about a live URL, not a file that
	// was checked out in the analyzed repository -- code scanning's
	// physicalLocation.artifactLocation.uri specifically means the
	// latter. Reporting an http(s) URL there is a URI scheme mismatch
	// against the checkout's file:// source root and causes GitHub to
	// reject the *entire* SARIF upload ("SARIF URI scheme \"http\" did
	// not match the checkout URI scheme \"file\""). The target URL is
	// preserved in Properties["target_url"] and prefixed onto the
	// message text instead, which have no such constraint.
	Locations  []sarifLocation        `json:"locations,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// severityToSarifLevel maps ANPU severities onto SARIF's level enum
// (error/warning/note/none).
func severityToSarifLevel(s models.Severity) string {
	switch s {
	case models.SeverityCritical, models.SeverityHigh:
		return "error"
	case models.SeverityMedium:
		return "warning"
	case models.SeverityLow:
		return "note"
	default:
		return "none"
	}
}

// WriteSARIF renders the scan's findings as a SARIF 2.1.0 log, suitable
// for upload to GitHub code scanning or other SARIF-consuming tools.
func WriteSARIF(summary *models.ScanSummary, path string) error {
	// Initialize as empty (not nil) so an empty scan serializes as []
	// rather than null, which the SARIF 2.1.0 schema does not allow.
	rules := []sarifRule{}
	rulesSeen := map[string]bool{}
	results := []sarifResult{}

	for _, f := range summary.Findings {
		if !rulesSeen[f.ID] {
			rulesSeen[f.ID] = true
			rules = append(rules, sarifRule{
				ID:               f.ID,
				Name:             f.Title,
				ShortDescription: sarifMultiformatMsg{Text: f.Title},
				FullDescription:  sarifMultiformatMsg{Text: f.Description},
				Help:             sarifMultiformatMsg{Text: f.Remediation},
				Properties: map[string]interface{}{
					"severity":   f.Severity,
					"confidence": f.Confidence,
					"category":   f.Category,
					"cwe":        f.CWE,
				},
			})
		}

		uri := f.URL
		if uri == "" {
			uri = f.Target
		}
		// No physicalLocation: uri is a live scan target (http/https),
		// never a file in the repo checkout, so it can't be reported as
		// an artifactLocation without violating code scanning's
		// same-scheme-as-checkout rule (see the Locations field doc
		// above). Fold it into the message and properties instead, so
		// the target is still shown on the alert without risking a
		// rejected upload.
		msg := f.Description
		if uri != "" {
			msg = fmt.Sprintf("Target: %s\n\n%s", uri, f.Description)
		}
		results = append(results, sarifResult{
			RuleID:  f.ID,
			Level:   severityToSarifLevel(f.Severity),
			Message: sarifMultiformatMsg{Text: msg},
			Properties: map[string]interface{}{
				"confidence": f.Confidence,
				"risk_score": f.RiskScore,
				"target_url": uri,
			},
		})
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "ANPU",
				InformationURI: "https://github.com/Marwanmorsy999/anpu",
				Version:        version.Version,
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling SARIF report: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing SARIF report to %s: %w", path, err)
	}
	return nil
}
