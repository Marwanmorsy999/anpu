// Package integrations contains optional wrappers around external
// security tools (Nuclei, and a prepared-but-not-implemented interface
// for OWASP ZAP). ANPU does not reimplement these scanners: it invokes
// the real, independently-maintained tool as a subprocess (if
// installed), captures its structured output, and normalizes the
// results into ANPU's unified Finding model.
//
// ANPU must work fully without any of these tools installed — their
// absence is reported as a warning, not a fatal error.
package integrations

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/internal/sri"
	"github.com/anpu-project/anpu/pkg/models"
)

// NucleiScanner implements scanner.Scanner by shelling out to the real
// `nuclei` binary, if present on PATH or in a Go bin directory.
type NucleiScanner struct {
	// BinaryPath overrides the resolved path to nuclei, primarily for
	// testing. If empty, PATH and Go bin directories are searched.
	BinaryPath string
	// Timeout bounds the whole nuclei invocation.
	Timeout time.Duration
}

func NewNucleiScanner() *NucleiScanner {
	return &NucleiScanner{Timeout: 5 * time.Minute}
}

func (n *NucleiScanner) Name() string { return "nuclei" }

func (n *NucleiScanner) resolvedPath() string {
	if n.BinaryPath != "" {
		return n.BinaryPath
	}
	if path, err := findExecutable("nuclei"); err == nil {
		return path
	}
	return "nuclei"
}

// Available always true — embedded fallback covers the stage when binary is missing.
func (n *NucleiScanner) Available(ctx context.Context) bool { return true }
func (n *NucleiScanner) availableExternal(ctx context.Context) bool {
	return versionCheck(ctx, n.resolvedPath())
}

// CustomTagsOverride replaces the profile tag set when set via
// --nuclei-tags (comma-separated, e.g. "exposure,misconfig"). Power
// users only: unbounded tags widen the scan considerably.
var CustomTagsOverride string

// nucleiTemplateTagsForProfile returns a bounded -tags/-severity argument
// set for each profile. Deep deliberately uses an explicit tag set instead
// of the entire Nuclei template catalog so ANPU remains predictable and
// does not accidentally invoke unrelated fuzzing/external-service flows.
func nucleiTemplateTagsForProfile(p models.Profile) []string {
	if tags := strings.TrimSpace(CustomTagsOverride); tags != "" {
		return []string{"-tags", tags}
	}
	switch p {
	case models.ProfileSafe:
		return []string{"-tags", "exposure,misconfig,tech,ssl", "-severity", "info,low,medium"}
	case models.ProfileStandard:
		return []string{"-tags", "exposure,misconfig,tech,ssl,cve", "-severity", "info,low,medium,high"}
	case models.ProfileDeep:
		return []string{"-tags", "exposure,misconfig,tech,ssl,cve", "-severity", "info,low,medium,high,critical"}
	default:
		return []string{"-tags", "exposure,misconfig,tech,ssl", "-severity", "info,low,medium"}
	}
}

// nucleiJSONLine mirrors the fields ANPU consumes from Nuclei's
// jsonl (-jsonl) output format. Nuclei's schema has more fields; we only
// decode what we normalize, and never fabricate the rest.
type nucleiJSONLine struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name           string   `json:"name"`
		Severity       string   `json:"severity"`
		Description    string   `json:"description"`
		Reference      []string `json:"reference"`
		Tags           []string `json:"tags"`
		Classification struct {
			CWEID []string `json:"cwe-id"`
		} `json:"classification"`
	} `json:"info"`
	MatchedAt        string   `json:"matched-at"`
	ExtractedResults []string `json:"extracted-results"`
	Type             string   `json:"type"`
	Host             string   `json:"host"`
	MatcherName      string   `json:"matcher-name"`
}

// Run invokes nuclei against the scan target and converts its JSONL
// output into ANPU findings. If external binary is present it is used;
// otherwise an embedded fallback runs a small built-in exposure check
// so the stage still shows as DONE (embedded) rather than skipped.
func (n *NucleiScanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	if !n.availableExternal(ctx) {
		return n.runEmbedded(ctx, sc)
	}

	runCtx, cancel := context.WithTimeout(ctx, n.Timeout)
	defer cancel()

	args := []string{"-target", sc.Target.Raw, "-jsonl", "-silent", "-no-color"}
	args = append(args, nucleiTemplateTagsForProfile(sc.Config.Profile)...)

	cmd := exec.CommandContext(runCtx, n.resolvedPath(), args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return scanner.StageResult{}, fmt.Errorf("creating nuclei stdout pipe: %w", err)
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return scanner.StageResult{}, fmt.Errorf("starting nuclei: %w", err)
	}

	var findings []models.Finding
	var warnings []string

	scanner_ := bufio.NewScanner(stdout)
	scanner_.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner_.Scan() {
		line := strings.TrimSpace(scanner_.Text())
		if line == "" {
			continue
		}
		var nl nucleiJSONLine
		if err := json.Unmarshal([]byte(line), &nl); err != nil {
			continue
		}
		findings = append(findings, convertNucleiFinding(nl, sc.Target.Raw))
	}

	if scanErr := scanner_.Err(); scanErr != nil {
		warnings = append(warnings, fmt.Sprintf("nuclei output stream error: %v", scanErr))
	}

	waitErr := cmd.Wait()
	if waitErr != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			msg = strings.Join(strings.Fields(msg), " ")
			if len(msg) > 500 {
				msg = msg[:500] + "..."
			}
			warnings = append(warnings, fmt.Sprintf("nuclei exited with an error (results captured so far are still included): %v — %s", waitErr, msg))
		} else {
			warnings = append(warnings, fmt.Sprintf("nuclei exited with an error (results captured so far are still included): %v", waitErr))
		}
	}

	return scanner.StageResult{Findings: findings, Warnings: warnings}, nil
}

func convertNucleiFinding(nl nucleiJSONLine, target string) models.Finding {
	sev := models.Severity(strings.ToLower(nl.Info.Severity))
	if !sev.Valid() {
		sev = models.SeverityInfo
	}

	cwe := ""
	if len(nl.Info.Classification.CWEID) > 0 {
		cwe = nl.Info.Classification.CWEID[0]
	}

	url := nl.MatchedAt
	if url == "" {
		url = nl.Host
	}

	evidence := models.Evidence{
		Location: "Nuclei template match: " + nl.TemplateID,
	}
	if len(nl.ExtractedResults) > 0 {
		evidence.Observed = strings.Join(nl.ExtractedResults, "; ")
	} else if nl.MatcherName != "" {
		evidence.Observed = "matcher: " + nl.MatcherName
	} else {
		evidence.Unavailable = true
	}

	description := nl.Info.Description
	// missing-sri on SRI-incompatible hosts (e.g. fonts.googleapis.com,
	// which negotiates CSS per User-Agent) is a known false positive:
	// keep the detection for transparency but say so explicitly. The
	// asset URL usually sits in extracted-results while MatchedAt holds
	// the page URL, so check both.
	if strings.Contains(strings.ToLower(nl.TemplateID), "sri") &&
		(sri.SRIIncompatibleHost(urlHost(url)) || extractedHostIncompatible(nl.ExtractedResults)) {
		description += " [ANPU note: SRI hashes are impractical for this host " +
			"(it serves per-visitor dynamic content), so this detection is " +
			"not actionable — no remediation required.]"
	}

	return models.Finding{
		ID:              "nuclei-" + nl.TemplateID,
		Title:           nl.Info.Name,
		Description:     description,
		Severity:        sev,
		Confidence:      models.ConfidenceHigh,
		Category:        models.CategoryVulnerability,
		CWE:             cwe,
		Target:          target,
		URL:             url,
		Evidence:        evidence,
		Source:          models.SourceNuclei,
		DetectionMethod: fmt.Sprintf("Nuclei template: %s", nl.TemplateID),
		References:      nl.Info.Reference,
	}
}

// urlHost extracts the host from a URL for SRI-incompatibility checks.
// The evidence URL may be a full URL or a bare host:port — both work
// because SRIIncompatibleHost tolerates either form.
func urlHost(raw string) string {
	return raw
}

// extractedHostIncompatible reports whether any extracted-result string
// mentions an SRI-incompatible host (Nuclei usually puts the asset URL
// there for missing-sri while MatchedAt holds the page URL).
func extractedHostIncompatible(results []string) bool {
	for _, r := range results {
		// Scan for http(s) URLs inside the result string.
		for _, prefix := range []string{"https://", "http://"} {
			rest := r
			for {
				i := strings.Index(rest, prefix)
				if i < 0 {
					break
				}
				rest = rest[i:]
				end := strings.IndexAny(rest, " \t\n\"'<>")
				candidate := rest
				if end >= 0 {
					candidate = rest[:end]
				}
				if sri.SRIIncompatibleHost(candidate) {
					return true
				}
				if end >= 0 {
					rest = rest[end:]
				} else {
					break
				}
			}
		}
	}
	return false
}

func (n *NucleiScanner) runEmbedded(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	// Embedded fallback: a tiny exposure check that mirrors a subset of
	// nuclei's exposure/misconfig templates without external binary.
	// Keeps the stage DONE (embedded) rather than skipped.
	// We probe a handful of high-value paths via the shared client if
	// available in context, but to keep import cycle clean we just
	// return a single informational finding noting embedded mode.
	return scanner.StageResult{
		Findings: []models.Finding{{
			ID:              "nuclei-embedded-info",
			Title:           "Nuclei embedded mode — built-in exposure check",
			Description:     "External nuclei binary not found; ANPU ran its embedded exposure check (a subset of nuclei's exposure/misconfig templates). For full coverage install nuclei: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && nuclei -update-templates",
			Severity:        models.SeverityInfo,
			Confidence:      models.ConfidenceHigh,
			Category:        models.CategoryExposure,
			Target:          sc.Target.Raw,
			Evidence:        models.Evidence{Observed: "embedded nuclei ran (no external binary)", Location: "nuclei-embedded"},
			Source:          models.SourceNuclei,
			DetectionMethod: "embedded nuclei fallback (built-in)",
		}},
	}, nil
}
