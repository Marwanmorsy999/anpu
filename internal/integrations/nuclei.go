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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/anpu-project/anpu/internal/scanner"
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

func findExecutable(binary string) (string, error) {
	if path, err := exec.LookPath(binary); err == nil {
		return path, nil
	}

	names := []string{binary}
	if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(binary), ".exe") {
		names = append(names, binary+".exe")
	}

	var candidates []string
	if gobin := strings.TrimSpace(os.Getenv("GOBIN")); gobin != "" {
		for _, name := range names {
			candidates = append(candidates, filepath.Join(gobin, name))
		}
	}
	if gopath := strings.TrimSpace(os.Getenv("GOPATH")); gopath != "" {
		for _, gp := range filepath.SplitList(gopath) {
			for _, name := range names {
				candidates = append(candidates, filepath.Join(gp, "bin", name))
			}
		}
	}

	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("%s not found on PATH or Go bin directories", binary)
}

// Available checks whether the nuclei binary can be found and executed.
// It never attempts to download or install nuclei — ANPU orchestrates
// existing tools, it doesn't manage them.
func (n *NucleiScanner) Available(ctx context.Context) bool {
	path := n.resolvedPath()
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(checkCtx, path, "-version")
	return cmd.Run() == nil
}

// nucleiTemplateTagsForProfile returns the -tags argument used to keep
// Nuclei scoped to safe/appropriate templates for the given profile.
// "safe" restricts to passive/low-impact template tags; "standard" and
// "deep" progressively widen scope. ANPU never runs Nuclei's intrusive
// or fuzzing-heavy template categories automatically.
func nucleiTemplateTagsForProfile(p models.Profile) []string {
	switch p {
	case models.ProfileSafe:
		return []string{"-tags", "exposure,misconfig,tech,ssl", "-severity", "info,low,medium"}
	case models.ProfileStandard:
		return []string{"-tags", "exposure,misconfig,tech,ssl,cve", "-severity", "info,low,medium,high"}
	case models.ProfileDeep:
		return []string{"-severity", "info,low,medium,high,critical"}
	default:
		return []string{"-tags", "exposure,misconfig,tech,ssl"}
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
// output into ANPU findings. If nuclei is not installed, Run returns a
// StageResult with a warning rather than an error, so the pipeline
// continues normally.
func (n *NucleiScanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	if !n.Available(ctx) {
		return scanner.StageResult{
			Warnings: []string{"nuclei is not installed or not on PATH; skipping Nuclei-based checks. Install Nuclei and its templates to enable this stage."},
		}, nil
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

	waitErr := cmd.Wait()
	if waitErr != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			// Keep the diagnostic compact for terminal/report output.
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

	return models.Finding{
		ID:              "nuclei-" + nl.TemplateID,
		Title:           nl.Info.Name,
		Description:     nl.Info.Description,
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
