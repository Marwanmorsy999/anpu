// Package reporting — export_csvmd.go: CSV and Markdown renderers
// (Wave 4 item 149). One row per finding with stable columns; Markdown
// mirrors the terminal summary plus a findings table. Pure functions
// over ScanSummary (unit-tested, no I/O beyond the target path).
package reporting

import (
	"encoding/csv"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/anpu-project/anpu/pkg/models"
)

// csvRecord flattens one finding (pure, tested).
func csvRecord(f models.Finding) []string {
	return []string{
		string(f.Severity), string(f.Confidence), string(f.Category),
		f.ID, f.Title, f.URL, f.CWE, string(f.Source), f.DetectionMethod,
		oneLine(f.Description, 500), oneLine(f.Evidence.Observed, 300),
		strings.Join(f.References, " "),
	}
}

func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		s = s[:n] + "..."
	}
	return s
}

// WriteCSV writes findings as CSV (header + one row each, sorted by
// severity rank then ID for stable diffs).
func WriteCSV(summary *models.ScanSummary, path string) error {
	fs := append([]models.Finding(nil), summary.Findings...)
	sort.Slice(fs, func(i, j int) bool {
		if fs[i].Severity.Rank() != fs[j].Severity.Rank() {
			return fs[i].Severity.Rank() > fs[j].Severity.Rank()
		}
		return fs[i].ID < fs[j].ID
	})
	f, err := os.Create(path) // #nosec G304 -- CLI reads operator-specified paths (reports, wordlists, checkpoints, code dir).
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{"severity", "confidence", "category", "id", "title", "url", "cwe", "source", "detection_method", "description", "evidence", "references"}); err != nil {
		return err
	}
	for _, finding := range fs {
		if err := w.Write(csvRecord(finding)); err != nil {
			return err
		}
	}
	return nil
}

// WriteMarkdown writes a human-readable Markdown report.
func WriteMarkdown(summary *models.ScanSummary, path string) error {
	var b strings.Builder
	_, _ = fmt.Fprintf(&b, "# ANPU scan: %s\n\n", summary.Target)
	fmt.Fprintf(&b, "- Profile: %s\n- Status: %s\n- Risk score: %.1f\n- Findings: %d\n- Endpoints: %d\n- Technologies: %d\n\n",
		summary.Profile, summary.Status, summary.RiskScore, len(summary.Findings), len(summary.Endpoints), len(summary.Technologies))
	if len(summary.Technologies) > 0 {
		b.WriteString("## Technologies\n\n")
		for _, t := range summary.Technologies {
			v := ""
			if t.Version != "" {
				v = " " + t.Version
			}
			_, _ = fmt.Fprintf(&b, "- %s%s (%s)\n", t.Name, v, t.Category)
		}
		b.WriteString("\n")
	}
	b.WriteString("## Findings\n\n")
	b.WriteString("| Severity | Confidence | ID | Title | URL |\n|---|---|---|---|---|\n")
	fs := append([]models.Finding(nil), summary.Findings...)
	sort.Slice(fs, func(i, j int) bool {
		if fs[i].Severity.Rank() != fs[j].Severity.Rank() {
			return fs[i].Severity.Rank() > fs[j].Severity.Rank()
		}
		return fs[i].ID < fs[j].ID
	})
	for _, f := range fs {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
			f.Severity, f.Confidence, mdCell(f.ID), mdCell(f.Title), mdCell(f.URL))
	}
	b.WriteString("\n")
	for _, f := range fs {
		fmt.Fprintf(&b, "### %s\n\n- ID: `%s`\n- Severity: %s, Confidence: %s\n- URL: %s\n\n%s\n\n",
			f.Title, f.ID, f.Severity, f.Confidence, f.URL, f.Description)
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

func mdCell(s string) string {
	s = strings.ReplaceAll(oneLine(s, 120), "|", "\\|")
	if s == "" {
		return "—"
	}
	return s
}
