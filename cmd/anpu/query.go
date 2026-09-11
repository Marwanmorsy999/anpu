package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/anpu-project/anpu/pkg/models"
)

// newQueryCmd implements `anpu query` (Wave 4 item 146): filter findings
// across saved JSON reports by severity/confidence/category/text.
func newQueryCmd() *cobra.Command {
	var (
		inputs     []string
		reportsDir string
		severity   string
		confidence string
		category   string
		text       string
		jsonOut    bool
		limit      int
	)
	cmd := &cobra.Command{
		Use:   "query",
		Short: "Filter findings across saved scan reports",
		Long: `Filter findings from saved JSON scan reports (files, not the
SQLite history database — use ` + "`anpu show`" + ` for stored scans).

Examples:
  anpu query --severity high
  anpu query --dir ./my-reports --text xss
  anpu query --input ./reports/scan.json --text xss --json
  anpu query --category vulnerability --confidence confirmed --limit 20`,
		RunE: func(cmd *cobra.Command, args []string) error {
			files := inputs
			if len(files) == 0 {
				auto, err := newestReports(reportsDir, 5)
				if err != nil {
					return err
				}
				files = auto
			}
			if len(files) == 0 {
				return fmt.Errorf("no reports found: pass --input report.json or run a scan with --json first")
			}
			var matched []models.Finding
			for _, f := range files {
				summary, err := loadSummaryJSON(f)
				if err != nil {
					_, _ = fmt.Fprintf(os.Stderr, "anpu: skipping %s: %v\n", f, err)
					continue
				}
				for _, finding := range summary.Findings {
					if !queryMatch(finding, severity, confidence, category, text) {
						continue
					}
					matched = append(matched, finding)
				}
			}
			sort.Slice(matched, func(i, j int) bool {
				if matched[i].Severity.Rank() != matched[j].Severity.Rank() {
					return matched[i].Severity.Rank() > matched[j].Severity.Rank()
				}
				return matched[i].ID < matched[j].ID
			})
			if limit > 0 && len(matched) > limit {
				matched = matched[:limit]
			}
			if jsonOut {
				data, _ := json.MarshalIndent(matched, "", "  ")
				fmt.Println(string(data))
				return nil
			}
			fmt.Printf("%-8s %-9s %-28s %s\n", "SEVERITY", "CONF", "ID", "TITLE")
			for _, f := range matched {
				fmt.Printf("%-8s %-9s %-28s %s\n", f.Severity, f.Confidence, truncate(f.ID, 28), truncate(f.Title, 70))
			}
			fmt.Printf("\n%d finding(s) from %d report(s)\n", len(matched), len(files))
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&inputs, "input", nil, "report JSON to query (repeatable; default: newest in --dir)")
	cmd.Flags().StringVar(&reportsDir, "dir", "./reports", "directory to auto-pick newest reports from (matches scan --output)")
	cmd.Flags().StringVar(&severity, "severity", "", "minimum severity floor: low, medium, high, critical")
	cmd.Flags().StringVar(&confidence, "confidence", "", "minimum confidence: low, medium, high, confirmed")
	cmd.Flags().StringVar(&category, "category", "", "finding category substring match")
	cmd.Flags().StringVar(&text, "text", "", "case-insensitive substring over id/title/description/url")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print matches as JSON")
	cmd.Flags().IntVar(&limit, "limit", 50, "max findings to print (0 = all)")
	return cmd
}

func queryMatch(f models.Finding, severity, confidence, category, text string) bool {
	if severity != "" {
		floor := models.Severity(strings.ToLower(severity))
		if !floor.Valid() || f.Severity.Rank() < floor.Rank() {
			return false
		}
	}
	if confidence != "" {
		floor := models.Confidence(strings.ToLower(confidence))
		if !floor.Valid() || confRank(f.Confidence) < confRank(floor) {
			return false
		}
	}
	if category != "" && !strings.Contains(strings.ToLower(string(f.Category)), strings.ToLower(category)) {
		return false
	}
	if text != "" {
		blob := strings.ToLower(f.ID + "\n" + f.Title + "\n" + f.Description + "\n" + f.URL)
		if !strings.Contains(blob, strings.ToLower(text)) {
			return false
		}
	}
	return true
}

func confRank(c models.Confidence) int {
	switch c {
	case models.ConfidenceLow:
		return 1
	case models.ConfidenceMedium:
		return 2
	case models.ConfidenceHigh:
		return 3
	case models.ConfidenceConfirmed:
		return 4
	}
	return 0
}

func loadSummaryJSON(path string) (*models.ScanSummary, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- CLI reads operator-specified paths (reports, wordlists, checkpoints, code dir).
	if err != nil {
		return nil, err
	}
	var s models.ScanSummary
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &s, nil
}

// newestReports returns up to n most-recent *.json files in dir.
func newestReports(dir string, n int) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w (run a scan with --json first)", dir, err)
	}
	type fi struct {
		path string
		mod  int64
	}
	var files []fi
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, fi{filepath.Join(dir, e.Name()), info.ModTime().UnixNano()})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod > files[j].mod })
	var out []string
	for i, f := range files {
		if i >= n {
			break
		}
		out = append(out, f.path)
	}
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
