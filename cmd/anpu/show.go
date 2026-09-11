package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/anpu-project/anpu/internal/reporting"
	"github.com/anpu-project/anpu/internal/storage"
	"github.com/anpu-project/anpu/pkg/models"
)

func newShowCmd() *cobra.Command {
	var exportPath string
	var format string
	var severityFloor string
	var limit int
	var longOut bool

	cmd := &cobra.Command{
		Use:   "show <scan-id>",
		Short: "Open the results of a past scan",
		Long: `Print a stored scan from the local history database
(~/.anpu/anpu.db) — the same record ` + "`anpu diff`" + ` compares.

Findings can be filtered by severity floor (--severity) and capped
(--limit, 0 = all). --long adds full finding IDs (for --risk-accept
files), URLs, and evidence excerpts.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(defaultDBPath())
			if err != nil {
				return fmt.Errorf("opening scan history database: %w", err)
			}
			defer func() { _ = store.Close() }()

			summary, err := store.GetScan(args[0])
			if err != nil {
				return err
			}

			if exportPath != "" {
				var exportErr error
				switch format {
				case "html":
					exportErr = reporting.WriteHTML(summary, exportPath)
				case "json":
					exportErr = reporting.WriteJSON(summary, exportPath)
				case "sarif":
					exportErr = reporting.WriteSARIF(summary, exportPath)
				case "csv":
					exportErr = reporting.WriteCSV(summary, exportPath)
				case "md", "markdown":
					exportErr = reporting.WriteMarkdown(summary, exportPath)
				default:
					return fmt.Errorf("unknown --format %q: must be html, json, sarif, csv, or md", format)
				}
				if exportErr == nil {
					_, _ = fmt.Fprintf(os.Stderr, "Wrote %s to %s\n", format, exportPath)
				}
				return exportErr
			}

			printScanDetail(summary, severityFloor, limit, longOut)
			return nil
		},
	}

	cmd.Flags().StringVar(&exportPath, "export", "", "re-render this scan to a file instead of printing a summary")
	cmd.Flags().StringVar(&format, "format", "html", "export format when --export is set: html, json, sarif, csv, md")
	cmd.Flags().StringVar(&severityFloor, "severity", "", "minimum severity to print: low, medium, high, critical (empty = all)")
	cmd.Flags().IntVar(&limit, "limit", 50, "max findings to print (0 = all)")
	cmd.Flags().BoolVar(&longOut, "long", false, "print full finding IDs, URLs, and evidence excerpts")

	return cmd
}

// filterFindingsBySeverity returns findings at/above the floor,
// sorted by severity rank then ID for stable output. An invalid or
// empty floor keeps everything.
func filterFindingsBySeverity(fs []models.Finding, floor string) []models.Finding {
	floor = strings.ToLower(strings.TrimSpace(floor))
	out := make([]models.Finding, 0, len(fs))
	if floor == "" {
		out = append(out, fs...)
	} else {
		want := models.Severity(floor)
		if !want.Valid() {
			out = append(out, fs...)
		} else {
			for _, f := range fs {
				if f.Severity.Rank() >= want.Rank() {
					out = append(out, f)
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity.Rank() != out[j].Severity.Rank() {
			return out[i].Severity.Rank() > out[j].Severity.Rank()
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func printScanDetail(s *models.ScanSummary, severityFloor string, limit int, longOut bool) {
	fmt.Printf("Scan:    %s\n", s.ID)
	fmt.Printf("Target:  %s\n", s.Target)
	fmt.Printf("Profile: %s\n", s.Profile)
	fmt.Printf("Started: %s\n", s.StartedAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("Status:  %s\n\n", s.Status)

	if len(s.Technologies) > 0 {
		fmt.Println("Technologies:")
		for _, t := range s.Technologies {
			v := t.Version
			if v != "" {
				v = " v" + v
			}
			fmt.Printf("  - %s%s (%s)\n", t.Name, v, t.Category)
		}
		fmt.Println()
	}

	fmt.Printf("Endpoints discovered: %d\n\n", len(s.Endpoints))

	reporting.PrintResultsSummary(s, "", false)

	// Pipeline timing travels with the stored summary, same as HTML.
	if len(s.PhaseTimings) > 0 {
		fmt.Println("\nPhases:")
		for _, pt := range s.PhaseTimings {
			fmt.Printf("  %-12s %.1fs (%d stages)\n", pt.Phase, pt.Seconds, pt.Stages)
		}
	}
	if len(s.SlowestStages) > 0 {
		fmt.Println("Slowest stages:")
		for _, st := range s.SlowestStages {
			fmt.Printf("  %-12s %.1fs\n", st.Stage, st.Seconds)
		}
	}

	fs := filterFindingsBySeverity(s.Findings, severityFloor)
	hidden := len(s.Findings) - len(fs)
	if limit > 0 && len(fs) > limit {
		hidden += len(fs) - limit
		fs = fs[:limit]
	}
	if len(fs) > 0 {
		fmt.Println("\nFindings:")
		for _, f := range fs {
			fmt.Printf("  [%-8s] %s  (%s, %s)\n", f.Severity, f.Title, f.Category, f.Confidence)
			if longOut {
				fmt.Printf("      id: %s\n", f.ID)
				if f.URL != "" {
					fmt.Printf("      url: %s\n", f.URL)
				}
				if obs := oneLineFinding(f.Evidence.Observed, 160); obs != "" {
					fmt.Printf("      evidence: %s\n", obs)
				}
			}
		}
	}
	if hidden > 0 {
		fmt.Printf("\n(%d finding(s) hidden by --severity/--limit; re-run with --limit 0 to see all)\n", hidden)
	}
}

// oneLineFinding collapses whitespace for terminal display.
func oneLineFinding(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		s = s[:n] + "..."
	}
	return s
}
