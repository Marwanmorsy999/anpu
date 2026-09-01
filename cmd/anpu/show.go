package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/anpu-project/anpu/internal/reporting"
	"github.com/anpu-project/anpu/internal/storage"
	"github.com/anpu-project/anpu/pkg/models"
)

func newShowCmd() *cobra.Command {
	var exportPath string
	var format string

	cmd := &cobra.Command{
		Use:   "show <scan-id>",
		Short: "Show the results of a previous scan",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(defaultDBPath())
			if err != nil {
				return fmt.Errorf("opening scan history database: %w", err)
			}
			defer store.Close()

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
				default:
					return fmt.Errorf("unknown --format %q: must be html, json, or sarif", format)
				}
				if exportErr == nil {
					fmt.Fprintf(os.Stderr, "Wrote %s to %s\n", format, exportPath)
				}
				return exportErr
			}

			printScanDetail(summary)
			return nil
		},
	}

	cmd.Flags().StringVar(&exportPath, "export", "", "re-render this scan to a file instead of printing a summary")
	cmd.Flags().StringVar(&format, "format", "html", "export format when --export is set: html, json, sarif")

	return cmd
}

func printScanDetail(s *models.ScanSummary) {
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

	if len(s.Findings) > 0 {
		fmt.Println("\nFindings:")
		for _, f := range s.Findings {
			fmt.Printf("  [%-8s] %s  (%s, %s)\n", f.Severity, f.Title, f.Category, f.Confidence)
		}
	}
}
