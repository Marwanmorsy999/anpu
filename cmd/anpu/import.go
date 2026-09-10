package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/anpu-project/anpu/internal/importx"
	"github.com/anpu-project/anpu/pkg/models"
)

// newImportCmd implements `anpu import` (Wave 4 item 147): normalize
// Burp XML, ZAP JSON, or HAR captures into ANPU findings for
// query/export/diff workflows. Import-only: ANPU sends no traffic.
func newImportCmd() *cobra.Command {
	var (
		format  string
		target  string
		output  string
		jsonOut bool
	)
	cmd := &cobra.Command{
		Use:   "import <file>",
		Short: "Import Burp, ZAP, or HAR results as findings",
		Long: `Normalize a third-party artifact into ANPU findings.

Formats (auto-detected from extension when --format is omitted):
  .xml  Burp Suite export
  .json ZAP JSON report (zap-baseline -J)
  .har  HTTP Archive capture (endpoints + 5xx notes)

Examples:
  anpu import burp.xml --json
  anpu import zap.json --output imported.json
  anpu import session.har --target https://example.com/`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			if format == "" {
				format = detectImportFormat(path)
			}
			if target == "" {
				target = "imported"
			}
			data, err := os.ReadFile(path) // #nosec G304 -- CLI reads operator-specified paths (reports, wordlists, checkpoints, code dir).
			if err != nil {
				return fmt.Errorf("reading %s: %w", path, err)
			}
			var findings []models.Finding
			var endpoints []models.Endpoint
			switch strings.ToLower(format) {
			case "burp", "xml":
				findings, err = importx.ParseBurp(data, target)
			case "zap", "json":
				findings, err = importx.ParseZAP(data, target)
			case "har":
				findings, endpoints, err = importx.ParseHAR(data, target)
			default:
				return fmt.Errorf("unknown --format %q: burp, zap, or har", format)
			}
			if err != nil {
				return err
			}
			fmt.Printf("Imported %d finding(s), %d endpoint(s) from %s (%s)\n", len(findings), len(endpoints), path, format)
			if output != "" {
				doc := struct {
					Findings  []models.Finding  `json:"findings"`
					Endpoints []models.Endpoint `json:"endpoints"`
				}{findings, endpoints}
				raw, _ := json.MarshalIndent(doc, "", "  ")
				if err := os.WriteFile(output, raw, 0o600); err != nil {
					return err
				}
				fmt.Printf("Wrote %s\n", output)
			}
			if jsonOut {
				raw, _ := json.MarshalIndent(findings, "", "  ")
				fmt.Println(string(raw))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "", "burp, zap, or har (default: from file extension)")
	cmd.Flags().StringVar(&target, "target", "", "target label for imported findings")
	cmd.Flags().StringVar(&output, "output", "", "write normalized findings+endpoints JSON here")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print findings as JSON")
	return cmd
}

func detectImportFormat(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".har"):
		return "har"
	case strings.HasSuffix(lower, ".xml"):
		return "burp"
	case strings.HasSuffix(lower, ".json"):
		return "zap"
	}
	return ""
}
