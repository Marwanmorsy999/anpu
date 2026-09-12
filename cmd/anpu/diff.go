package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	anpudiff "github.com/Marwanmorsy999/anpu/internal/diff"
	"github.com/Marwanmorsy999/anpu/internal/storage"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

func newDiffCmd() *cobra.Command {
	var jsonOut bool
	var output string

	cmd := &cobra.Command{
		Use:   "diff <older-scan-id|older.json> <newer-scan-id|newer.json>",
		Short: "See what changed between two scans",
		Long: `Compare two scans — stored history IDs or --json report files.

Identity model: findings match by DedupKey
(category + normalized URL + title + parameter + CWE); a finding whose
severity, confidence, score, evidence, or remediation changed reports
as "changed". Endpoints match by normalized URL, technologies by
name + category (version bumps report as "changed").

HTML/CSV/MD reports are lossy renders and cannot be diffed — use the
--json siblings (same filename stem). Targets must be equivalent after
normalization (scheme/host case, default ports, and trailing slashes
are ignored).`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			before, err := loadDiffInput(args[0])
			if err != nil {
				return err
			}
			after, err := loadDiffInput(args[1])
			if err != nil {
				return err
			}
			if normalizeCompareTarget(before.Target) != normalizeCompareTarget(after.Target) {
				return fmt.Errorf("cannot compare scans for different targets: %q vs %q", before.Target, after.Target)
			}

			result := anpudiff.Compare(before, after)
			if output != "" {
				data, err := json.MarshalIndent(result, "", "  ")
				if err != nil {
					return fmt.Errorf("encoding diff: %w", err)
				}
				if err := os.WriteFile(output, append(data, '\n'), 0o600); err != nil {
					return fmt.Errorf("writing diff: %w", err)
				}
			}
			if jsonOut {
				data, _ := json.MarshalIndent(result, "", "  ")
				fmt.Println(string(data))
			} else {
				printDiff(result)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print the comparison as JSON")
	cmd.Flags().StringVar(&output, "output", "", "write the JSON comparison to a file")
	return cmd
}

// loadDiffInput resolves one diff operand: a --json report file when the
// argument names an existing file, otherwise a history scan ID.
func loadDiffInput(arg string) (*models.ScanSummary, error) {
	if info, err := os.Stat(arg); err == nil && !info.IsDir() {
		if !strings.HasSuffix(strings.ToLower(arg), ".json") {
			return nil, fmt.Errorf("report files for diff must be --json reports (.json); %q is a lossy render — use its .json sibling", arg)
		}
		data, err := os.ReadFile(arg) // #nosec G304 -- CLI diffs an operator-specified report file.
		if err != nil {
			return nil, fmt.Errorf("reading report %q: %w", arg, err)
		}
		var summary models.ScanSummary
		if err := json.Unmarshal(data, &summary); err != nil {
			return nil, fmt.Errorf("parsing report %q as an ANPU JSON report: %w", arg, err)
		}
		if strings.TrimSpace(summary.Target) == "" {
			return nil, fmt.Errorf("report %q has no scan target — not an ANPU JSON report", arg)
		}
		return &summary, nil
	}
	store, err := storage.Open(defaultDBPath())
	if err != nil {
		return nil, fmt.Errorf("opening scan history database: %w", err)
	}
	defer func() { _ = store.Close() }()
	return store.GetScan(arg)
}

func printDiff(r *anpudiff.Result) {
	fmt.Printf("ANPU SCAN DIFF\n\n")
	fmt.Printf("From: %s\nTo:   %s\nTarget: %s\n\n", r.FromID, r.ToID, r.Target)
	fmt.Printf("Risk Score: %.1f → %.1f  (%+.1f)\n\n", r.RiskBefore, r.RiskAfter, r.RiskDelta)
	fmt.Printf("Findings:       +%d  -%d  ~%d\n", r.FindingsAdded, r.FindingsRemoved, r.FindingsChanged)
	fmt.Printf("Endpoints:      +%d  -%d\n", r.EndpointsAdded, r.EndpointsRemoved)
	fmt.Printf("Technologies:   +%d  -%d\n\n", r.TechnologiesAdded, r.TechnologiesRemoved)

	for _, c := range r.Findings {
		prefix := changePrefix(c.Kind)
		fmt.Printf("%s %-8s %s\n", prefix, c.Finding.Severity, c.Finding.Title)
		if c.Finding.URL != "" {
			fmt.Printf("    %s\n", c.Finding.URL)
		}
	}
	for _, c := range r.Endpoints {
		fmt.Printf("%s endpoint %s\n", changePrefix(c.Kind), c.Endpoint.URL)
	}
	for _, c := range r.Technologies {
		if c.Kind == "changed" {
			fmt.Printf("~ technology %s: %s → %s\n", c.Technology.Name, displayVersion(c.Previous.Version), displayVersion(c.Technology.Version))
		} else {
			fmt.Printf("%s technology %s%s\n", changePrefix(c.Kind), c.Technology.Name, versionSuffix(c.Technology.Version))
		}
	}
}

func changePrefix(kind string) string {
	switch kind {
	case "added":
		return "+"
	case "removed":
		return "-"
	case "changed":
		return "~"
	default:
		return " "
	}
}

func displayVersion(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}

func versionSuffix(v string) string {
	if v == "" {
		return ""
	}
	return " v" + v
}
