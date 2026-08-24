package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	anpudiff "github.com/anpu-project/anpu/internal/diff"
	"github.com/anpu-project/anpu/internal/storage"
)

func newDiffCmd() *cobra.Command {
	var jsonOut bool
	var output string

	cmd := &cobra.Command{
		Use:   "diff <older-scan-id> <newer-scan-id>",
		Short: "Compare two previous scans",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(defaultDBPath())
			if err != nil {
				return fmt.Errorf("opening scan history database: %w", err)
			}
			defer store.Close()

			before, err := store.GetScan(args[0])
			if err != nil {
				return err
			}
			after, err := store.GetScan(args[1])
			if err != nil {
				return err
			}
			if before.Target != after.Target {
				return fmt.Errorf("cannot compare scans for different targets: %q vs %q", before.Target, after.Target)
			}

			result := anpudiff.Compare(before, after)
			if output != "" {
				data, err := json.MarshalIndent(result, "", "  ")
				if err != nil {
					return fmt.Errorf("encoding diff: %w", err)
				}
				if err := os.WriteFile(output, append(data, '\n'), 0o644); err != nil {
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
