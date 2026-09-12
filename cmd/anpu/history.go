package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Marwanmorsy999/anpu/internal/storage"
)

func newHistoryCmd() *cobra.Command {
	var limit int
	var targetFilter string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "history",
		Short: "See your past scans",
		Long: `List stored scans from the local history database
(~/.anpu/anpu.db) — the same source ` + "`anpu show`" + ` and ` + "`anpu diff`" + ` read.

--target filters by target substring (case-insensitive); --json prints
machine-readable rows with full IDs and targets (no truncation).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(defaultDBPath())
			if err != nil {
				return fmt.Errorf("opening scan history database: %w", err)
			}
			defer func() { _ = store.Close() }()

			scans, err := store.ListScans(limit)
			if err != nil {
				return fmt.Errorf("listing scans: %w", err)
			}
			scans = filterScans(scans, targetFilter)
			if len(scans) == 0 {
				if targetFilter != "" {
					fmt.Printf("No scans matching %q. Run `anpu scan <target>` first.\n", targetFilter)
					return nil
				}
				fmt.Println("No scans recorded yet. Run `anpu scan <target>` first.")
				return nil
			}

			if jsonOut {
				data, _ := json.MarshalIndent(scans, "", "  ")
				fmt.Println(string(data))
				return nil
			}
			fmt.Printf("%-24s %-44s %-10s %-12s %-10s %s\n", "SCAN ID", "TARGET", "PROFILE", "STATUS", "RISK", "FINDINGS")
			for _, s := range scans {
				fmt.Printf("%-24s %-44s %-10s %-12s %-10.1f %d\n",
					s.ID, truncateStr(s.Target, 44), s.Profile, s.Status, s.RiskScore, s.FindingsCnt)
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 20, "maximum number of scans to list")
	cmd.Flags().StringVar(&targetFilter, "target", "", "only list scans whose target contains this substring")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print rows as JSON with full IDs and targets")
	return cmd
}

// filterScans keeps rows whose target contains substr (case-insensitive).
// Empty substr keeps everything.
func filterScans(scans []storage.ScanListItem, substr string) []storage.ScanListItem {
	substr = strings.ToLower(strings.TrimSpace(substr))
	if substr == "" {
		return scans
	}
	out := make([]storage.ScanListItem, 0, len(scans))
	for _, s := range scans {
		if strings.Contains(strings.ToLower(s.Target), substr) {
			out = append(out, s)
		}
	}
	return out
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
