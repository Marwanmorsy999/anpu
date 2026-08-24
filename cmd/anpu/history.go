package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/anpu-project/anpu/internal/storage"
)

func newHistoryCmd() *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:   "history",
		Short: "List previous scans",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.Open(defaultDBPath())
			if err != nil {
				return fmt.Errorf("opening scan history database: %w", err)
			}
			defer store.Close()

			scans, err := store.ListScans(limit)
			if err != nil {
				return fmt.Errorf("listing scans: %w", err)
			}
			if len(scans) == 0 {
				fmt.Println("No scans recorded yet. Run `anpu scan <target>` first.")
				return nil
			}

			fmt.Printf("%-24s %-30s %-10s %-12s %-10s %s\n", "SCAN ID", "TARGET", "PROFILE", "STATUS", "RISK", "FINDINGS")
			for _, s := range scans {
				fmt.Printf("%-24s %-30s %-10s %-12s %-10.1f %d\n",
					s.ID, truncateStr(s.Target, 30), s.Profile, s.Status, s.RiskScore, s.FindingsCnt)
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 20, "maximum number of scans to list")
	return cmd
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
