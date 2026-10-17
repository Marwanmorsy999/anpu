package main

import (
	"fmt"

	"github.com/Marwanmorsy999/anpu/pkg/version"
	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the ANPU version",
		Long: `Print the ANPU version and build metadata.

The version is injected at release time by GoReleaser (pkg/version).
Source builds report the version default; the commit is "unknown"
unless set via ldflags.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("anpu version %s\n", version.Version)
			if version.Commit != "" && version.Commit != "unknown" {
				fmt.Printf("commit %s\n", version.Commit)
			}
			return nil
		},
	}
}
