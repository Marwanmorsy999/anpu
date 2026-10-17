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

This prints exactly the same line as ` + "`anpu --version`" + ` — the two
forms are identical by construction, both rendering
version.Full() from pkg/version.

The version, commit, and build date are injected at release time by
GoReleaser (see .goreleaser.yaml). Source builds report the version only,
with the commit and date shown as "unknown".`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Routed through cmd.OutOrStdout() (not bare fmt.Printf) so the
			// output is capturable and testable. A write failure must not
			// become a non-zero exit for a version query.
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "anpu version "+version.Full())
			return nil
		},
	}
}
