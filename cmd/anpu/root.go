package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var (
	flagConfigPath string
	flagVerbose    bool
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "anpu",
		Short: "ANPU — Guard what you build. Open-source web security intelligence.",
		Long: `ANPU is an authorized web security analysis and attack-surface
intelligence tool. It orchestrates existing security tools (Nuclei,
and in future OWASP ZAP) alongside its own passive analyzers, and
combines the results into a single, understandable security report.

ANPU must only be used against targets you own or are explicitly
authorized to test.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().StringVar(&flagConfigPath, "config", "", "path to a YAML config file (default: anpu.yaml in the current directory, if present)")
	root.PersistentFlags().BoolVar(&flagVerbose, "verbose", false, "show per-stage finding and warning counts")

	root.AddCommand(newScanCmd())
	root.AddCommand(newHistoryCmd())
	root.AddCommand(newShowCmd())
	root.AddCommand(newDiffCmd())
	root.AddCommand(newToolsCmd())

	return root
}

func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".anpu"
	}
	return filepath.Join(home, ".anpu")
}

func defaultDBPath() string {
	dir := defaultDataDir()
	_ = os.MkdirAll(dir, 0o755)
	return filepath.Join(dir, "anpu.db")
}

func resolveConfigPath() string {
	if flagConfigPath != "" {
		return flagConfigPath
	}
	if _, err := os.Stat("anpu.yaml"); err == nil {
		return "anpu.yaml"
	}
	return "anpu.yaml" // config.Load tolerates a missing file
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "Error:", err)
	os.Exit(1)
}
