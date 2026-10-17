package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/Marwanmorsy999/anpu/internal/feeds"
	"github.com/Marwanmorsy999/anpu/internal/integrations"
	"github.com/Marwanmorsy999/anpu/pkg/version"
	"github.com/spf13/cobra"
)

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check the ANPU environment and data locations",
		Long: `Print ANPU's runtime environment: Go build info, the scan-history
DB path, whether Nuclei is installed (and its version), and whether the
report output directory is writable. Exits 0 regardless — it reports the
environment, it does not gate on it.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDoctor(cmd)
		},
	}
}

func runDoctor(cmd *cobra.Command) error {
	out := cmd.OutOrStdout()
	ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
	defer cancel()

	fmt.Fprintln(out, "ANPU doctor")
	fmt.Fprintln(out)

	fmt.Fprintln(out, "Build:")
	fmt.Fprintf(out, "  version   : %s\n", version.Version)
	fmt.Fprintf(out, "  commit    : %s\n", version.Commit)
	fmt.Fprintf(out, "  built     : %s\n", version.Date)
	fmt.Fprintf(out, "  go        : %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		fmt.Fprintf(out, "  module    : %s %s\n", bi.Main.Path, bi.Main.Version)
	}
	fmt.Fprintf(out, "  data-dir  : %s\n", resolveDataDir())
	fmt.Fprintln(out)

	fmt.Fprintln(out, "Data:")
	dbPath := defaultDBPath()
	fmt.Fprintf(out, "  db        : %s", dbPath)
	if info, err := os.Stat(dbPath); err == nil {
		fmt.Fprintf(out, " (present, %d bytes)\n", info.Size())
	} else {
		fmt.Fprintln(out, " (not created yet — written on first scan)")
	}
	fmt.Fprintf(out, "  feeds     : %s\n", feeds.CacheDir())
	fmt.Fprintln(out)

	fmt.Fprintln(out, "Nuclei:")
	if path, ok := integrations.LookupBinary("nuclei"); ok {
		fmt.Fprintf(out, "  found     : %s\n", path)
		if v := integrations.ToolVersion(ctx, "nuclei"); v != "" {
			fmt.Fprintf(out, "  version   : %s\n", v)
		} else {
			fmt.Fprintln(out, "  version   : (no version response)")
		}
	} else {
		fmt.Fprintln(out, "  found     : not installed")
		fmt.Fprintln(out, "              advanced/ultra (standard/deep alias) profiles use the embedded fallback until installed")
	}
	fmt.Fprintln(out)

	fmt.Fprintln(out, "Reports:")
	reportDir, err := filepath.Abs("./reports")
	if err != nil {
		reportDir = "./reports"
	}
	if err := os.MkdirAll(reportDir, 0o750); err == nil {
		fmt.Fprintf(out, "  output    : %s (writable)\n", reportDir)
	} else {
		fmt.Fprintf(out, "  output    : %s (NOT writable: %v)\n", reportDir, err)
	}
	return nil
}
