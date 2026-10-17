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

	// doctor only reports; a write failure (closed pipe) must not turn
	// into a non-zero exit, so every write error is explicitly discarded.
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(out, format, a...) }
	l := func(a ...any) { _, _ = fmt.Fprintln(out, a...) }

	l("ANPU doctor")
	l()

	l("Build:")
	p("  version   : %s\n", version.Version)
	p("  commit    : %s\n", version.Commit)
	p("  built     : %s\n", version.Date)
	p("  go        : %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		p("  module    : %s %s\n", bi.Main.Path, bi.Main.Version)
	}
	p("  data-dir  : %s\n", resolveDataDir())
	l()

	l("Data:")
	dbPath := defaultDBPath()
	p("  db        : %s", dbPath)
	if info, err := os.Stat(dbPath); err == nil {
		p(" (present, %d bytes)\n", info.Size())
	} else {
		l(" (not created yet — written on first scan)")
	}
	p("  feeds     : %s\n", feeds.CacheDir())
	l()

	l("Nuclei:")
	if path, ok := integrations.LookupBinary("nuclei"); ok {
		p("  found     : %s\n", path)
		if v := integrations.ToolVersion(ctx, "nuclei"); v != "" {
			p("  version   : %s\n", v)
		} else {
			l("  version   : (no version response)")
		}
	} else {
		l("  found     : not installed")
		l("              advanced/ultra (standard/deep alias) profiles use the embedded fallback until installed")
	}
	l()

	l("Reports:")
	reportDir, err := filepath.Abs("./reports")
	if err != nil {
		reportDir = "./reports"
	}
	if mkErr := os.MkdirAll(reportDir, 0o750); mkErr == nil {
		p("  output    : %s (writable)\n", reportDir)
	} else {
		p("  output    : %s (NOT writable: %v)\n", reportDir, mkErr)
	}
	return nil
}
