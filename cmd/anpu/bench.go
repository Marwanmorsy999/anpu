package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Marwanmorsy999/anpu/internal/bench"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

func newBenchCmd() *cobra.Command {
	var target, profilesFlag, format, out, gtPath, refreshDocs, checkFile string
	var runs int
	cmd := &cobra.Command{
		Use:   "bench",
		Short: "Measure ANPU against the planted-signal fixture",
		Long: `Run the honesty benchmark: scan a target with each profile, match
findings against planted ground-truth signals, and report hits, misses,
and unmatched counts — including what ANPU did NOT detect.

The benchmark measures; it does not pass or fail. A completed measurement
always exits 0 (even with MISS verdicts). Freshness enforcement is opt-in
via --check, which CI uses to keep docs/benchmark.md honest.

Only point bench at targets you own or are explicitly authorized to test.
The local fixture (tests/bench) is the intended target:

  docker compose -f tests/bench/docker-compose.yml up -d
  anpu bench --target http://127.0.0.1:8901`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runBench(cmd, target, profilesFlag, format, out, gtPath, refreshDocs, checkFile, runs)
		},
	}
	cmd.Flags().StringVar(&target, "target", "http://127.0.0.1:8901", "fixture target URL (only loopback targets get automatic local-network allowance)")
	cmd.Flags().StringVar(&profilesFlag, "profiles", "safe,advanced", "comma-separated scan profiles to measure")
	cmd.Flags().IntVar(&runs, "runs", 1, "runs per profile (table shows run 1; JSON keeps all runs)")
	cmd.Flags().StringVar(&gtPath, "ground-truth", "tests/bench/ground-truth.yml", "path to ground-truth.yml")
	cmd.Flags().StringVar(&format, "format", "table", "output format: table, json, or markdown")
	cmd.Flags().StringVar(&out, "out", "", "write output to a file instead of stdout")
	cmd.Flags().StringVar(&refreshDocs, "refresh-docs", "", "replace the freshness section in this docs file and exit")
	cmd.Flags().StringVar(&checkFile, "check", "", "fail (exit 1) if this docs file's freshness section differs from measured output")
	return cmd
}

// splitProfiles parses and validates the --profiles flag.
func splitProfiles(raw string) ([]string, error) {
	var out []string
	for _, p := range strings.Split(raw, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if !models.Profile(p).Valid() {
			return nil, fmt.Errorf("invalid profile %q", p)
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no profiles given (e.g. --profiles safe,advanced)")
	}
	return out, nil
}

// isLoopbackTarget reports whether a target URL points at loopback. The
// harness auto-allows local-network scanning for its child scans if and
// only if this holds; anything else inherits the caller's environment.
func isLoopbackTarget(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// pickNewestJSON returns the most recently modified *.json in dir.
func pickNewestJSON(dir string) (string, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) == 0 {
		return "", fmt.Errorf("no JSON report found in %s", dir)
	}
	sort.Slice(files, func(i, j int) bool {
		ai, _ := os.Stat(files[i])
		bj, _ := os.Stat(files[j])
		var am, bm int64
		if ai != nil {
			am = ai.ModTime().UnixNano()
		}
		if bj != nil {
			bm = bj.ModTime().UnixNano()
		}
		return am > bm
	})
	return files[0], nil
}

// checkFixture dials the target so a missing fixture fails fast with a
// useful message instead of a scan timeout.
func checkFixture(target string) error {
	u, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("invalid --target %q: %w", target, err)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 5*time.Second)
	if err != nil {
		return fmt.Errorf("cannot reach %s: is the fixture running? (docker compose -f tests/bench/docker-compose.yml up -d, or python tests/bench/server.py)", target)
	}
	_ = conn.Close()
	return nil
}

// runChildScan executes `anpu scan` as a child process (dogfooding the
// real CLI path, including flags and reporting) and returns the parsed
// JSON summary plus wall-clock seconds.
func runChildScan(exe, target, profile, outDir string, allowLocal bool) (*models.ScanSummary, float64, error) {
	args := []string{"scan", target,
		"--profile", profile,
		"--json", "--html=false", "--sarif=false", "--csv=false", "--md=false",
		"--output", outDir,
	}
	c := exec.Command(exe, args...) // #nosec G204 -- bench re-invokes ANPU's own binary (os.Executable) with fixed scan flags; only target/profile come from operator flags.
	c.Env = os.Environ()
	if allowLocal {
		c.Env = append(c.Env, "ANPU_ALLOW_LOCAL_NETWORK=1")
	}
	start := time.Now()
	combined, err := c.CombinedOutput()
	elapsed := time.Since(start).Seconds()
	if err != nil {
		tail := string(combined)
		if len(tail) > 2000 {
			tail = tail[len(tail)-2000:]
		}
		return nil, elapsed, fmt.Errorf("scan --profile %s failed: %v\n%s", profile, err, tail)
	}
	reportPath, err := pickNewestJSON(outDir)
	if err != nil {
		return nil, elapsed, err
	}
	data, err := os.ReadFile(reportPath) // #nosec G304 -- bench reads the report it just produced.
	if err != nil {
		return nil, elapsed, err
	}
	var summary models.ScanSummary
	if err := json.Unmarshal(data, &summary); err != nil {
		return nil, elapsed, fmt.Errorf("parsing report %s: %w", reportPath, err)
	}
	return &summary, elapsed, nil
}

func runBench(cmd *cobra.Command, target, profilesFlag, format, out, gtPath, refreshDocs, checkFile string, runs int) error {
	profiles, err := splitProfiles(profilesFlag)
	if err != nil {
		return err
	}
	if runs < 1 {
		return fmt.Errorf("--runs must be >= 1")
	}
	switch format {
	case "table", "json", "markdown":
	default:
		return fmt.Errorf("invalid --format %q (want table, json, or markdown)", format)
	}
	gt, err := bench.LoadGroundTruth(gtPath)
	if err != nil {
		return err
	}
	if err := checkFixture(target); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locating anpu binary: %w", err)
	}
	allowLocal := isLoopbackTarget(target) && os.Getenv("ANPU_ALLOW_LOCAL_NETWORK") == ""

	var records []bench.RunRecord
	var firstResults []bench.ProfileResult
	var durations []float64
	for _, profile := range profiles {
		for i := 0; i < runs; i++ {
			tmpDir, err := os.MkdirTemp("", "anpu-bench-*")
			if err != nil {
				return err
			}
			summary, elapsed, err := runChildScan(exe, target, profile, tmpDir, allowLocal)
			_ = os.RemoveAll(tmpDir)
			if err != nil {
				return err
			}
			result := bench.Evaluate(summary, gt, profile)
			records = append(records, bench.RunRecord{Profile: profile, DurationSeconds: elapsed, Result: result})
			if i == 0 {
				firstResults = append(firstResults, result)
				durations = append(durations, elapsed)
			}
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "bench: %s run %d/%d: %d findings in %.1fs\n",
				profile, i+1, runs, result.Total, elapsed)
		}
	}

	var output string
	switch format {
	case "json":
		rep := bench.Report{Target: target, Runs: runs, Records: records}
		output, err = bench.RenderJSON(rep)
		if err != nil {
			return err
		}
	case "markdown":
		output = bench.RenderMarkdown(firstResults, target, profiles, runs)
	default:
		output = bench.RenderTable(firstResults, durations)
	}

	if refreshDocs != "" {
		if format != "markdown" {
			return fmt.Errorf("--refresh-docs requires --format markdown")
		}
		if err := bench.RefreshSection(refreshDocs, output); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "bench: refreshed %s\n", refreshDocs)
	}
	if checkFile != "" {
		if format != "markdown" {
			return fmt.Errorf("--check requires --format markdown")
		}
		if err := bench.CheckSection(checkFile, output); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "bench: %s is fresh\n", checkFile)
	}
	if out != "" {
		if err := os.WriteFile(out, []byte(output), 0o600); err != nil {
			return err
		}
		return nil
	}
	_, _ = fmt.Fprint(cmd.OutOrStdout(), output)

	misses := 0
	for _, r := range firstResults {
		for _, o := range r.Signals {
			if o.Verdict == bench.VerdictMISS {
				misses++
			}
		}
	}
	if misses > 0 {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "bench: %d MISS verdict(s) — see docs/benchmark.md\n", misses)
	}
	return nil
}
