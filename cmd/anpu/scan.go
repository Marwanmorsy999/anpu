package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/anpu-project/anpu/internal/config"
	"github.com/anpu-project/anpu/internal/endpoints"
	"github.com/anpu-project/anpu/internal/findings"
	"github.com/anpu-project/anpu/internal/headers"
	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/integrations"
	"github.com/anpu-project/anpu/internal/recon"
	"github.com/anpu-project/anpu/internal/reporting"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/internal/scoring"
	"github.com/anpu-project/anpu/internal/storage"
	"github.com/anpu-project/anpu/internal/technology"
	"github.com/anpu-project/anpu/internal/tls"
	"github.com/anpu-project/anpu/pkg/models"
)

func newScanCmd() *cobra.Command {
	var (
		profile      string
		jsonOut      bool
		htmlOut      bool
		sarifOut     bool
		outputDir    string
		noNuclei     bool
		noZAP        bool
		failOn       string
		skipPreCheck bool
	)

	cmd := &cobra.Command{
		Use:   "scan <target>",
		Short: "Run a security scan against a target",
		Long: `Run ANPU's scan pipeline against a target URL.

ANPU only performs active network requests against targets you own or
are explicitly authorized to test.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var targetArg string
			if len(args) > 0 {
				targetArg = args[0]
			}
			return runScan(cmd, targetArg, profile, jsonOut, htmlOut, sarifOut, outputDir, noNuclei, noZAP, failOn, skipPreCheck)
		},
	}

	cmd.Flags().StringVar(&profile, "profile", "safe", "scan profile: safe, standard, or deep")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "write a JSON report")
	cmd.Flags().BoolVar(&htmlOut, "html", true, "write an HTML report")
	cmd.Flags().BoolVar(&sarifOut, "sarif", false, "write a SARIF report")
	cmd.Flags().StringVar(&outputDir, "output", "./reports", "directory to write reports into")
	cmd.Flags().BoolVar(&noNuclei, "no-nuclei", false, "disable the Nuclei integration for this scan")
	cmd.Flags().BoolVar(&noZAP, "no-zap", false, "disable the ZAP integration for this scan (no-op in this MVP; ZAP is not yet implemented)")
	cmd.Flags().StringVar(&failOn, "fail-on", "none", "return a non-zero exit status when findings meet/exceed this severity: none, low, medium, high, critical")
	cmd.Flags().BoolVar(&skipPreCheck, "skip-pre-check", false, "skip the initial connectivity check (scan runs even if host appears down)")

	return cmd
}

func runScan(cmd *cobra.Command, targetArg, profileStr string, jsonOut, htmlOut, sarifOut bool, outputDir string, noNuclei, noZAP bool, failOn string, skipPreCheck bool) error {
	profile := models.Profile(strings.ToLower(profileStr))
	if !profile.Valid() {
		return fmt.Errorf("invalid --profile %q: must be one of safe, standard, deep", profileStr)
	}
	failThreshold, err := parseFailOn(failOn)
	if err != nil {
		return err
	}

	fmt.Print(reporting.AuthorizationWarning)

	cfgFile, err := config.Load(resolveConfigPath())
	if err != nil {
		return err
	}

	if targetArg == "" {
		if cfgFile.Target.URL == "" {
			return fmt.Errorf("no target specified: pass a URL or set target.url in anpu.yaml")
		}
		targetArg = cfgFile.Target.URL
		if !strings.HasPrefix(targetArg, "http://") && !strings.HasPrefix(targetArg, "https://") {
			targetArg = "https://" + targetArg // default to https for config targets
		}
	}

	target, err := scanner.ValidateTarget(targetArg)
	if err != nil {
		return fmt.Errorf("target validation failed: %w", err)
	}

	modules := config.ResolveModules(profile, cfgFile, noNuclei, noZAP)

	cfg := models.ScanConfig{
		Target:       target.Raw,
		Profile:      profile,
		OutputDir:    outputDir,
		JSON:         jsonOut,
		HTML:         htmlOut,
		SARIF:        sarifOut,
		NoZAP:        noZAP,
		Verbose:      flagVerbose,
		SkipPreCheck: skipPreCheck,
		Modules:      modules,
	}

	reporting.PrintBanner(target.Raw)

	client := anpuhttp.NewClientWithLocalNetworkAllowed(scanner.AllowLocalNetwork)
	pipeline := buildPipeline(client, modules)

	summary, err := pipeline.Run(
		cmd.Context(),
		target,
		cfg,
		findings.Deduplicate,
		scoring.ScoreAll,
		scoring.AggregateScore,
		func(p scanner.StageProgress) {
			if p.Skipped {
				fmt.Println(reporting.StageLine(p.StageName, false, true, nil, false, 0, 0))
				return
			}
			fmt.Println(reporting.StageLine(p.StageName, p.Err == nil, false, p.Err, cfg.Verbose, p.NewFindingsCount, p.WarningsCount))
		},
	)
	if err != nil {
		return fmt.Errorf("scan pipeline failed: %w", err)
	}

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	reportPath := ""
	slugBase := target.Host
	if target.URL.Path != "" && target.URL.Path != "/" {
		slugBase += target.URL.Path
	}
	slug := sanitizeForFilename(slugBase)
	dateStr := time.Now().Format("2006-01-02-150405")

	if htmlOut {
		p := filepath.Join(outputDir, fmt.Sprintf("%s-%s.html", slug, dateStr))
		if err := reporting.WriteHTML(summary, p); err != nil {
			return err
		}
		reportPath = p
	}
	if jsonOut {
		p := filepath.Join(outputDir, fmt.Sprintf("%s-%s.json", slug, dateStr))
		if err := reporting.WriteJSON(summary, p); err != nil {
			return err
		}
		if reportPath == "" {
			reportPath = p
		}
	}
	if sarifOut {
		p := filepath.Join(outputDir, fmt.Sprintf("%s-%s.sarif", slug, dateStr))
		if err := reporting.WriteSARIF(summary, p); err != nil {
			return err
		}
		if reportPath == "" {
			reportPath = p
		}
	}

	store, err := storage.Open(defaultDBPath())
	if err != nil {
		summary.Warnings = append(summary.Warnings, fmt.Sprintf("could not open local scan history database: %v", err))
	} else {
		defer store.Close()
		if err := store.SaveScan(summary); err != nil {
			summary.Warnings = append(summary.Warnings, fmt.Sprintf("could not save scan to history: %v", err))
		}
	}

	reporting.PrintResultsSummary(summary, reportPath)
	if failThreshold != "" && scanMeetsThreshold(summary, failThreshold) {
		return fmt.Errorf("CI security gate failed: at least one %s-severity finding was detected", failThreshold)
	}
	return nil
}

// buildPipeline wires up every scan stage in pipeline order. This is the
// single place that knows about concrete scanner implementations — the
// orchestrator (internal/scanner) and every analyzer package only know
// about the Scanner interface, so adding a new stage means adding one
// entry here.
func buildPipeline(client *anpuhttp.Client, modules models.ModuleConfig) *scanner.Pipeline {
	nuclei := integrations.NewNucleiScanner()
	zap := integrations.NewZapScanner()

	return &scanner.Pipeline{
		Client: client,
		Stages: []scanner.Stage{
			{Label: "Recon", Enabled: modules.Recon, Scanner: recon.New(client)},
			{Label: "Technology", Enabled: modules.Technology, Scanner: technology.New(client)},
			{Label: "TLS", Enabled: modules.TLS, Scanner: tls.New(client)},
			{Label: "Headers", Enabled: modules.Headers, Scanner: headers.New(client)},
			{Label: "Cookies", Enabled: modules.Cookies, Scanner: headers.NewCookieAnalyzer(client)},
			{Label: "Endpoints", Enabled: modules.Endpoints, Scanner: endpoints.New(client)},
			{Label: "Nuclei", Enabled: modules.Nuclei, Scanner: nuclei},
			{Label: "ZAP", Enabled: modules.ZAP, Scanner: zap},
		},
	}
}

func sanitizeForFilename(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return b.String()
}

func parseFailOn(raw string) (models.Severity, error) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" || raw == "none" {
		return "", nil
	}
	s := models.Severity(raw)
	if !s.Valid() || s == models.SeverityInfo {
		return "", fmt.Errorf("invalid --fail-on %q: must be none, low, medium, high, or critical", raw)
	}
	return s, nil
}

func scanMeetsThreshold(summary *models.ScanSummary, threshold models.Severity) bool {
	for _, f := range summary.Findings {
		if f.Severity.Rank() >= threshold.Rank() {
			return true
		}
	}
	return false
}
