package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/anpu-project/anpu/internal/active"
	"github.com/anpu-project/anpu/internal/api"
	"github.com/anpu-project/anpu/internal/auth"
	"github.com/anpu-project/anpu/internal/authz"
	"github.com/anpu-project/anpu/internal/config"
	"github.com/anpu-project/anpu/internal/cors"
	"github.com/anpu-project/anpu/internal/dirs"
	"github.com/anpu-project/anpu/internal/endpoints"
	"github.com/anpu-project/anpu/internal/findings"
	"github.com/anpu-project/anpu/internal/headers"
	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/integrations"
	"github.com/anpu-project/anpu/internal/methods"
	"github.com/anpu-project/anpu/internal/portscan"
	"github.com/anpu-project/anpu/internal/recon"
	"github.com/anpu-project/anpu/internal/reporting"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/internal/scoring"
	"github.com/anpu-project/anpu/internal/secrets"
	"github.com/anpu-project/anpu/internal/storage"
	"github.com/anpu-project/anpu/internal/subdomains"
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
		noActive     bool
		failOn       string
		skipPreCheck bool
		quiet        bool
		rateLimit    float64
		requestDelay time.Duration

		// Auth flags — all opt-in, no credential is required or guessed.
		authToken   string
		authCookies []string
		authHeaders []string
		authRole    string

		// AuthZ flags (Phase 3) — second identity for authorization comparison.
		authzToken   string
		authzCookies []string
		authzHeaders []string
		authzRole    string

		// API flags (Phase 5) — schema-driven API security testing.
		openAPISource string
		graphQLURL    string
		apiBaseURL    string
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
			return runScan(cmd, targetArg, profile, jsonOut, htmlOut, sarifOut, outputDir, noNuclei, noZAP, noActive, failOn, skipPreCheck,
				quiet, rateLimit, requestDelay,
				authToken, authCookies, authHeaders, authRole,
				authzToken, authzCookies, authzHeaders, authzRole,
				openAPISource, graphQLURL, apiBaseURL)
		},
	}

	cmd.Flags().StringVar(&profile, "profile", "safe", "scan profile: safe, standard, or deep")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "write a JSON report")
	cmd.Flags().BoolVar(&htmlOut, "html", true, "write an HTML report")
	cmd.Flags().BoolVar(&sarifOut, "sarif", false, "write a SARIF report")
	cmd.Flags().StringVar(&outputDir, "output", "./reports", "directory to write reports into")
	cmd.Flags().BoolVar(&noNuclei, "no-nuclei", false, "disable the Nuclei integration for this scan")
	cmd.Flags().BoolVar(&noActive, "no-active", false, "disable the safe active testing engine (Phase 4) for this scan")
	cmd.Flags().BoolVar(&noZAP, "no-zap", false, "disable the ZAP integration for this scan (no-op in this MVP; ZAP is not yet implemented)")
	cmd.Flags().StringVar(&failOn, "fail-on", "none", "return a non-zero exit status when findings meet/exceed this severity: none, low, medium, high, critical")
	cmd.Flags().BoolVar(&skipPreCheck, "skip-pre-check", false, "skip the initial connectivity check (scan runs even if host appears down)")
	cmd.Flags().BoolVar(&quiet, "quiet", false, "suppress info-severity findings from terminal output (they still appear in reports)")
	cmd.Flags().Float64Var(&rateLimit, "rate-limit", 0, "max requests per second across all stages (0 = unlimited)")
	cmd.Flags().DurationVar(&requestDelay, "delay", 0, "fixed inter-request delay, e.g. 200ms or 1s (stacks with --rate-limit)")

	// Authentication flags — all opt-in.  ANPU never guesses or derives
	// credentials; everything here must be supplied explicitly.
	cmd.Flags().StringVar(&authToken, "auth-token", "", "bearer token to include in every request (Authorization: Bearer <token>)")
	cmd.Flags().StringArrayVar(&authCookies, "auth-cookie", nil, "cookie to include in every request, in name=value form (repeatable)")
	cmd.Flags().StringArrayVar(&authHeaders, "auth-header", nil, "custom header to include in every request, in 'Name: Value' form (repeatable)")
	cmd.Flags().StringVar(&authRole, "auth-role", "", "label for the scan identity, e.g. admin, user (default: anonymous / user)")

	// AuthZ (Phase 3) — second identity for authorization comparison testing.
	// ANPU will probe every discovered endpoint under both identities and flag anomalies.
	cmd.Flags().StringVar(&authzToken, "authz-token", "", "bearer token for the second (challenger) identity")
	cmd.Flags().StringArrayVar(&authzCookies, "authz-cookie", nil, "cookie for the second identity, in name=value form (repeatable)")
	cmd.Flags().StringArrayVar(&authzHeaders, "authz-header", nil, "custom header for the second identity, in 'Name: Value' form (repeatable)")
	cmd.Flags().StringVar(&authzRole, "authz-role", "", "label for the second identity, e.g. user, anonymous (default: challenger)")

	// API (Phase 5) — schema-driven API security testing.
	cmd.Flags().StringVar(&openAPISource, "openapi", "", "path or URL to an OpenAPI 3.x or Swagger 2.x schema; enables API-aware endpoint discovery and injection")
	cmd.Flags().StringVar(&graphQLURL, "graphql", "", "GraphQL endpoint URL to introspect (e.g. https://api.example.com/graphql)")
	cmd.Flags().StringVar(&apiBaseURL, "api-base-url", "", "override the base URL detected from the OpenAPI schema (useful for scanning staging with a production schema)")

	return cmd
}

func runScan(cmd *cobra.Command, targetArg, profileStr string, jsonOut, htmlOut, sarifOut bool, outputDir string, noNuclei, noZAP, noActive bool, failOn string, skipPreCheck bool,
	quiet bool, rateLimit float64, requestDelay time.Duration,
	authToken string, authCookies, authHeaders []string, authRole string,
	authzToken string, authzCookies, authzHeaders []string, authzRole string,
	openAPISource, graphQLURL, apiBaseURL string) error {

	profile := models.Profile(strings.ToLower(profileStr))
	if !profile.Valid() {
		return fmt.Errorf("invalid --profile %q: must be one of safe, standard, deep", profileStr)
	}
	failThreshold, err := parseFailOn(failOn)
	if err != nil {
		return err
	}

	// Build the auth context early so a bad flag combination surfaces
	// before we print the banner or touch the network.
	authCtx, err := auth.FromFlags(authToken, authCookies, authHeaders, authRole)
	if err != nil {
		return fmt.Errorf("invalid auth flags: %w", err)
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

	modules := config.ResolveModules(profile, cfgFile, noNuclei, noZAP, noActive)

	cfg := models.ScanConfig{
		Target:       target.Raw,
		Profile:      profile,
		OutputDir:    outputDir,
		JSON:         jsonOut,
		HTML:         htmlOut,
		SARIF:        sarifOut,
		NoZAP:        noZAP,
		Verbose:      flagVerbose,
		Quiet:        quiet,
		SkipPreCheck: skipPreCheck,
		Modules:      modules,
		Auth:         authCtx,
		RateLimit:    rateLimit,
		RequestDelay: requestDelay,
	}

	// Build the challenger context (context B) for authz comparison.
	// Defaults to "challenger" role if not specified.
	if authzRole == "" && (authzToken != "" || len(authzCookies) > 0 || len(authzHeaders) > 0) {
		authzRole = "challenger"
	}
	authzCtx, err := auth.FromFlags(authzToken, authzCookies, authzHeaders, authzRole)
	if err != nil {
		return fmt.Errorf("invalid authz flags: %w", err)
	}

	if authCtx.IsAuthenticated() {
		fmt.Printf("  auth context : %s\n", auth.Summary(authCtx))
	}
	if authzCtx.IsAuthenticated() {
		fmt.Printf("  authz context: %s\n", auth.Summary(authzCtx))
	}

	reporting.PrintBanner(target.Raw)

	client := anpuhttp.NewClientWithLocalNetworkAllowed(scanner.AllowLocalNetwork)
	if rateLimit > 0 || requestDelay > 0 {
		limiter := anpuhttp.NewRateLimiter(rateLimit, requestDelay)
		client = client.WithRateLimiter(limiter)
	}
	apiCfg := api.Config{
		OpenAPISource: openAPISource,
		GraphQLURL:    graphQLURL,
		BaseURL:       apiBaseURL,
	}
	pipeline := buildPipeline(client, modules, authzCtx, apiCfg)

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

	reporting.PrintResultsSummary(summary, reportPath, quiet)
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
func buildPipeline(client *anpuhttp.Client, modules models.ModuleConfig, authzCtx models.AuthContext, apiCfg api.Config) *scanner.Pipeline {
	nuclei := integrations.NewNucleiScanner()
	zap := integrations.NewZapScanner()

	// AuthZ testing runs after Endpoints so it has a full attack surface
	// to probe.  It is enabled whenever a challenger context (context B)
	// has been configured — anonymous vs. anonymous would produce nothing.
	authzEnabled := authzCtx.IsAuthenticated() || (authzCtx.Method == models.AuthMethodNone && authzCtx.Role != "")
	authzScanner := authz.New(client, authzCtx)

	return &scanner.Pipeline{
		Client: client,
		Stages: []scanner.Stage{
			{Label: "Recon", Enabled: modules.Recon, Scanner: recon.New(client)},
			{Label: "Technology", Enabled: modules.Technology, Scanner: technology.New(client)},
			{Label: "TLS", Enabled: modules.TLS, Scanner: tls.New(client)},
			{Label: "Headers", Enabled: modules.Headers, Scanner: headers.New(client)},
			{Label: "Cookies", Enabled: modules.Cookies, Scanner: headers.NewCookieAnalyzer(client)},
			{Label: "Endpoints", Enabled: modules.Endpoints, Scanner: endpoints.New(client)},
			// API scanner (Phase 5) runs immediately after endpoint discovery
			// so that schema-derived endpoints are in ScanContext.Endpoints
			// before the AuthZ and Active stages consume them.
			{Label: "API", Enabled: apiCfg.OpenAPISource != "" || apiCfg.GraphQLURL != "", Scanner: api.New(apiCfg)},
			{Label: "Subdomains", Enabled: modules.Subdomains, Scanner: subdomains.New()},
			{Label: "PortScan", Enabled: modules.PortScan, Scanner: portscan.New()},
			{Label: "Dirs", Enabled: modules.Dirs, Scanner: dirs.New(client)},
			// Secrets consumes the endpoints discovered above, so it must
			// stay after the Endpoints stage.
			{Label: "Secrets", Enabled: modules.Secrets, Scanner: secrets.New(client)},
			{Label: "CORS", Enabled: modules.CORS, Scanner: cors.New(client)},
			{Label: "Methods", Enabled: modules.Methods, Scanner: methods.New(client)},
			// AuthZ runs after Endpoints/Dirs so both contexts probe the
			// full discovered attack surface.
			{Label: "AuthZ", Enabled: authzEnabled, Scanner: authzScanner},
			// Active runs last among ANPU built-ins so it benefits from
			// the complete endpoint list and technology fingerprints.
			{Label: "Active", Enabled: modules.Active, Scanner: active.New(client)},
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
