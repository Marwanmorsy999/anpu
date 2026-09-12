package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/anpu-project/anpu/internal/active"
	"github.com/anpu-project/anpu/internal/auth"
	"github.com/anpu-project/anpu/internal/config"
	"github.com/anpu-project/anpu/internal/feeds"
	"github.com/anpu-project/anpu/internal/findings"
	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/integrations"
	"github.com/anpu-project/anpu/internal/oob"
	"github.com/anpu-project/anpu/internal/reporting"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/internal/scope"
	"github.com/anpu-project/anpu/internal/scoring"
	"github.com/anpu-project/anpu/internal/storage"
	"github.com/anpu-project/anpu/pkg/models"
)

// ScanRuntime (runtime.go) carries flag state into runScan explicitly;
// the legacy package globals it replaces were removed in Phase 6.

func newScanCmd() *cobra.Command {
	var (
		profile               string
		jsonOut               bool
		htmlOut               bool
		sarifOut              bool
		csvOut                bool
		mdOut                 bool
		outputDir             string
		noNuclei              bool
		noZAP                 bool
		noActive              bool
		noCSRF                bool
		noDeps                bool
		noTakeover            bool
		noSRI                 bool
		noBackup              bool
		noKatana              bool
		noHttpx               bool
		noSubfinder           bool
		noDalfox              bool
		noDNSIntel            bool
		noIPIntel             bool
		noNaabu               bool
		noDNSx                bool
		noRDAP                bool
		noLeak                bool
		noFavicon             bool
		noDoH                 bool
		noBucket              bool
		noBGP                 bool
		noAPI                 bool
		noAuthZ               bool
		oobHost               string
		oobInteractsh         bool
		nucleiTags            string
		unsafeFlag            bool
		zapAjax               bool
		parallelFlag          int
		checkpointFlag        string
		resumeFlag            string
		adversarial           bool
		confirmAuthorized     bool
		ghostFlag             bool
		ghostCanaryPrefixFlag string
		ghostWorkersFlag      int
		proxyPoolFlag         string
		failOn                string
		skipPreCheck          bool
		quiet                 bool
		silent                bool
		plain                 bool
		noBanner              bool
		proxyURL              string
		minConfidence         string
		rateLimit             float64
		requestDelay          time.Duration
		stealth               bool
		randomAgent           bool
		customUA              string
		disableMods           []string
		enableMods            []string
		onlyMods              []string

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

		// Batch / pipe flags — hacker workflow: feed targets via stdin
		// or a file, stream findings as JSONL for chaining with jq,
		// nuclei, dalfox, etc.
		stdinFlag      bool
		listFile       string
		jsonlOut       bool
		scopeFile      string
		autoInst       bool
		yesFlag        bool
		riskAcceptFlag string
		budgetFlag     time.Duration
	)

	cmd := &cobra.Command{
		Use:   "scan <target>",
		Short: "Check a website for security problems",
		Long: `Run ANPU's scan pipeline against a target URL.

ANPU only performs active network requests against targets you own or
are explicitly authorized to test.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var targetArg string
			if len(args) > 0 {
				targetArg = args[0]
			}
			integrations.CustomTagsOverride = nucleiTags
			integrations.ZapAjax = zapAjax
			integrations.UnsafeEnabled = unsafeFlag
			rt := &ScanRuntime{
				OOBInteractsh:        oobInteractsh,
				Adversarial:          adversarial,
				AdversarialConfirmed: confirmAuthorized,
				ScopeFile:            scopeFile,
				AutoInstall:          autoInst,
				AssumeYes:            yesFlag,
				Unsafe:               unsafeFlag,
				Budget:               budgetFlag,
				Parallel:             parallelFlag,
				Checkpoint:           checkpointFlag,
				Resume:               resumeFlag,
				RiskAccept:           riskAcceptFlag,
				Ghost:                ghostFlag,
				GhostCanaryPrefix:    ghostCanaryPrefixFlag,
				GhostWorkers:         ghostWorkersFlag,
				ProxyPool:            proxyPoolFlag,
			}
			rt.applyUnsafeOverride()
			if adversarial && !confirmAuthorized && !unsafeFlag {
				return fmt.Errorf("--adversarial requires --confirm-authorized (authorized ultra/adversarial only; no data destruction, Benign/LowImpact only)")
			}
			if rt.Adversarial {
				active.AdversarialEnabled = true
				active.AdversarialConfirmed = rt.AdversarialConfirmed
			} else {
				active.AdversarialEnabled = false
				active.AdversarialConfirmed = false
			}
			// Wire ghost mode into active canaries and http transport
			if rt.Ghost {
				if ghostCanaryPrefixFlag == "" {
					anpuhttp.GhostCanaryPrefix = ""
					active.SetGhost(true, "")
				} else {
					anpuhttp.GhostCanaryPrefix = ghostCanaryPrefixFlag
					active.SetGhost(true, ghostCanaryPrefixFlag)
				}
				anpuhttp.GhostEnabled = true
				active.GhostEnabled = true
				anpuhttp.GhostWorkers = ghostWorkersFlag
			} else {
				active.SetGhost(false, ghostCanaryPrefixFlag)
				anpuhttp.GhostEnabled = false
				active.GhostEnabled = false
				anpuhttp.GhostCanaryPrefix = ghostCanaryPrefixFlag
			}
			return runScan(cmd, rt, targetArg, profile, jsonOut, htmlOut, sarifOut, csvOut, mdOut, outputDir, noNuclei, noZAP, noActive, noCSRF, noDeps, noTakeover, noSRI, noBackup, noKatana, noHttpx, noSubfinder, noDalfox, noDNSIntel, noIPIntel, noNaabu, noDNSx, noRDAP, noLeak, noFavicon, noDoH, noBucket, noBGP, noAPI, noAuthZ, oobHost, failOn, skipPreCheck,
				quiet, silent, plain, noBanner, proxyURL, minConfidence, rateLimit, requestDelay, stealth, randomAgent, customUA, disableMods, enableMods, onlyMods,
				stdinFlag, listFile, jsonlOut,
				authToken, authCookies, authHeaders, authRole,
				authzToken, authzCookies, authzHeaders, authzRole,
				openAPISource, graphQLURL, apiBaseURL)
		},
	}

	cmd.Flags().StringVar(&profile, "profile", "safe", "scan profile: safe, advanced, ultra (aliases: standard→advanced, deep→ultra)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "write a JSON report")
	cmd.Flags().BoolVar(&htmlOut, "html", true, "write an HTML report")
	cmd.Flags().BoolVar(&sarifOut, "sarif", false, "write a SARIF report")
	cmd.Flags().BoolVar(&csvOut, "csv", false, "write a CSV finding export (one row per finding)")
	cmd.Flags().BoolVar(&mdOut, "md", false, "write a Markdown finding summary")
	cmd.Flags().StringVar(&outputDir, "output", "./reports", "directory to write reports into")
	cmd.Flags().BoolVar(&noNuclei, "no-nuclei", false, "disable the Nuclei integration for this scan")
	cmd.Flags().BoolVar(&noActive, "no-active", false, "disable the safe active testing engine (Phase 4) for this scan")
	cmd.Flags().BoolVar(&noCSRF, "no-csrf", false, "disable CSRF token detection (Phase 10A)")
	cmd.Flags().BoolVar(&noDeps, "no-deps", false, "disable dependency vulnerability scanning (Phase 10B)")
	cmd.Flags().BoolVar(&noSRI, "no-sri", false, "disable Subresource Integrity passive check (Phase 12C)")
	cmd.Flags().BoolVar(&noBackup, "no-backup", false, "disable backup file discovery (Phase 12E)")
	cmd.Flags().BoolVar(&noKatana, "no-katana", false, "disable the katana crawl integration for this scan")
	cmd.Flags().BoolVar(&noHttpx, "no-httpx", false, "disable the httpx probe integration for this scan")
	cmd.Flags().BoolVar(&noSubfinder, "no-subfinder", false, "disable the subfinder integration for this scan")
	cmd.Flags().BoolVar(&noDalfox, "no-dalfox", false, "disable the dalfox XSS confirmation integration for this scan")
	cmd.Flags().BoolVar(&noDNSIntel, "no-dnsintel", false, "disable DNS record intel (MX/NS/TXT/SPF/DMARC)")
	cmd.Flags().BoolVar(&noIPIntel, "no-ipintel", false, "disable IP/ASN/cloud intel")
	cmd.Flags().BoolVar(&noNaabu, "no-naabu", false, "disable the naabu fast port-scan integration")
	cmd.Flags().BoolVar(&noDNSx, "no-dnsx", false, "disable the dnsx DNS toolkit integration")
	cmd.Flags().BoolVar(&noRDAP, "no-rdap", false, "disable RDAP WHOIS domain registration intel")
	cmd.Flags().BoolVar(&noLeak, "no-leak", false, "disable private-IP/internal-host leak detection")
	cmd.Flags().BoolVar(&noFavicon, "no-favicon", false, "disable favicon hash correlation")
	cmd.Flags().BoolVar(&noDoH, "no-doh", false, "disable DNS-over-HTTPS exposure check")
	cmd.Flags().BoolVar(&noBucket, "no-bucket", false, "disable cloud bucket probe (S3/Azure/GCS)")
	cmd.Flags().BoolVar(&noBGP, "no-bgp", false, "disable BGP prefix/ASN intel")
	cmd.Flags().BoolVar(&noAPI, "no-api", false, "disable API schema discovery and testing")
	cmd.Flags().BoolVar(&noAuthZ, "no-authz", false, "disable authorization testing")
	cmd.Flags().StringVar(&oobHost, "oob-host", "", "out-of-band callback host for Log4Shell/JNDI and blind injection detection (e.g. your interactsh or Burp Collaborator host)")
	cmd.Flags().BoolVar(&oobInteractsh, "oob-interactsh", false, "use the public interactsh fleet (oast.pro) to CONFIRM blind SSRF/XXE/Log4Shell via observed callbacks (sends callback metadata to interactsh servers)")
	cmd.Flags().StringVar(&nucleiTags, "nuclei-tags", "", "override nuclei template tags (comma-separated, e.g. exposure,misconfig); widens the scan considerably")
	cmd.Flags().BoolVar(&zapAjax, "zap-ajax", false, "enable the ZAP Ajax spider for JS-heavy routes (Docker runs only; longer scan)")
	cmd.Flags().BoolVar(&adversarial, "adversarial", false, "enable adversarial hazardous probes (stateful multi-step, header/body/WS, JWT/mass-assign/race/smuggling/proto-pollute) — requires --confirm-authorized on authorized ultra targets only; Benign/LowImpact only, no data destruction")
	cmd.Flags().BoolVar(&confirmAuthorized, "confirm-authorized", false, "confirm you are authorized to run hazardous adversarial probes against this target (required with --adversarial)")
	cmd.Flags().BoolVar(&ghostFlag, "ghost", false, "undetectable mode: Chrome 131 JA3, h2, GREASE, stable header set, Pareto 800-3500ms jitter, no anpu canary substring, proxy rotation, adaptive rate, payload polymorphism (combine with --proxy-pool and --adversarial for max power)")
	cmd.Flags().StringVar(&ghostCanaryPrefixFlag, "ghost-canary-prefix", "", "custom ghost canary prefix (default \"\" when --ghost, no anpu substring; set to \"anpu\" to keep allowlist mode)")
	cmd.Flags().IntVar(&ghostWorkersFlag, "ghost-workers", 4, "parallel ghost workers for sharded active scanning (0 = sequential)")
	cmd.Flags().StringVar(&proxyPoolFlag, "proxy-pool", "", "path to file with proxy URLs (one per line, http/https/socks5) for RoundRobin per-request rotation with healthcheck")
	cmd.Flags().BoolVar(&noTakeover, "no-takeover", false, "disable subdomain takeover detection (Phase 11B)")
	cmd.Flags().BoolVar(&noZAP, "no-zap", false, "disable the OWASP ZAP integration for this scan (ZAP requires Docker or a local zap.sh installation; enabled by default on --profile deep)")
	cmd.Flags().StringVar(&failOn, "fail-on", "none", "return a non-zero exit status when findings meet/exceed this severity: none, low, medium, high, critical")
	cmd.Flags().BoolVar(&skipPreCheck, "skip-pre-check", false, "skip the initial connectivity check (scan runs even if host appears down)")
	cmd.Flags().BoolVar(&quiet, "quiet", false, "suppress info-severity findings from terminal output (they still appear in reports)")
	cmd.Flags().BoolVar(&silent, "silent", false, "suppress banner, stage lines, and summary for clean piped output (reports still written)")
	cmd.Flags().BoolVar(&plain, "plain", false, "use ASCII markers ([ok]/[!!]/[--]) instead of unicode symbols")
	cmd.Flags().BoolVar(&noBanner, "no-banner", false, "suppress the ANPU banner (target line still shown unless --silent)")
	cmd.Flags().StringVar(&proxyURL, "proxy", "", "route all HTTP traffic through a proxy (http/https/socks5), e.g. http://127.0.0.1:8080 for Burp/ZAP; HTTP_PROXY/HTTPS_PROXY/NO_PROXY env are honored when unset")
	cmd.Flags().StringVar(&minConfidence, "min-confidence", "none", "minimum confidence level for findings: none, low, medium, high, confirmed (findings below this are excluded from all output)")
	cmd.Flags().Float64Var(&rateLimit, "rate-limit", 0, "max requests per second across all stages (0 = unlimited)")
	cmd.Flags().DurationVar(&requestDelay, "delay", 0, "fixed inter-request delay, e.g. 200ms or 1s (stacks with --rate-limit)")
	cmd.Flags().BoolVar(&stealth, "stealth", false, "anonymous mode: random browser UA per request + jitter (combine with --proxy socks5://127.0.0.1:9050 for Tor anonymity)")
	cmd.Flags().BoolVar(&randomAgent, "random-agent", false, "use a random browser User-Agent per request instead of the truthful ANPU UA")
	cmd.Flags().StringVar(&customUA, "user-agent", "", "override User-Agent for all requests")
	cmd.Flags().StringSliceVar(&disableMods, "disable", nil, "disable modules (comma-separated, e.g. --disable dirs,active) — simple alternative to many --no-* flags")
	cmd.Flags().StringSliceVar(&enableMods, "enable", nil, "enable modules (comma-separated, e.g. --enable portscan,naabu) — overrides profile defaults")
	cmd.Flags().StringSliceVar(&onlyMods, "only", nil, "run only this module(s) (e.g. --only dnsintel or --only headers,tls) — disables all others")

	// --- hide advanced/noise flags from default --help (still work) ---
	for _, n := range []string{
		"no-nuclei", "no-active", "no-csrf", "no-deps", "no-takeover", "no-sri", "no-backup",
		"no-katana", "no-httpx", "no-subfinder", "no-dalfox", "no-dnsintel", "no-ipintel", "no-naabu", "no-dnsx",
		"no-rdap", "no-leak", "no-favicon", "no-doh", "no-bucket", "no-bgp", "no-api", "no-authz", "no-zap",
		"no-banner", "plain", "random-agent", "user-agent", "oob-host", "oob-interactsh", "nuclei-tags", "zap-ajax", "skip-pre-check", "quiet", "min-confidence",
		"auth-token", "auth-cookie", "auth-header", "auth-role", "authz-token", "authz-cookie", "authz-header", "authz-role",
		"openapi", "graphql", "api-base-url",
	} {
		_ = cmd.Flags().MarkHidden(n)
	}

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

	// Batch / pipe flags.
	cmd.Flags().BoolVar(&stdinFlag, "stdin", false, "read targets (one URL per line) from stdin, e.g. cat targets.txt | anpu scan --stdin")
	cmd.Flags().StringVarP(&listFile, "list", "l", "", "read targets (one URL per line) from a file")
	cmd.Flags().StringVar(&scopeFile, "scope-file", "", "path to an allowlist file (one host per line); targets not listed abort before any request (hard stop)")
	cmd.Flags().BoolVar(&autoInst, "auto-install", false, "auto-install missing external tools mid-scan (go/pipx/docker; apt/choco best-effort) instead of skipping them")
	cmd.Flags().BoolVar(&yesFlag, "yes", false, "assume yes for install confirmations (scripts/CI)")
	cmd.Flags().BoolVar(&unsafeFlag, "unsafe", false, "operator master override: implies adversarial+confirmed, lifts safe-purity filters, fuller wrapper strength (defaults/warnings/exclusions unchanged)")
	cmd.Flags().IntVar(&parallelFlag, "parallel", 8, "run snapshot-safe stages concurrently with N workers (1 = sequential, max 32)")
	cmd.Flags().StringVar(&checkpointFlag, "checkpoint", "", "write per-stage checkpoint snapshots here for --resume")
	cmd.Flags().StringVar(&resumeFlag, "resume", "", "resume an interrupted scan from a checkpoint file")
	cmd.Flags().StringVar(&riskAcceptFlag, "risk-accept", "", "suppress finding IDs listed in a YAML accept file (id/reason/expires)")
	cmd.Flags().DurationVar(&budgetFlag, "budget", 0, "cap total scan wall time, e.g. 15m (queued stages stop between stages with per-phase coverage; 0 = uncapped)")
	cmd.Flags().BoolVar(&jsonlOut, "jsonl", false, "stream findings as JSON lines to stdout for piping (implies --silent human output)")

	return cmd
}

func runScan(cmd *cobra.Command, rt *ScanRuntime, targetArg, profileStr string, jsonOut, htmlOut, sarifOut, csvOut, mdOut bool, outputDir string, noNuclei, noZAP, noActive, noCSRF, noDeps, noTakeover, noSRI, noBackup, noKatana, noHttpx, noSubfinder, noDalfox, noDNSIntel, noIPIntel, noNaabu, noDNSx, noRDAP, noLeak, noFavicon, noDoH, noBucket, noBGP, noAPI, noAuthZ bool, oobHost, failOn string, skipPreCheck bool,
	quiet, silent, plain, noBanner bool, proxyURL, minConfidenceStr string, rateLimit float64, requestDelay time.Duration, stealth, randomAgent bool, customUA string, disableMods, enableMods, onlyMods []string,
	stdinFlag bool, listFile string, jsonlOut bool,
	authToken string, authCookies, authHeaders []string, authRole string,
	authzToken string, authzCookies, authzHeaders []string, authzRole string,
	openAPISource, graphQLURL, apiBaseURL string) error {

	profile := models.Profile(strings.ToLower(profileStr))
	if !profile.Valid() {
		return fmt.Errorf("invalid --profile %q: must be one of safe, advanced, ultra (aliases: standard, deep)", profileStr)
	}
	profile = profile.Normalize()
	// Ultra-only second-family confirmations (Phase 3): same rules as
	// advanced, plus exclusive corroboration paths in XSS, command
	// injection, and blind timing. Level shortcuts inherit this via runScan.
	active.SetUltraConfirm(profile == models.ProfileUltra)
	failThreshold, err := parseFailOn(failOn)
	if err != nil {
		return err
	}
	minConf, err := findings.ParseMinConfidence(minConfidenceStr)
	if err != nil {
		return err
	}

	// Build the auth context early so a bad flag combination surfaces
	// before we print the banner or touch the network.
	authCtx, err := auth.FromFlags(authToken, authCookies, authHeaders, authRole)
	if err != nil {
		return fmt.Errorf("invalid auth flags: %w", err)
	}

	bannerOpts := reporting.BannerOptions{Silent: silent, NoBanner: noBanner, Plain: plain}
	reporting.PrintAuthorizationWarning()

	cfgFile, err := config.Load(resolveConfigPath())
	if err != nil {
		return err
	}

	// Config-file defaults for adversarial/ghost (CLI flags win when set;
	// rt was already populated from CLI flags by the calling command's
	// RunE, or left at defaults for level shortcuts).
	// scan.adversarial in YAML still requires --confirm-authorized on the CLI.
	if !rt.Adversarial && cfgFile.Scan.Adversarial != nil && *cfgFile.Scan.Adversarial {
		rt.Adversarial = true
	}
	// scan.unsafe in YAML acts like CLI --unsafe (master override).
	if !rt.Unsafe && cfgFile.Scan.Unsafe != nil && *cfgFile.Scan.Unsafe {
		rt.Unsafe = true
		integrations.UnsafeEnabled = true
		rt.Adversarial = true
		rt.AdversarialConfirmed = true
	}
	if !rt.Ghost && cfgFile.Scan.Ghost != nil && *cfgFile.Scan.Ghost {
		rt.Ghost = true
	}
	if rt.GhostCanaryPrefix == "" && cfgFile.Scan.GhostCanaryPrefix != nil {
		rt.GhostCanaryPrefix = *cfgFile.Scan.GhostCanaryPrefix
	}
	if (rt.GhostWorkers == 0 || rt.GhostWorkers == 4) && cfgFile.Scan.GhostWorkers != nil && *cfgFile.Scan.GhostWorkers >= 0 {
		rt.GhostWorkers = *cfgFile.Scan.GhostWorkers
	}
	if rt.Ghost && rt.GhostWorkers <= 0 {
		rt.GhostWorkers = 4
	}
	if rt.ProxyPool == "" && cfgFile.Scan.ProxyPool != nil {
		rt.ProxyPool = *cfgFile.Scan.ProxyPool
	}
	if rt.Adversarial && !rt.AdversarialConfirmed {
		return fmt.Errorf("--adversarial requires --confirm-authorized (authorized ultra/adversarial only; no data destruction, Benign/LowImpact only)")
	}
	if rt.Adversarial {
		active.AdversarialEnabled = true
		active.AdversarialConfirmed = rt.AdversarialConfirmed
	} else {
		active.AdversarialEnabled = false
		active.AdversarialConfirmed = false
	}
	// Re-apply ghost canary wiring when values came from the config file
	// (the RunE block already handled CLI-provided values).
	if rt.Ghost {
		active.SetGhost(true, rt.GhostCanaryPrefix)
		active.GhostEnabled = true
		anpuhttp.GhostEnabled = true
		anpuhttp.GhostCanaryPrefix = rt.GhostCanaryPrefix
		anpuhttp.GhostWorkers = rt.GhostWorkers
	}

	// --jsonl implies --silent human output so stdout stays pure JSONL.
	if jsonlOut {
		silent = true
		bannerOpts.Silent = true
	}

	targets, err := collectTargets(cmd, targetArg, stdinFlag, listFile, cfgFile)
	if err != nil {
		return err
	}
	batch := len(targets) > 1

	modules := config.ResolveModules(profile, cfgFile, noNuclei, noZAP, noActive, noCSRF, noDeps, noTakeover, noSRI, noBackup, noKatana, noHttpx, noSubfinder, noDalfox, noDNSIntel, noIPIntel, noNaabu, noDNSx, noRDAP, noLeak, noFavicon, noDoH, noBucket, noBGP, noAPI, noAuthZ)
	// --only is absolute: disable all, then enable only the requested ones.
	// --disable/--enable are ignored when --only is present (warn).
	if len(onlyMods) > 0 {
		if len(disableMods) > 0 {
			_, _ = fmt.Fprintf(os.Stderr, "anpu: --disable is ignored when --only is present (only %q will run)\n", strings.Join(onlyMods, ","))
		}
		if len(enableMods) > 0 {
			_, _ = fmt.Fprintf(os.Stderr, "anpu: --enable is ignored when --only is present (only %q will run)\n", strings.Join(onlyMods, ","))
		}
		disableAllModules(&modules)
		applyModuleToggles(&modules, nil, onlyMods)
	} else {
		applyModuleToggles(&modules, disableMods, enableMods)
	}
	// Re-assert after toggles: disableAllModules zeroes the struct, which
	// would otherwise wipe an authorized --adversarial/--unsafe grant on
	// --only runs (adversarial tools would warn-skip despite consent).
	if rt.Adversarial && rt.AdversarialConfirmed {
		modules.Adversarial = true
	}
	// Explicit --openapi/--graphql with a disabled API module warns instead
	// of silently forcing the stage on (--only stays absolute).
	if (openAPISource != "" || graphQLURL != "") && !modules.API {
		_, _ = fmt.Fprintf(os.Stderr, "anpu: --openapi/--graphql ignored (API module disabled; use --enable api or --only api)\n")
	}

	// Wire OOB host for Log4Shell JNDI probing (Phase 12I).
	// Set before the active scanner runs so the log4shellRule picks it up.
	active.Log4ShellOOBHost = oobHost

	// Automatic OOB confirmation via the public interactsh fleet.
	// Strictly opt-in: without the flag, InteractSession stays nil and
	// blind rules behave exactly as before (in-band signals only).
	if rt.OOBInteractsh {
		sess, serr := oob.NewSession("")
		if serr != nil {
			_, _ = fmt.Fprintf(os.Stderr, "anpu: interactsh unavailable, continuing without OOB confirmation: %v\n", serr)
		} else {
			active.InteractSession = sess
			defer func() {
				_ = sess.Close()
				active.InteractSession = nil
			}()
			if !silent {
				fmt.Printf("  oob        : interactsh session %s (blind SSRF/XXE/Log4Shell auto-confirm)\n", sess.Host())
			}
		}
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

	if authCtx.IsAuthenticated() && !silent {
		fmt.Printf("  auth context : %s\n", auth.Summary(authCtx))
	}
	if authzCtx.IsAuthenticated() && !silent {
		fmt.Printf("  authz context: %s\n", auth.Summary(authzCtx))
	}

	client, apiCfg, err := buildClient(rt, clientOptions{
		customUA:     customUA,
		stealth:      stealth,
		randomAgent:  randomAgent,
		proxyURL:     proxyURL,
		rateLimit:    rateLimit,
		requestDelay: requestDelay,
		openAPI:      openAPISource,
		graphQLURL:   graphQLURL,
		apiBaseURL:   apiBaseURL,
		silent:       silent,
	})
	if err != nil {
		return err
	}
	pipeline := buildPipeline(client, modules, authzCtx, apiCfg, profile, rt.Unsafe, onlyMods)
	pipeline.MaxParallel = rt.Parallel
	pipeline.CheckpointFile = rt.Checkpoint
	pipeline.ResumeFile = rt.Resume

	confFilter := func(fs []models.Finding) ([]models.Finding, []models.Finding) {
		return findings.FilterByConfidence(fs, minConf)
	}

	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	var (
		scanErrors int
		gateTrip   bool
		scanned    int
	)
	// Auto-install: missing external binaries self-provision mid-scan.
	// Config-file default applies unless the CLI flag was set.
	if !rt.AutoInstall && cfgFile.Scan.AutoInstall != nil && *cfgFile.Scan.AutoInstall {
		rt.AutoInstall = true
	}
	integrations.AutoInstallEnabled = rt.AutoInstall
	if rt.AutoInstall {
		// Alert before anything is fetched: list the missing tools
		// this scan may install, then confirm once. --stdin targets
		// come from the same stream, so never prompt there.
		missing := missingBinaries(modules)
		if !silent || len(missing) > 0 {
			fmt.Fprintf(os.Stderr, "anpu: --auto-install may download+build %d missing tool(s): %s\n",
				len(missing), strings.Join(missing, ", "))
		}
		proceed := rt.AssumeYes || stdinFlag || listFile != ""
		if !proceed {
			proceed = askConfirm(os.Stdin, os.Stderr, false, stdinInteractive(), false,
				fmt.Sprintf("Proceed (installs up to %d tools as their stages run)?", len(missing)))
		} else if !silent {
			_, _ = fmt.Fprintln(os.Stderr, "anpu: auto-install confirmed (--yes / non-interactive / file input)")
		}
		if !proceed {
			_, _ = fmt.Fprintln(os.Stderr, "anpu: auto-install declined — continuing with embedded coverage only")
			rt.AutoInstall = false
			integrations.AutoInstallEnabled = false
		} else if !silent {
			fmt.Println("  auto-install : enabled (missing tools self-provision: go/pipx/docker, apt/choco best-effort)")
		}
	}
	// Scope hard stop: resolved once, enforced before any packet.
	allowlist, err := scope.LoadFile(rt.ScopeFile)
	if err != nil {
		return err
	}
	for i, rawTarget := range targets {
		target, err := scanner.ValidateTarget(rawTarget)
		if err != nil {
			if !batch {
				return fmt.Errorf("target validation failed: %w", err)
			}
			_, _ = fmt.Fprintf(os.Stderr, "anpu: skipping target %q: %v\n", rawTarget, err)
			scanErrors++
			continue
		}
		if err := scope.Enforce(allowlist, rt.ScopeFile, target.Host, target.Port); err != nil {
			if !batch {
				return err
			}
			_, _ = fmt.Fprintf(os.Stderr, "anpu: %v\n", err)
			scanErrors++
			continue
		}
		// Scope auto-expansion: a same-registrable-domain redirect hop
		// (apex → www) joins the in-memory scan scope so discovery does
		// not starve on empty crawls. Cross-domain hops never expand.
		// Fail-silent: an unreachable target simply scans alias-free.
		var targetAliases []string
		if alias, ok := probeScopeExpansion(cmd.Context(), client, target.Raw); ok {
			targetAliases = []string{alias}
			if !silent {
				fmt.Printf("  scope expanded: %s → +%s (same-site redirect)\n", target.Host, alias)
			}
		}
		if batch && !silent {
			fmt.Printf("\n=== [%d/%d] %s ===\n", i+1, len(targets), target.Raw)
		}
		cfg := models.ScanConfig{
			Target:        target.Raw,
			TargetAliases: targetAliases,
			Budget:        rt.Budget,
			Profile:       profile,
			OutputDir:     outputDir,
			JSON:          jsonOut,
			HTML:          htmlOut,
			SARIF:         sarifOut,
			NoZAP:         noZAP,
			Verbose:       flagVerbose,
			Quiet:         quiet,
			MinConfidence: minConf,
			SkipPreCheck:  skipPreCheck,
			Modules:       modules,
			Auth:          authCtx,
			RateLimit:     rateLimit,
			RequestDelay:  requestDelay,
		}

		reporting.PrintBannerWithOptions(target.Raw, bannerOpts)

		live := reporting.NewLive(os.Stdout, bannerOpts)
		live.SetVerbose(cfg.Verbose)
		stageLabels := make([]string, 0, len(pipeline.Stages))
		for _, st := range pipeline.Stages {
			stageLabels = append(stageLabels, st.Label)
		}
		live.Expect(stageLabels)
		live.Boot(target.Raw, string(profile), len(stageLabels))

		// Wave 3 scoring hook: KEV exploited-in-wild flags (cache
		// auto-refreshes when older than a week, fail-silent); live
		// EPSS only when ANPU_EPSS=1. Offline-safe.
		kev := feeds.EnsureKEV(cmd.Context())
		scoreWithFeeds := func(fs []models.Finding) []models.Finding {
			fs = feeds.Enrich(fs, kev, os.Getenv("ANPU_EPSS") == "1")
			return scoring.ScoreAll(fs)
		}
		staticPhases := &reporting.PhaseTracker{}
		summary, err := pipeline.Run(
			cmd.Context(),
			target,
			cfg,
			findings.Deduplicate,
			scoreWithFeeds,
			scoring.AggregateScore,
			confFilter,
			func(p scanner.StageProgress) {
				if silent {
					return
				}
				ls := reporting.LiveStage{
					Label:       p.StageName,
					Done:        p.Done,
					Skipped:     p.Skipped,
					Reason:      p.Reason,
					Err:         p.Err,
					NewFindings: p.NewFindingsCount,
					Warnings:    p.WarningsCount,
					Phase:       string(p.Phase),
				}
				if live.Animated() {
					live.StageDone(ls)
					return
				}
				if h := staticPhases.Header(ls.Phase, bannerOpts); h != "" {
					fmt.Println(h)
				}
				fmt.Println(reporting.StaticStageLine(ls, bannerOpts))
			},
		)
		live.Close()
		if err == nil {
			// Wave 3 reputation: 2 keyless lookups (URLhaus + ThreatFox),
			// surfaced as warnings. Fail-silent offline.
			summary.Warnings = append(summary.Warnings, feeds.Reputation(cmd.Context(), target.Raw, target.Host)...)
		}
		if err != nil {
			if !batch {
				return fmt.Errorf("scan pipeline failed: %w", err)
			}
			_, _ = fmt.Fprintf(os.Stderr, "anpu: scan failed for %s: %v\n", target.Raw, err)
			scanErrors++
			continue
		}

		// Risk acceptance: suppress listed finding IDs (with reason and
		// optional expiry) before reports and history are written, so
		// accepted risks stop re-alerting (including in drift).
		if rt.RiskAccept != "" {
			entries, rerr := findings.LoadRiskAccept(rt.RiskAccept)
			if rerr != nil {
				_, _ = fmt.Fprintf(os.Stderr, "anpu: %v\n", rerr)
			} else {
				kept, suppressed, notes := findings.ApplyRiskAccept(summary.Findings, entries, time.Now())
				summary.Findings = kept
				summary.SuppressedByRiskAccept = len(suppressed)
				summary.RecomputeSeverityCounts()
				if len(suppressed) > 0 {
					summary.Warnings = append(summary.Warnings, fmt.Sprintf("risk-accept: suppressed %d finding(s) (%s)", len(suppressed), strings.Join(suppressed, ", ")))
				}
				for _, n := range notes {
					summary.Warnings = append(summary.Warnings, "risk-accept: "+n)
				}
			}
		}

		reportPath := ""
		slugBase := target.Host
		if target.URL.Path != "" && target.URL.Path != "/" {
			slugBase += target.URL.Path
		}
		slug := sanitizeForFilename(slugBase)
		dateStr := time.Now().Format("2006-01-02-150405")

		reportPath, skipTarget, err := writeScanReports(summary,
			reportOutputs{HTML: htmlOut, JSON: jsonOut, SARIF: sarifOut, CSV: csvOut, MD: mdOut},
			outputDir, slug, dateStr, target.Raw, batch, &scanErrors)
		if err != nil {
			return err
		}
		if skipTarget {
			continue
		}

		store, err := storage.Open(defaultDBPath())
		if err != nil {
			summary.Warnings = append(summary.Warnings, fmt.Sprintf("could not open local scan history database: %v", err))
		} else {
			if err := store.SaveScan(summary); err != nil {
				summary.Warnings = append(summary.Warnings, fmt.Sprintf("could not save scan to history: %v", err))
			}
			_ = store.Close()
		}

		if jsonlOut {
			if err := reporting.WriteFindingsJSONL(os.Stdout, summary); err != nil {
				return err
			}
		} else {
			live.Panel(summary, reportPath, quiet, bannerOpts)
		}
		scanned++
		if failThreshold != "" && scanMeetsThreshold(summary, failThreshold) {
			gateTrip = true
			if !batch {
				return fmt.Errorf("CI security gate failed: at least one %s-severity finding was detected", failThreshold)
			}
		}
	}

	if scanned == 0 && scanErrors > 0 {
		return fmt.Errorf("all %d target(s) failed to scan", len(targets))
	}
	if gateTrip {
		return fmt.Errorf("CI security gate failed: at least one %s-severity finding was detected", failThreshold)
	}
	if scanErrors > 0 {
		return fmt.Errorf("%d of %d target(s) failed to scan", scanErrors, len(targets))
	}
	return nil
}

// probeScopeExpansion fetches the target once and reports a
// same-registrable-domain redirect alias (apex → www). One bounded
// request; any failure means alias-free (fail-open).
func probeScopeExpansion(ctx context.Context, client *anpuhttp.Client, targetRaw string) (string, bool) {
	if client == nil {
		return "", false
	}
	pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	resp, err := client.Get(pctx, targetRaw)
	if err != nil || resp == nil || resp.FinalURL == "" {
		return "", false
	}
	return scope.RedirectAlias(targetRaw, resp.FinalURL)
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
