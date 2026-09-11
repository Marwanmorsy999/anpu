package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/anpu-project/anpu/internal/active"
	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/integrations"
	"github.com/anpu-project/anpu/pkg/models"
	"github.com/spf13/cobra"
)

// newLevelCmd creates a simple shortcut for a profile.
// Usage: anpu safe https://example.com  (no --profile needed)
func newLevelCmd(use string, profile models.Profile, short string) *cobra.Command {
	var (
		outputDir              string
		jsonOut                bool
		sarifOut               bool
		csvOut                 bool
		mdOut                  bool
		jsonlOut               bool
		proxyURL               string
		stealth                bool
		rateLimit              float64
		oobInteractshLevel     bool
		adversarialLevel       bool
		confirmAuthorizedLevel bool
		ghostLevel             bool
		ghostCanaryPrefixLevel string
		ghostWorkersLevel      int
		proxyPoolLevel         string
		scopeFileLevel         string
		autoInstallLevel       bool
		yesLevel               bool
		unsafeLevel            bool
		zapAjaxLevel           bool
		parallelLevel          int
		checkpointLevel        string
		resumeLevel            string
		riskAcceptLevel        string
		disableModsLevel       []string
		enableModsLevel        []string
		onlyModsLevel          []string
	)

	cmd := &cobra.Command{
		Use:   use + " <target>",
		Short: short,
		Long: fmt.Sprintf("%s — runs the %s profile.\n\n%s\n\nExamples:\n  anpu %s https://example.com\n  anpu %s https://example.com --json --output ./reports\n  anpu %s https://example.com --stealth --proxy http://127.0.0.1:8080",
			short, profile, levelDesc(profile), use, use, use),
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetArg := ""
			if len(args) > 0 {
				targetArg = args[0]
			}
			integrations.UnsafeEnabled = unsafeLevel
			integrations.ZapAjax = zapAjaxLevel
			rt := &ScanRuntime{
				OOBInteractsh:        oobInteractshLevel,
				Adversarial:          adversarialLevel,
				AdversarialConfirmed: confirmAuthorizedLevel,
				ScopeFile:            scopeFileLevel,
				AutoInstall:          autoInstallLevel,
				AssumeYes:            yesLevel,
				Unsafe:               unsafeLevel,
				Parallel:             parallelLevel,
				Checkpoint:           checkpointLevel,
				Resume:               resumeLevel,
				RiskAccept:           riskAcceptLevel,
				Ghost:                ghostLevel,
				GhostCanaryPrefix:    ghostCanaryPrefixLevel,
				GhostWorkers:         ghostWorkersLevel,
				ProxyPool:            proxyPoolLevel,
			}
			rt.applyUnsafeOverride()
			if adversarialLevel && !confirmAuthorizedLevel {
				return fmt.Errorf("--adversarial requires --confirm-authorized (authorized ultra/adversarial only; no data destruction, Benign/LowImpact only)")
			}
			if adversarialLevel {
				active.AdversarialEnabled = true
				active.AdversarialConfirmed = confirmAuthorizedLevel
			} else {
				active.AdversarialEnabled = false
				active.AdversarialConfirmed = false
			}
			if ghostLevel {
				active.SetGhost(true, ghostCanaryPrefixLevel)
				active.GhostEnabled = true
				anpuhttp.GhostEnabled = true
				anpuhttp.GhostCanaryPrefix = ghostCanaryPrefixLevel
				anpuhttp.GhostWorkers = ghostWorkersLevel
			} else {
				active.SetGhost(false, ghostCanaryPrefixLevel)
				active.GhostEnabled = false
				anpuhttp.GhostEnabled = false
				anpuhttp.GhostCanaryPrefix = ghostCanaryPrefixLevel
			}
			// Delegate to the full scan pipeline with level-appropriate profile.
			// We reuse runScan with sensible defaults: html=true, silent/plain handling via reporting.
			return runScan(cmd, rt, targetArg, string(profile),
				jsonOut, true, sarifOut, csvOut, mdOut, outputDir,
				false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, "", "none", false,
				false, false, false, false, proxyURL, "none", rateLimit, time.Duration(0), stealth, false, "", disableModsLevel, enableModsLevel, onlyModsLevel,
				false, "", jsonlOut,
				"", nil, nil, "",
				"", nil, nil, "",
				"", "", "")
		},
	}

	cmd.Flags().StringVar(&outputDir, "output", "./reports", "directory for reports")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "also write JSON report")
	cmd.Flags().BoolVar(&sarifOut, "sarif", false, "also write SARIF report")
	cmd.Flags().BoolVar(&csvOut, "csv", false, "also write CSV finding export")
	cmd.Flags().BoolVar(&mdOut, "md", false, "also write Markdown finding summary")
	cmd.Flags().BoolVar(&jsonlOut, "jsonl", false, "stream findings as JSONL to stdout")
	cmd.Flags().StringVar(&proxyURL, "proxy", "", "proxy URL (http/https/socks5) e.g. http://127.0.0.1:8080")
	cmd.Flags().BoolVar(&stealth, "stealth", false, "random UA + jitter + TLS shuffle")
	cmd.Flags().Float64Var(&rateLimit, "rate-limit", 0, "max requests per second (0 = unlimited)")
	cmd.Flags().BoolVar(&oobInteractshLevel, "oob-interactsh", false, "use the public interactsh fleet (oast.pro) to CONFIRM blind SSRF/XXE/Log4Shell via observed callbacks")
	cmd.Flags().BoolVar(&adversarialLevel, "adversarial", false, "enable adversarial hazardous probes — requires --confirm-authorized on authorized ultra targets only; Benign/LowImpact only, no data destruction")
	cmd.Flags().BoolVar(&confirmAuthorizedLevel, "confirm-authorized", false, "confirm you are authorized to run hazardous adversarial probes against this target (required with --adversarial)")
	cmd.Flags().BoolVar(&ghostLevel, "ghost", false, "undetectable mode: Chrome 131 JA3, h2, GREASE, Pareto 800-3500ms jitter, no anpu canary substring, proxy rotation, adaptive rate")
	cmd.Flags().StringVar(&ghostCanaryPrefixLevel, "ghost-canary-prefix", "", "custom ghost canary prefix (default \"\" when --ghost, no anpu substring)")
	cmd.Flags().IntVar(&ghostWorkersLevel, "ghost-workers", 4, "parallel ghost workers for sharded active scanning (0 = sequential)")
	cmd.Flags().StringVar(&proxyPoolLevel, "proxy-pool", "", "path to file with proxy URLs (one per line, http/https/socks5) for RoundRobin rotation")
	cmd.Flags().StringVar(&scopeFileLevel, "scope-file", "", "path to an allowlist file (one host per line); off-scope targets abort before any request")
	cmd.Flags().BoolVar(&autoInstallLevel, "auto-install", false, "auto-install missing external tools mid-scan instead of skipping them")
	cmd.Flags().BoolVar(&yesLevel, "yes", false, "assume yes for install confirmations")
	cmd.Flags().BoolVar(&unsafeLevel, "unsafe", false, "operator master override (see scan --help)")
	cmd.Flags().BoolVar(&zapAjaxLevel, "zap-ajax", false, "enable the ZAP Ajax spider (Docker runs only)")
	cmd.Flags().IntVar(&parallelLevel, "parallel", 8, "run snapshot-safe stages concurrently with N workers")
	cmd.Flags().StringVar(&checkpointLevel, "checkpoint", "", "write per-stage checkpoint snapshots here for --resume")
	cmd.Flags().StringVar(&resumeLevel, "resume", "", "resume an interrupted scan from a checkpoint file")
	cmd.Flags().StringVar(&riskAcceptLevel, "risk-accept", "", "suppress finding IDs listed in a YAML accept file")
	cmd.Flags().StringSliceVar(&disableModsLevel, "disable", nil, "disable modules (comma-separated, e.g. --disable dirs,active)")
	cmd.Flags().StringSliceVar(&enableModsLevel, "enable", nil, "enable modules (comma-separated, e.g. --enable portscan,naabu)")
	cmd.Flags().StringSliceVar(&onlyModsLevel, "only", nil, "run only this module(s) (e.g. --only headers,tls)")

	return cmd
}

func levelDesc(p models.Profile) string {
	switch p.Normalize() {
	case models.ProfileSafe:
		return "SAFE — passive only, zero noise. Tools: Recon, DNSIntel, IPIntel, RDAP, Leak, Favicon, DoH, Bucket, BGP, ArchiveURLs, CertSAN, EmailHarv, DNSAudit, EmailAuth, CSPRecon, SocialHijack, CommentMiner, BrokenLink, OriginIP, Clickjack, PolicyHeaders, CookiePrefix, JWTPlus, H2FP, GFClassify, CertHistory, SubPermute, Technology, TLS, Headers, Cookies, Endpoints, SRI, Params, Codesecrets (local dir), API/AuthZ anonymous probing as designed behavior."
	case models.ProfileAdvanced:
		return "ADVANCED — safe + polite active. Adds: Subdomains, Takeover, Dirs, Secrets, CORS, Methods, CSRF, Backup, Deps, Active checks (XSS/SQLi/SSRF/blind), exposure pack (ExposedGit, ExposedConfig, Actuator, DebugPages, OAuthAnalyzer, SAMLMetadata, CSWSH, PostMessage, JSSecrets, HiddenParams), technique pack (VerbTamper, CacheDeception, ForbiddenBypass, TakeoverPlus, APIVersion, APIConsole, VHost), vuln-expansion pack (GraphQLFP, GraphQLSchema, SSTIExpand, NoSQLExpand, H2Smuggle adversarial-gated, RedirectPack, LFIPack, CVEPack, CORSPlus, AXFRPlus, BackupPlus, FaviconPlus, DebugMethods, EncodePoly, DiffOracle, Soap, Nsecwalk, Wafdetect, Oauthpack, Ppollute, Swscope, Timeoracle, Jwtconfirm), Katana, Httpx, Subfinder, DNSx, Dalfox, Nuclei."
	case models.ProfileUltra:
		return "ULTRA — everything: safe + advanced plus PortScan, Naabu, ZAP, DNS brute-force, and the full Wave 2 wrapper depth (binary when installed, embedded natives otherwise; --auto-install self-provisions). Most thorough, most intrusive. Add --adversarial --confirm-authorized for hazardous stateful adversarial (header/body/WS, JWT/mass-assign/race/smuggling/proto-pollute, sqli boolean differential + bundle, alias flood) — authorized ultra only, Benign/LowImpact no destruction, Grade F 9.0 max+volume."
	default:
		return string(p)
	}
}

func newSafeCmd() *cobra.Command {
	return newLevelCmd("safe", models.ProfileSafe, "Gentle check — looks, never touches")
}

func newAdvancedCmd() *cobra.Command {
	// alias: standard
	cmd := newLevelCmd("advanced", models.ProfileAdvanced, "Deeper check — gentle look plus careful tests")
	cmd.Aliases = []string{"standard"}
	return cmd
}

func newUltraCmd() *cobra.Command {
	cmd := newLevelCmd("ultra", models.ProfileUltra, "Deepest check — finds the most, takes the longest")
	cmd.Aliases = []string{"deep"}
	return cmd
}

// ensure profile flag also accepts aliases at validation time
func init() {
	// nothing, alias handling is in models.Profile.Normalize
	_ = strings.ToLower
}
