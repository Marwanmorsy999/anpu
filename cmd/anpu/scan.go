package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/anpu-project/anpu/internal/active"
	"github.com/anpu-project/anpu/internal/actuator"
	"github.com/anpu-project/anpu/internal/api"
	"github.com/anpu-project/anpu/internal/apiconsole"
	"github.com/anpu-project/anpu/internal/apiversion"
	"github.com/anpu-project/anpu/internal/archiveurls"
	"github.com/anpu-project/anpu/internal/auth"
	"github.com/anpu-project/anpu/internal/authz"
	"github.com/anpu-project/anpu/internal/axfrplus"
	"github.com/anpu-project/anpu/internal/backup"
	"github.com/anpu-project/anpu/internal/backupplus"
	"github.com/anpu-project/anpu/internal/bgp"
	"github.com/anpu-project/anpu/internal/brokenlink"
	"github.com/anpu-project/anpu/internal/bucket"
	"github.com/anpu-project/anpu/internal/cachedeception"
	"github.com/anpu-project/anpu/internal/certhistory"
	"github.com/anpu-project/anpu/internal/certsan"
	"github.com/anpu-project/anpu/internal/clickjack"
	"github.com/anpu-project/anpu/internal/codesecrets"
	"github.com/anpu-project/anpu/internal/commentminer"
	"github.com/anpu-project/anpu/internal/config"
	"github.com/anpu-project/anpu/internal/cookieprefix"
	"github.com/anpu-project/anpu/internal/cors"
	"github.com/anpu-project/anpu/internal/corsplus"
	"github.com/anpu-project/anpu/internal/csprecon"
	"github.com/anpu-project/anpu/internal/csrf"
	"github.com/anpu-project/anpu/internal/cswsh"
	"github.com/anpu-project/anpu/internal/cvepack"
	"github.com/anpu-project/anpu/internal/debugmethods"
	"github.com/anpu-project/anpu/internal/debugpages"
	"github.com/anpu-project/anpu/internal/deps"
	"github.com/anpu-project/anpu/internal/difforacle"
	"github.com/anpu-project/anpu/internal/dirs"
	"github.com/anpu-project/anpu/internal/dnsaudit"
	"github.com/anpu-project/anpu/internal/dnsintel"
	"github.com/anpu-project/anpu/internal/doh"
	"github.com/anpu-project/anpu/internal/emailauth"
	"github.com/anpu-project/anpu/internal/emailharv"
	"github.com/anpu-project/anpu/internal/encodepoly"
	"github.com/anpu-project/anpu/internal/endpoints"
	"github.com/anpu-project/anpu/internal/exposedconfig"
	"github.com/anpu-project/anpu/internal/exposedgit"
	"github.com/anpu-project/anpu/internal/favicon"
	"github.com/anpu-project/anpu/internal/faviconplus"
	"github.com/anpu-project/anpu/internal/feeds"
	"github.com/anpu-project/anpu/internal/findings"
	"github.com/anpu-project/anpu/internal/forbiddenbypass"
	"github.com/anpu-project/anpu/internal/gfclassify"
	"github.com/anpu-project/anpu/internal/graphqlfp"
	"github.com/anpu-project/anpu/internal/graphqlschema"
	"github.com/anpu-project/anpu/internal/h2fp"
	"github.com/anpu-project/anpu/internal/h2smuggle"
	"github.com/anpu-project/anpu/internal/headers"
	"github.com/anpu-project/anpu/internal/hiddenparams"
	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/integrations"
	"github.com/anpu-project/anpu/internal/ipintel"
	"github.com/anpu-project/anpu/internal/jsluice"
	"github.com/anpu-project/anpu/internal/jssecrets"
	"github.com/anpu-project/anpu/internal/jwtconfirm"
	"github.com/anpu-project/anpu/internal/jwtplus"
	"github.com/anpu-project/anpu/internal/leak"
	"github.com/anpu-project/anpu/internal/lfipack"
	"github.com/anpu-project/anpu/internal/methods"
	"github.com/anpu-project/anpu/internal/nosqlexpand"
	"github.com/anpu-project/anpu/internal/nsecwalk"
	"github.com/anpu-project/anpu/internal/oauth"
	"github.com/anpu-project/anpu/internal/oauthpack"
	"github.com/anpu-project/anpu/internal/oob"
	"github.com/anpu-project/anpu/internal/originip"
	"github.com/anpu-project/anpu/internal/params"
	"github.com/anpu-project/anpu/internal/policyheaders"
	"github.com/anpu-project/anpu/internal/portscan"
	"github.com/anpu-project/anpu/internal/postmessage"
	"github.com/anpu-project/anpu/internal/ppollute"
	"github.com/anpu-project/anpu/internal/rdap"
	"github.com/anpu-project/anpu/internal/recon"
	"github.com/anpu-project/anpu/internal/redirectpack"
	"github.com/anpu-project/anpu/internal/reporting"
	"github.com/anpu-project/anpu/internal/saml"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/internal/scope"
	"github.com/anpu-project/anpu/internal/scoring"
	"github.com/anpu-project/anpu/internal/secrets"
	"github.com/anpu-project/anpu/internal/soap"
	"github.com/anpu-project/anpu/internal/socialhijack"
	"github.com/anpu-project/anpu/internal/sri"
	"github.com/anpu-project/anpu/internal/sstiexpand"
	"github.com/anpu-project/anpu/internal/storage"
	"github.com/anpu-project/anpu/internal/subdomains"
	"github.com/anpu-project/anpu/internal/subpermute"
	"github.com/anpu-project/anpu/internal/swscope"
	"github.com/anpu-project/anpu/internal/takeover"
	"github.com/anpu-project/anpu/internal/takeoverplus"
	"github.com/anpu-project/anpu/internal/technology"
	"github.com/anpu-project/anpu/internal/timeoracle"
	"github.com/anpu-project/anpu/internal/tls"
	"github.com/anpu-project/anpu/internal/verbtamper"
	"github.com/anpu-project/anpu/internal/vhost"
	"github.com/anpu-project/anpu/internal/wafdetect"
	"github.com/anpu-project/anpu/pkg/models"
)

// oobInteractshEnabled mirrors the --oob-interactsh flag into runScan
// (whose long positional parameter list is frozen). Set by newScanCmd
// and newLevelCmd before delegating.
var oobInteractshEnabled bool
var adversarialEnabled bool
var adversarialConfirmed bool

// scopeFilePath carries --scope-file into runScan (frozen param list,
// same pattern as oob/adversarial globals). Empty = allow-all.
var scopeFilePath string

// autoInstallEnabled carries --auto-install into runScan, which flips
// integrations.AutoInstallEnabled so missing binaries self-provision
// mid-scan instead of warn-and-skip. Default false.
var autoInstallEnabled bool

// assumeYes carries --yes into runScan to skip install confirmations.
var assumeYes bool

// unsafeEnabled carries --unsafe into runScan: operator master override
// (implies adversarial+confirmed, lifts safe-purity filters, fuller
// wrapper strength). Defaults, warnings, and hard exclusions unchanged.
var unsafeEnabled bool

// parallelN carries --parallel (0/1 = legacy sequential).
var parallelN int

// checkpointPath/resumePath carry --checkpoint/--resume stage snapshots.
var checkpointPath, resumePath string

// riskAcceptPath carries --risk-accept (finding IDs to suppress with
// reason + optional expiry).
var riskAcceptPath string
var ghostEnabled bool
var ghostCanaryPrefix string
var ghostWorkers int
var proxyPoolPath string

func newScanCmd() *cobra.Command {
	var (
		profile               string
		jsonOut               bool
		htmlOut               bool
		sarifOut              bool
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
			oobInteractshEnabled = oobInteractsh
			integrations.CustomTagsOverride = nucleiTags
			integrations.ZapAjax = zapAjax
			adversarialEnabled = adversarial
			adversarialConfirmed = confirmAuthorized
			scopeFilePath = scopeFile
			autoInstallEnabled = autoInst
			assumeYes = yesFlag
			unsafeEnabled = unsafeFlag
			integrations.UnsafeEnabled = unsafeFlag
			parallelN = parallelFlag
			checkpointPath = checkpointFlag
			resumePath = resumeFlag
			riskAcceptPath = riskAcceptFlag
			if unsafeFlag {
				// Master override: operator takes charge. Implies
				// adversarial+confirmed (no separate confirmation),
				// lifts safe-purity filters, fuller wrapper strength.
				adversarialEnabled = true
				adversarialConfirmed = true
			}
			ghostEnabled = ghostFlag
			ghostCanaryPrefix = ghostCanaryPrefixFlag
			ghostWorkers = ghostWorkersFlag
			proxyPoolPath = proxyPoolFlag
			if adversarial && !confirmAuthorized && !unsafeFlag {
				return fmt.Errorf("--adversarial requires --confirm-authorized (authorized ultra/adversarial only; no data destruction, Benign/LowImpact only)")
			}
			if adversarialEnabled {
				active.AdversarialEnabled = true
				active.AdversarialConfirmed = adversarialConfirmed
			} else {
				active.AdversarialEnabled = false
				active.AdversarialConfirmed = false
			}
			// Wire ghost mode into active canaries and http transport
			if ghostEnabled {
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
			return runScan(cmd, targetArg, profile, jsonOut, htmlOut, sarifOut, outputDir, noNuclei, noZAP, noActive, noCSRF, noDeps, noTakeover, noSRI, noBackup, noKatana, noHttpx, noSubfinder, noDalfox, noDNSIntel, noIPIntel, noNaabu, noDNSx, noRDAP, noLeak, noFavicon, noDoH, noBucket, noBGP, noAPI, noAuthZ, oobHost, failOn, skipPreCheck,
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
	cmd.Flags().BoolVar(&jsonlOut, "jsonl", false, "stream findings as JSON lines to stdout for piping (implies --silent human output)")

	return cmd
}

func runScan(cmd *cobra.Command, targetArg, profileStr string, jsonOut, htmlOut, sarifOut bool, outputDir string, noNuclei, noZAP, noActive, noCSRF, noDeps, noTakeover, noSRI, noBackup, noKatana, noHttpx, noSubfinder, noDalfox, noDNSIntel, noIPIntel, noNaabu, noDNSx, noRDAP, noLeak, noFavicon, noDoH, noBucket, noBGP, noAPI, noAuthZ bool, oobHost, failOn string, skipPreCheck bool,
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
	// the package globals below were already populated from CLI flags by
	// the calling command's RunE, or left at defaults for level shortcuts).
	// scan.adversarial in YAML still requires --confirm-authorized on the CLI.
	if !adversarialEnabled && cfgFile.Scan.Adversarial != nil && *cfgFile.Scan.Adversarial {
		adversarialEnabled = true
	}
	// scan.unsafe in YAML acts like CLI --unsafe (master override).
	if !unsafeEnabled && cfgFile.Scan.Unsafe != nil && *cfgFile.Scan.Unsafe {
		unsafeEnabled = true
		integrations.UnsafeEnabled = true
		adversarialEnabled = true
		adversarialConfirmed = true
	}
	if !ghostEnabled && cfgFile.Scan.Ghost != nil && *cfgFile.Scan.Ghost {
		ghostEnabled = true
	}
	if ghostCanaryPrefix == "" && cfgFile.Scan.GhostCanaryPrefix != nil {
		ghostCanaryPrefix = *cfgFile.Scan.GhostCanaryPrefix
	}
	if (ghostWorkers == 0 || ghostWorkers == 4) && cfgFile.Scan.GhostWorkers != nil && *cfgFile.Scan.GhostWorkers >= 0 {
		ghostWorkers = *cfgFile.Scan.GhostWorkers
	}
	if ghostEnabled && ghostWorkers <= 0 {
		ghostWorkers = 4
	}
	if proxyPoolPath == "" && cfgFile.Scan.ProxyPool != nil {
		proxyPoolPath = *cfgFile.Scan.ProxyPool
	}
	if adversarialEnabled && !adversarialConfirmed {
		return fmt.Errorf("--adversarial requires --confirm-authorized (authorized ultra/adversarial only; no data destruction, Benign/LowImpact only)")
	}
	if adversarialEnabled {
		active.AdversarialEnabled = true
		active.AdversarialConfirmed = adversarialConfirmed
	} else {
		active.AdversarialEnabled = false
		active.AdversarialConfirmed = false
	}
	// Re-apply ghost canary wiring when values came from the config file
	// (the RunE block already handled CLI-provided values).
	if ghostEnabled {
		active.SetGhost(true, ghostCanaryPrefix)
		active.GhostEnabled = true
		anpuhttp.GhostEnabled = true
		anpuhttp.GhostCanaryPrefix = ghostCanaryPrefix
		anpuhttp.GhostWorkers = ghostWorkers
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
			fmt.Fprintf(os.Stderr, "anpu: --disable is ignored when --only is present (only %q will run)\n", strings.Join(onlyMods, ","))
		}
		if len(enableMods) > 0 {
			fmt.Fprintf(os.Stderr, "anpu: --enable is ignored when --only is present (only %q will run)\n", strings.Join(onlyMods, ","))
		}
		disableAllModules(&modules)
		applyModuleToggles(&modules, nil, onlyMods)
	} else {
		applyModuleToggles(&modules, disableMods, enableMods)
	}
	// Re-assert after toggles: disableAllModules zeroes the struct, which
	// would otherwise wipe an authorized --adversarial/--unsafe grant on
	// --only runs (adversarial tools would warn-skip despite consent).
	if adversarialEnabled && adversarialConfirmed {
		modules.Adversarial = true
	}
	// Explicit --openapi/--graphql with a disabled API module warns instead
	// of silently forcing the stage on (--only stays absolute).
	if (openAPISource != "" || graphQLURL != "") && !modules.API {
		fmt.Fprintf(os.Stderr, "anpu: --openapi/--graphql ignored (API module disabled; use --enable api or --only api)\n")
	}

	// Wire OOB host for Log4Shell JNDI probing (Phase 12I).
	// Set before the active scanner runs so the log4shellRule picks it up.
	active.Log4ShellOOBHost = oobHost

	// Automatic OOB confirmation via the public interactsh fleet.
	// Strictly opt-in: without the flag, InteractSession stays nil and
	// blind rules behave exactly as before (in-band signals only).
	if oobInteractshEnabled {
		sess, serr := oob.NewSession("")
		if serr != nil {
			fmt.Fprintf(os.Stderr, "anpu: interactsh unavailable, continuing without OOB confirmation: %v\n", serr)
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

	client := anpuhttp.NewClientWithLocalNetworkAllowed(scanner.AllowLocalNetwork)
	if ghostEnabled {
		client = client.WithGhost(true)
		if !silent {
			fmt.Printf("  ghost      : enabled (Chrome131 JA3, h2, GREASE, Pareto 800-3500ms, no-anpu canary")
			if ghostWorkers > 0 {
				fmt.Printf(", %d workers", ghostWorkers)
			}
			if proxyPoolPath != "" {
				fmt.Printf(", pool %s", proxyPoolPath)
			}
			fmt.Printf(")\n")
		}
	}
	if customUA != "" {
		client = client.WithCustomUA(customUA)
		if !silent {
			fmt.Printf("  user-agent : custom (%d chars)\n", len(customUA))
		}
	} else if stealth || randomAgent || ghostEnabled {
		client = client.WithRandomAgent(true)
		if stealth || ghostEnabled {
			if !ghostEnabled {
				client = client.WithStealth(true)
			}
		}
		if !silent {
			mode := "random-agent"
			if stealth {
				mode = "stealth (random UA + jitter)"
			}
			if ghostEnabled {
				mode = "ghost (Chrome131 JA3, Pareto jitter, header-order, 40 UA pool)"
			}
			fmt.Printf("  anonymity  : %s\n", mode)
		}
	}
	if proxyPoolPath != "" {
		var err error
		client, err = client.WithProxyPool(proxyPoolPath)
		if err != nil {
			return err
		}
		if !silent {
			fmt.Printf("  proxy-pool : %s\n", proxyPoolPath)
		}
	} else if proxyURL != "" {
		var err error
		client, err = client.WithProxy(proxyURL)
		if err != nil {
			return err
		}
		if !silent {
			fmt.Printf("  proxy      : %s\n", proxyURL)
		}
	}
	if rateLimit > 0 || requestDelay > 0 {
		limiter := anpuhttp.NewRateLimiter(rateLimit, requestDelay)
		client = client.WithRateLimiter(limiter)
	} else if ghostEnabled {
		// Ghost without explicit rate-limit still adapts: Pareto jitter 800-3500ms
		// plus header/JA3 rotation; the RateLimiter fixed bucket remains when ghost off.
		limiter := anpuhttp.NewRateLimiter(2, 0) // adaptive 2 rps default for ghost ultra
		client = client.WithRateLimiter(limiter)
		if !silent {
			fmt.Printf("  rate       : ghost adaptive 2 rps + Pareto jitter\n")
		}
	}
	// Stealth without explicit rate limit relies on per-request maybeJitter; no limiter needed.
	apiCfg := api.Config{
		OpenAPISource: openAPISource,
		GraphQLURL:    graphQLURL,
		BaseURL:       apiBaseURL,
	}
	pipeline := buildPipeline(client, modules, authzCtx, apiCfg, profile, unsafeEnabled)
	pipeline.MaxParallel = parallelN
	pipeline.CheckpointFile = checkpointPath
	pipeline.ResumeFile = resumePath

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
	if !autoInstallEnabled && cfgFile.Scan.AutoInstall != nil && *cfgFile.Scan.AutoInstall {
		autoInstallEnabled = true
	}
	integrations.AutoInstallEnabled = autoInstallEnabled
	if autoInstallEnabled {
		// Alert before anything is fetched: list the missing tools
		// this scan may install, then confirm once. --stdin targets
		// come from the same stream, so never prompt there.
		missing := missingBinaries(modules)
		if !silent || len(missing) > 0 {
			fmt.Fprintf(os.Stderr, "anpu: --auto-install may download+build %d missing tool(s): %s\n",
				len(missing), strings.Join(missing, ", "))
		}
		proceed := assumeYes || stdinFlag || listFile != ""
		if !proceed {
			proceed = askConfirm(os.Stdin, os.Stderr, false, stdinInteractive(), false,
				fmt.Sprintf("Proceed (installs up to %d tools as their stages run)?", len(missing)))
		} else if !silent {
			fmt.Fprintln(os.Stderr, "anpu: auto-install confirmed (--yes / non-interactive / file input)")
		}
		if !proceed {
			fmt.Fprintln(os.Stderr, "anpu: auto-install declined — continuing with embedded coverage only")
			autoInstallEnabled = false
			integrations.AutoInstallEnabled = false
		} else if !silent {
			fmt.Println("  auto-install : enabled (missing tools self-provision: go/pipx/docker, apt/choco best-effort)")
		}
	}
	// Scope hard stop: resolved once, enforced before any packet.
	allowlist, err := scope.LoadFile(scopeFilePath)
	if err != nil {
		return err
	}
	for i, rawTarget := range targets {
		target, err := scanner.ValidateTarget(rawTarget)
		if err != nil {
			if !batch {
				return fmt.Errorf("target validation failed: %w", err)
			}
			fmt.Fprintf(os.Stderr, "anpu: skipping target %q: %v\n", rawTarget, err)
			scanErrors++
			continue
		}
		if err := scope.Enforce(allowlist, scopeFilePath, target.Host, target.Port); err != nil {
			if !batch {
				return err
			}
			fmt.Fprintf(os.Stderr, "anpu: %v\n", err)
			scanErrors++
			continue
		}
		if batch && !silent {
			fmt.Printf("\n=== [%d/%d] %s ===\n", i+1, len(targets), target.Raw)
		}
		cfg := models.ScanConfig{
			Target:        target.Raw,
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
			fmt.Fprintf(os.Stderr, "anpu: scan failed for %s: %v\n", target.Raw, err)
			scanErrors++
			continue
		}

		// Risk acceptance: suppress listed finding IDs (with reason and
		// optional expiry) before reports and history are written, so
		// accepted risks stop re-alerting (including in drift).
		if riskAcceptPath != "" {
			entries, rerr := findings.LoadRiskAccept(riskAcceptPath)
			if rerr != nil {
				fmt.Fprintf(os.Stderr, "anpu: %v\n", rerr)
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

		if htmlOut {
			p := filepath.Join(outputDir, fmt.Sprintf("%s-%s.html", slug, dateStr))
			if err := reporting.WriteHTML(summary, p); err != nil {
				if !batch {
					return err
				}
				fmt.Fprintf(os.Stderr, "anpu: writing HTML for %s: %v\n", target.Raw, err)
				scanErrors++
				continue
			}
			reportPath = p
		}
		if jsonOut {
			p := filepath.Join(outputDir, fmt.Sprintf("%s-%s.json", slug, dateStr))
			if err := reporting.WriteJSON(summary, p); err != nil {
				if !batch {
					return err
				}
				fmt.Fprintf(os.Stderr, "anpu: writing JSON for %s: %v\n", target.Raw, err)
				scanErrors++
				continue
			}
			if reportPath == "" {
				reportPath = p
			}
		}
		if sarifOut {
			p := filepath.Join(outputDir, fmt.Sprintf("%s-%s.sarif", slug, dateStr))
			if err := reporting.WriteSARIF(summary, p); err != nil {
				if !batch {
					return err
				}
				fmt.Fprintf(os.Stderr, "anpu: writing SARIF for %s: %v\n", target.Raw, err)
				scanErrors++
				continue
			}
			if reportPath == "" {
				reportPath = p
			}
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

// collectTargets resolves the effective target list from (in priority
// order): --stdin, --list, the positional arg, then target.url in config.
// Lines starting with # and blank lines are ignored. Targets require an
// explicit http(s):// scheme, except config-file targets which default
// to https://.
func collectTargets(cmd *cobra.Command, targetArg string, stdinFlag bool, listFile string, cfgFile *config.File) ([]string, error) {
	switch {
	case stdinFlag && listFile != "":
		return nil, fmt.Errorf("use only one of --stdin or --list")
	case stdinFlag:
		if targetArg != "" {
			return nil, fmt.Errorf("pass targets via stdin or as an argument, not both")
		}
		lines, err := readTargetLines(cmd.InOrStdin())
		if err != nil {
			return nil, err
		}
		if len(lines) == 0 {
			return nil, fmt.Errorf("no targets received on stdin: pipe one URL per line")
		}
		return lines, nil
	case listFile != "":
		if targetArg != "" {
			return nil, fmt.Errorf("pass targets via --list or as an argument, not both")
		}
		f, err := os.Open(listFile) // #nosec G304 -- CLI reads operator-specified paths (reports, wordlists, checkpoints, code dir).
		if err != nil {
			return nil, fmt.Errorf("reading target list %q: %w", listFile, err)
		}
		defer f.Close()
		lines, err := readTargetLines(f)
		if err != nil {
			return nil, err
		}
		if len(lines) == 0 {
			return nil, fmt.Errorf("no targets found in %q", listFile)
		}
		return lines, nil
	default:
		if targetArg == "" {
			if cfgFile.Target.URL == "" {
				return nil, fmt.Errorf("no target specified: pass a URL, use --stdin/--list, or set target.url in anpu.yaml")
			}
			targetArg = cfgFile.Target.URL
			if !strings.HasPrefix(targetArg, "http://") && !strings.HasPrefix(targetArg, "https://") {
				targetArg = "https://" + targetArg // default to https for config targets
			}
		}
		return []string{targetArg}, nil
	}
}

// buildPipeline wires up every scan stage in pipeline order. This is the
// single place that knows about concrete scanner implementations — the
// orchestrator (internal/scanner) and every analyzer package only know
// about the Scanner interface, so adding a new stage means adding one
// entry here.
func buildPipeline(client *anpuhttp.Client, modules models.ModuleConfig, authzCtx models.AuthContext, apiCfg api.Config, profile models.Profile, unsafe bool) *scanner.Pipeline {
	nuclei := integrations.NewNucleiScanner()
	zap := integrations.NewZapScanner()
	mobsfScanner := integrations.NewMobSFScanner()
	katana := integrations.NewKatanaScanner()
	httpx := integrations.NewHttpxScanner()
	subfinder := integrations.NewSubfinderScanner()
	dalfox := integrations.NewDalfoxScanner()
	naabu := integrations.NewNaabuScanner()
	dnsx := integrations.NewDNSxScanner()

	// AuthZ testing runs after Endpoints so it has a full attack surface
	// to probe. With two identities it compares them; fully anonymous
	// scans fall back to forced-browsing of sensitive endpoints.
	authzScanner := authz.New(client, authzCtx)

	pipe := &scanner.Pipeline{
		Client: client,
		Stages: []scanner.Stage{
			{Label: "Recon", Enabled: modules.Recon, Scanner: recon.New(client)},
			{Label: "DNSIntel", Enabled: modules.DNSIntel, Scanner: dnsintel.New()},
			{Label: "IPIntel", Enabled: modules.IPIntel, Scanner: ipintel.NewWithClient(client)},
			{Label: "RDAP", Enabled: modules.RDAP, Scanner: rdap.New(client)},
			{Label: "Leak", Enabled: modules.Leak, Scanner: leak.New(client)},
			{Label: "Favicon", Enabled: modules.Favicon, Scanner: favicon.New(client)},
			{Label: "DoH", Enabled: modules.DoH, Scanner: doh.New(client)},
			{Label: "Bucket", Enabled: modules.Bucket, Scanner: bucket.New(client)},
			{Label: "BGP", Enabled: modules.BGP, Scanner: bgp.New(client)},
			// Wave 1 batch 1 — passive recon engines (safe for all profiles,
			// each bounded: 0-3 target requests, DNS-only where noted).
			{Label: "ArchiveURLs", Enabled: modules.ArchiveURLs, Scanner: archiveurls.New(client)},
			{Label: "CertSAN", Enabled: modules.CertSAN, Scanner: certsan.New()},
			{Label: "EmailHarv", Enabled: modules.EmailHarv, Scanner: emailharv.New(client)},
			{Label: "DNSAudit", Enabled: modules.DNSAudit, Scanner: dnsaudit.New()},
			{Label: "EmailAuth", Enabled: modules.EmailAuth, Scanner: emailauth.New(client)},
			{Label: "CSPRecon", Enabled: modules.CSPRecon, Scanner: csprecon.New(client)},
			{Label: "SocialHijack", Enabled: modules.SocialHijack, Scanner: socialhijack.New(client)},
			{Label: "CommentMiner", Enabled: modules.CommentMiner, Scanner: commentminer.New(client)},
			{Label: "BrokenLink", Enabled: modules.BrokenLink, Scanner: brokenlink.New(client)},
			{Label: "OriginIP", Enabled: modules.OriginIP, Scanner: originip.New(client)},
			{Label: "Technology", Enabled: modules.Technology, Scanner: technology.New(client)},
			// Httpx corroborates built-in fingerprinting when installed.
			{Label: "Httpx", Enabled: modules.Httpx, Scanner: httpx, SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "Codesecrets", Enabled: modules.Codesecrets, Scanner: codesecrets.New()},
			{Label: "TLS", Enabled: modules.TLS, Scanner: tls.New(client)},
			{Label: "Headers", Enabled: modules.Headers, Scanner: headers.New(client)},
			{Label: "Cookies", Enabled: modules.Cookies, Scanner: headers.NewCookieAnalyzer(client)},
			{Label: "Endpoints", Enabled: modules.Endpoints, Scanner: endpoints.New(client)},
			// Deps runs after Technology AND Endpoints so sc.Technologies is
			// already populated and crawler-discovered manifests are visible
			// for harvest (previously it ran before Endpoints and the
			// manifest path could never trigger).
			{Label: "Deps", Enabled: modules.Deps, Scanner: deps.NewWithClient(client), SkipReason: "safe profile is passive — use --profile standard"},
			// Katana crawls what the built-in crawler misses (JS-heavy
			// routes); its endpoints feed every later stage.
			{Label: "Katana", Enabled: modules.Katana, Scanner: katana, SkipReason: "safe profile is passive — use --profile standard"},
			// API scanner (Phase 5) runs immediately after endpoint discovery
			// so that schema-derived endpoints are in ScanContext.Endpoints
			// before the AuthZ and Active stages consume them. With no
			// --openapi/--graphql flags it auto-discovers well-known
			// schema locations (GET-only). --only stays absolute: explicit
			// flags never force the stage on (they warn instead, above).
			{Label: "API", Enabled: modules.API, Scanner: api.New(apiCfg)},
			{Label: "Subdomains", Enabled: modules.Subdomains, Scanner: subdomains.New(), SkipReason: "safe profile is passive — use --profile standard"},
			// Subfinder merges passive subdomains into sc.Subdomains for Takeover.
			{Label: "Subfinder", Enabled: modules.Subfinder, Scanner: subfinder, SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "DNSx", Enabled: modules.DNSx, Scanner: dnsx, SkipReason: "safe profile is passive — use --profile standard"},
			// Takeover runs after Subdomains so sc.Subdomains is populated.
			{Label: "Takeover", Enabled: modules.Takeover, Scanner: takeover.New(), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "PortScan", Enabled: modules.PortScan, Scanner: portscan.New(), SkipReason: "deep profile only (--profile deep)"},
			{Label: "Naabu", Enabled: modules.Naabu, Scanner: naabu, SkipReason: "deep profile only (--profile deep)"},
			{Label: "Dirs", Enabled: modules.Dirs, Scanner: dirs.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			// Secrets consumes the endpoints discovered above, so it must
			// stay after the Endpoints stage.
			{Label: "Secrets", Enabled: modules.Secrets, Scanner: secrets.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			// Params classifies query params on all discovered endpoints
			// (including JS routes from Secrets). Passive — independently
			// toggleable via --disable/--enable params (default on).
			{Label: "Params", Enabled: modules.Params, Scanner: params.New(), SkipReason: "disabled via --disable params"},
			{Label: "CORS", Enabled: modules.CORS, Scanner: cors.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "Methods", Enabled: modules.Methods, Scanner: methods.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			// CSRF runs after Endpoints so form action URLs are known.
			{Label: "CSRF", Enabled: modules.CSRF, Scanner: csrf.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			// SRI runs after Endpoints/Crawler so page URLs are populated.
			{Label: "SRI", Enabled: modules.SRI, Scanner: sri.New(client)},
			// Backup probes per-endpoint backup suffixes + root archives.
			// Enabled on Standard and Deep; skipped on Safe profile.
			{Label: "Backup", Enabled: modules.Backup, Scanner: backup.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			// Wave 1 batch 2 — bounded exposure probes (advanced/ultra; safe
			// stays passive). Self-sufficient (homepage + well-known paths);
			// CSWSH/HiddenParams also consume discovered endpoints, and
			// HiddenParams/OAuth/SAML endpoints feed AuthZ/IDOR/Active below.
			{Label: "ExposedGit", Enabled: modules.ExposedGit, Scanner: exposedgit.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "ExposedConfig", Enabled: modules.ExposedConfig, Scanner: exposedconfig.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "Actuator", Enabled: modules.Actuator, Scanner: actuator.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "DebugPages", Enabled: modules.DebugPages, Scanner: debugpages.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "OAuthAnalyzer", Enabled: modules.OAuthAnalyzer, Scanner: oauth.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "SAMLMetadata", Enabled: modules.SAMLMetadata, Scanner: saml.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "CSWSH", Enabled: modules.CSWSH, Scanner: cswsh.New(), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "PostMessage", Enabled: modules.PostMessage, Scanner: postmessage.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "JSSecrets", Enabled: modules.JSSecrets, Scanner: jssecrets.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "Jsluice", Enabled: modules.Jsluice, Scanner: jsluice.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "HiddenParams", Enabled: modules.HiddenParams, Scanner: hiddenparams.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			// Wave 1 batch 3 — items 21-30. Clickjack/PolicyHeaders/CookiePrefix
			// are passive header analysis (safe for all, no SkipReason);
			// TakeoverPlus runs after Takeover while subdomains are hot; the
			// rest are bounded active probes whose endpoints feed AuthZ/Active.
			{Label: "VerbTamper", Enabled: modules.VerbTamper, Scanner: verbtamper.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "CacheDeception", Enabled: modules.CacheDeception, Scanner: cachedeception.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "ForbiddenBypass", Enabled: modules.ForbiddenBypass, Scanner: forbiddenbypass.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "TakeoverPlus", Enabled: modules.TakeoverPlus, Scanner: takeoverplus.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "Clickjack", Enabled: modules.Clickjack, Scanner: clickjack.New(client)},
			{Label: "PolicyHeaders", Enabled: modules.PolicyHeaders, Scanner: policyheaders.New(client)},
			{Label: "CookiePrefix", Enabled: modules.CookiePrefix, Scanner: cookieprefix.New(client)},
			{Label: "APIVersion", Enabled: modules.APIVersion, Scanner: apiversion.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "APIConsole", Enabled: modules.APIConsole, Scanner: apiconsole.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "VHost", Enabled: modules.VHost, Scanner: vhost.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			// Wave 1 batches 4-5 — items 31-50. JWTPlus/H2FP/GFClassify/
			// CertHistory/SubPermute are passive/archive analysis (safe for
			// all, no SkipReason); H2Smuggle additionally requires
			// --adversarial --confirm-authorized at runtime; the rest are
			// bounded active probes whose endpoints feed AuthZ/Active.
			{Label: "GraphQLFP", Enabled: modules.GraphQLFP, Scanner: graphqlfp.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "GraphQLSchema", Enabled: modules.GraphQLSchema, Scanner: graphqlschema.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "JWTPlus", Enabled: modules.JWTPlus, Scanner: jwtplus.New(client)},
			{Label: "SSTIExpand", Enabled: modules.SSTIExpand, Scanner: sstiexpand.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "NoSQLExpand", Enabled: modules.NoSQLExpand, Scanner: nosqlexpand.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "H2Smuggle", Enabled: modules.H2Smuggle, Scanner: h2smuggle.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "H2FP", Enabled: modules.H2FP, Scanner: h2fp.New(client)},
			{Label: "RedirectPack", Enabled: modules.RedirectPack, Scanner: redirectpack.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "LFIPack", Enabled: modules.LFIPack, Scanner: lfipack.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "CVEPack", Enabled: modules.CVEPack, Scanner: cvepack.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "CORSPlus", Enabled: modules.CORSPlus, Scanner: corsplus.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "CertHistory", Enabled: modules.CertHistory, Scanner: certhistory.New(client)},
			{Label: "AXFRPlus", Enabled: modules.AXFRPlus, Scanner: axfrplus.New(), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "SubPermute", Enabled: modules.SubPermute, Scanner: subpermute.New()},
			{Label: "BackupPlus", Enabled: modules.BackupPlus, Scanner: backupplus.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "FaviconPlus", Enabled: modules.FaviconPlus, Scanner: faviconplus.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "DebugMethods", Enabled: modules.DebugMethods, Scanner: debugmethods.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "EncodePoly", Enabled: modules.EncodePoly, Scanner: encodepoly.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "DiffOracle", Enabled: modules.DiffOracle, Scanner: difforacle.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "GFClassify", Enabled: modules.GFClassify, Scanner: gfclassify.New()},
			// Next-wave natives — bounded active probes (advanced/ultra).
			{Label: "Soap", Enabled: modules.Soap, Scanner: soap.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "Nsecwalk", Enabled: modules.Nsecwalk, Scanner: nsecwalk.New(), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "Wafdetect", Enabled: modules.Wafdetect, Scanner: wafdetect.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "Oauthpack", Enabled: modules.Oauthpack, Scanner: oauthpack.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "Ppollute", Enabled: modules.Ppollute, Scanner: ppollute.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "Swscope", Enabled: modules.Swscope, Scanner: swscope.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "Timeoracle", Enabled: modules.Timeoracle, Scanner: timeoracle.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "Jwtconfirm", Enabled: modules.Jwtconfirm, Scanner: jwtconfirm.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			// AuthZ runs after Endpoints/Dirs so both contexts probe the
			// full discovered attack surface.
			{Label: "AuthZ", Enabled: modules.AuthZ, Scanner: authzScanner},
			// IDOR/BOLA (Master P1): numeric id|user_id|order_id id+1 replay under contextB low-priv
			// (authz/scanner.go:40 same-URL diff today; coordination via
			// Session.Vault/ArtifactPool in interface.go).
			// Runs immediately after AuthZ while endpoints are still hot.
			// Enabled on advanced/ultra by default (read-only GETs, like Active);
			// off on safe to keep safe passive. Toggle via --enable/--disable idor.
			{Label: "IDOR", Enabled: modules.IDOR, Scanner: authz.NewIDOR(client), SkipReason: "safe profile is passive — use --profile standard"},
			// Active runs last among ANPU built-ins so it benefits from
			// the complete endpoint list and technology fingerprints.
			{Label: "Active", Enabled: modules.Active, Scanner: active.New(client), SkipReason: "safe profile is passive — use --profile standard"},
			// Dalfox confirms XSS on discovered parameterized URLs.
			{Label: "Dalfox", Enabled: modules.Dalfox, Scanner: dalfox, SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "Nuclei", Enabled: modules.Nuclei, Scanner: nuclei, SkipReason: "safe profile is passive — use --profile standard"},
			{Label: "ZAP", Enabled: modules.ZAP, Scanner: zap, SkipReason: "deep profile only (--profile deep)"},
			// MobSF static analysis (mobile scope): runs only with ANPU_APK
			// + operator server configured; dynamic analysis never runs.
			{Label: "Mobsf", Enabled: modules.Mobsf, Scanner: mobsfScanner, SkipReason: "ultra only + ANPU_APK (static only, dynamic never)"},
		},
	}
	// Concurrent stages (Phase D): snapshot-safe natives (verified by
	// grep to never read accumulated Endpoints/Technologies/Subdomains)
	// run in parallel groups when --parallel > 1; everything else is a
	// barrier. Output merging stays in stage order (deterministic).
	for i := range pipe.Stages {
		if concurrentStages[pipe.Stages[i].Label] {
			pipe.Stages[i].Concurrent = true
		}
		if ph, ok := nativePhase(pipe.Stages[i].Label); ok {
			pipe.Stages[i].Phase = ph
		} else {
			pipe.Stages[i].Phase = scanner.PhaseTargeted
		}
	}
	// Wave 2 — free-binary wrappers (items 51-134): each stage runs the
	for _, spec := range integrations.StagedSpecs() {
		skip := "advanced profile or higher (binary or embedded)"
		if spec.Level == integrations.LevelUltra {
			skip = "ultra profile only (--profile ultra)"
		}
		if spec.Adversarial {
			skip += "; requires --adversarial --confirm-authorized"
		}
		st := wrapperStageFor(spec, modules, client, skip, profile, unsafe)
		st.Phase = wrapperPhase(spec)
		pipe.Stages = append(pipe.Stages, st)
	}
	return pipe
}

// nativePhase assigns every built-in stage to a pipeline phase.
// Foundation = passive intel needing nothing; Discovery = crawlers and
// enumerators producing endpoints/hosts; Targeted = consumers probing
// discovered surface; Active = differentials, confirmations, and
// timing-sensitive work. Unlisted labels default to Targeted.
func nativePhase(label string) (scanner.Phase, bool) {
	switch label {
	case "Recon", "DNSIntel", "IPIntel", "RDAP", "Leak", "Favicon", "DoH",
		"Bucket", "BGP", "ArchiveURLs", "CertSAN", "EmailHarv", "DNSAudit",
		"EmailAuth", "CSPRecon", "SocialHijack", "CommentMiner", "BrokenLink",
		"OriginIP", "Technology", "TLS", "Headers", "Cookies", "Clickjack",
		"PolicyHeaders", "CookiePrefix", "JWTPlus", "H2FP", "GFClassify",
		"CertHistory", "SubPermute", "Httpx", "Codesecrets":
		return scanner.PhaseFoundation, true
	case "Endpoints", "Katana", "API", "Subdomains", "Subfinder", "DNSx",
		"Takeover", "PortScan", "Naabu", "Dirs", "Params":
		return scanner.PhaseDiscovery, true
	case "H2Smuggle", "Timeoracle", "Active", "Dalfox":
		return scanner.PhaseActive, true
	}
	return scanner.PhaseTargeted, false
}

// wrapperPhase assigns external-tool stages to phases by input needs:
// host-only probers run in Foundation, crawlers and enumerators in
// Discovery, parameterized/adversarial confirmators in Active, and
// everything else in Targeted.
func wrapperPhase(spec *integrations.ToolSpec) scanner.Phase {
	switch spec.Name {
	case "tlsx", "cdncheck", "asnmap", "webanalyze", "csprecon", "hakoriginfinder",
		"gau", "waybackurls", "assetfinder", "findomain", "dnsgen", "alterx",
		"gotator", "dnsrecon", "metabigor", "puredns", "shuffledns", "massdns":
		return scanner.PhaseFoundation
	case "amass", "hakrawler", "gospider", "cariddi", "unfurl", "uro",
		"qsreplace", "anew", "arjun", "paramspider", "x8", "kiterunner",
		"subjs", "linkfinder":
		return scanner.PhaseDiscovery
	case "sqlmap", "ghauri", "commix", "tplmap", "sstimap", "ssrfmap",
		"nosqlmap", "smuggler", "dotdotpwn", "git-dumper", "gitjacker",
		"xsstrike", "kxss", "gxss", "crlfuzz":
		return scanner.PhaseActive
	}
	return scanner.PhaseTargeted
}

// binaryPresent reports whether a tool binary resolves. Variable (not
// direct call) so tests stub it deterministically.
var binaryPresent = func(binary string) bool {
	_, ok := integrations.LookupBinary(binary)
	return ok
}

// wrapperStageFor decides one wrapper stage: profile-off stays off;
// fully natively covered + binary absent stays off (no double probes)
// unless auto-install may provision the binary; otherwise the stage
// runs the binary when present, or only its not-yet-covered embedded
// fallbacks.
// safePureFallbacks are native labels allowed as embedded fallbacks on
// the safe profile: DNS/archive/offline analysis plus plain page GETs
// only — no probes, no POSTs, no payloads.
var safePureFallbacks = map[string]bool{
	"recon": true, "dnsintel": true, "ipintel": true, "technology": true,
	"tls": true, "headers": true, "cookies": true, "endpoints": true,
	"params": true, "sri": true, "api": true, "authz": true,
	"archiveurls": true, "certsan": true, "emailharv": true,
	"dnsaudit": true, "emailauth": true, "csprecon": true,
	"socialhijack": true, "commentminer": true, "brokenlink": true,
	"originip": true, "clickjack": true, "policyheaders": true,
	"cookieprefix": true, "jwtplus": true, "h2fp": true,
	"gfclassify": true, "certhistory": true, "subpermute": true,
	"bgp": true, "leak": true, "favicon": true, "doh": true, "bucket": true,
}

func wrapperStageFor(spec *integrations.ToolSpec, modules models.ModuleConfig, client *anpuhttp.Client, skip string, profile models.Profile, unsafe bool) scanner.Stage {
	g := integrations.NewGeneric(spec)
	on, _ := models.GetModuleByName(modules, spec.ToggleName())
	if !on {
		return scanner.Stage{Label: spec.LabelName(), Enabled: false, Scanner: g, SkipReason: skip}
	}
	var fallbacks []scanner.Scanner
	covered := true
	for _, label := range integrations.EmbeddedFallbacks(spec.Name) {
		// Safe stays passive unless --unsafe: active fallbacks never run
		// implicitly. (An explicitly installed binary still runs —
		// operator choice.)
		if profile == models.ProfileSafe && !unsafe && !safePureFallbacks[label] {
			covered = false
			continue
		}
		native, enabled := nativeStage(label, client, &modules)
		if native == nil {
			continue
		}
		if !enabled {
			covered = false
			fallbacks = append(fallbacks, native)
		}
	}
	binPresent := binaryPresent(spec.Binary)
	// Fully natively covered + binary absent: skip the duplicate
	// work — unless auto-install may still provision the binary.
	if !binPresent && covered && len(integrations.EmbeddedFallbacks(spec.Name)) > 0 && !integrations.AutoInstallEnabled {
		return scanner.Stage{
			Label: spec.LabelName(), Enabled: false, Scanner: g,
			SkipReason: "covered by native engines — install " + spec.Binary + " for full depth",
		}
	}
	g.Fallbacks = fallbacks
	// Safe with nothing safe to embed and no binary: stay off rather
	// than warn — safe promises passivity. (Explicitly installed
	// binaries and --auto-install still run.)
	if profile == models.ProfileSafe && len(fallbacks) == 0 && !binPresent && !integrations.AutoInstallEnabled {
		return scanner.Stage{
			Label: spec.LabelName(), Enabled: false, Scanner: g,
			SkipReason: "safe profile is passive — install " + spec.Binary + " for this tool",
		}
	}
	// Wrappers only read finalized discovery slices (endpoints/tech/
	// subdomains are complete before the first wrapper runs) and write
	// to unique temp files, so contiguous wrapper runs join parallel
	// groups. Two classes stay sequential: smuggler (CL.TE/TE.CL time
	// differentials are timing-sensitive) and the external crawlers
	// (gospider/hakrawler/cariddi/subjs hammer the target without the
	// native client's pacing — parallel crawls get WAF-throttled into
	// empty results, observed 40→0 on a Vercel front).
	concurrent := spec.Name != "smuggler" && spec.Name != "gospider" && spec.Name != "hakrawler" && spec.Name != "cariddi" && spec.Name != "subjs"
	return scanner.Stage{Label: spec.LabelName(), Enabled: true, Scanner: g, SkipReason: skip, Concurrent: concurrent}
}

// concurrentStages lists native stages verified snapshot-safe for
// parallel groups: they fetch/analyze independently and never read the
// accumulated Endpoints/Technologies/Subdomains slices (audit via grep
// for sc.Endpoints|sc.Technologies|sc.Subdomains in scanner.go files).
// Consumers (active, authz, takeover, takeoverplus, subpermute,
// hiddenparams, graphqlschema, apiversion, backup/plus, secrets,
// cors/plus, sri, csrf, dirs-adjacent probers, all wrappers, …) stay
// sequential barriers. Timing-sensitive rules (h2smuggle, timeoracle)
// stay sequential deliberately.
var concurrentStages = map[string]bool{
	"Recon": true, "DNSIntel": true, "IPIntel": true, "RDAP": true,
	"Leak": true, "Favicon": true, "DoH": true, "Bucket": true, "BGP": true,
	"ArchiveURLs": true, "CertSAN": true, "EmailHarv": true, "DNSAudit": true,
	"EmailAuth": true, "CSPRecon": true, "SocialHijack": true,
	"CommentMiner": true, "BrokenLink": true, "OriginIP": true,
	"Technology": true, "Httpx": true, "TLS": true, "Headers": true,
	"Cookies": true, "Endpoints": true, "Katana": true, "API": true,
	"Subdomains": true, "Subfinder": true, "DNSx": true, "PortScan": true,
	"Naabu": true, "Dirs": true, "Methods": true, "CORS": true,
	"OAuthAnalyzer": true, "SAMLMetadata": true, "PostMessage": true,
	"JSSecrets": true, "Jsluice": true, "DebugMethods": true, "DebugPages": true,
	"Actuator": true, "ExposedGit": true, "ExposedConfig": true,
	"GraphQLFP": true, "APIConsole": true, "VHost": true,
	"Soap": true, "Nsecwalk": true, "Wafdetect": true,
	"Ppollute": true, "Swscope": true, "Codesecrets": true,
	"JWTPlus": true, "H2FP": true, "GFClassify": true, "CertHistory": true,
	"PolicyHeaders": true,
	"ZAP":           true, "Mobsf": true,
	// Audited integrations: nuclei reads only the target raw URL;
	// dalfox reads the finalized endpoint list. Both join parallel
	// groups like the wrappers.
	"Nuclei": true, "Dalfox": true,
}

// nativeStage maps a native module label to a fresh scanner plus whether
// it is enabled in this scan. Unknown labels return (nil, false).
func nativeStage(label string, client *anpuhttp.Client, mc *models.ModuleConfig) (scanner.Scanner, bool) {
	switch label {
	case "recon":
		return recon.New(client), mc.Recon
	case "dnsintel":
		return dnsintel.New(), mc.DNSIntel
	case "ipintel":
		return ipintel.NewWithClient(client), mc.IPIntel
	case "technology":
		return technology.New(client), mc.Technology
	case "tls":
		return tls.New(client), mc.TLS
	case "headers":
		return headers.New(client), mc.Headers
	case "endpoints":
		return endpoints.New(client), mc.Endpoints
	case "subdomains":
		return subdomains.New(), mc.Subdomains
	case "takeover":
		return takeover.New(), mc.Takeover
	case "takeoverplus":
		return takeoverplus.New(client), mc.TakeoverPlus
	case "dirs":
		return dirs.New(client), mc.Dirs
	case "secrets":
		return secrets.New(client), mc.Secrets
	case "params":
		return params.New(), mc.Params
	case "cors":
		return cors.New(client), mc.CORS
	case "corsplus":
		return corsplus.New(client), mc.CORSPlus
	case "backup":
		return backup.New(client), mc.Backup
	case "backupplus":
		return backupplus.New(client), mc.BackupPlus
	case "deps":
		return deps.NewWithClient(client), mc.Deps
	case "active":
		return active.New(client), mc.Active
	case "bgp":
		return bgp.New(client), mc.BGP
	case "archiveurls":
		return archiveurls.New(client), mc.ArchiveURLs
	case "certsan":
		return certsan.New(), mc.CertSAN
	case "csprecon":
		return csprecon.New(client), mc.CSPRecon
	case "dnsaudit":
		return dnsaudit.New(), mc.DNSAudit
	case "originip":
		return originip.New(client), mc.OriginIP
	case "actuator":
		return actuator.New(client), mc.Actuator
	case "exposedconfig":
		return exposedconfig.New(client), mc.ExposedConfig
	case "debugpages":
		return debugpages.New(client), mc.DebugPages
	case "graphqlfp":
		return graphqlfp.New(client), mc.GraphQLFP
	case "graphqlschema":
		return graphqlschema.New(client), mc.GraphQLSchema
	case "jwtplus":
		return jwtplus.New(client), mc.JWTPlus
	case "forbiddenbypass":
		return forbiddenbypass.New(client), mc.ForbiddenBypass
	case "redirectpack":
		return redirectpack.New(client), mc.RedirectPack
	case "h2smuggle":
		return h2smuggle.New(client), mc.H2Smuggle
	case "lfipack":
		return lfipack.New(client), mc.LFIPack
	case "cvepack":
		return cvepack.New(client), mc.CVEPack
	case "postmessage":
		return postmessage.New(client), mc.PostMessage
	case "exposedgit":
		return exposedgit.New(client), mc.ExposedGit
	case "portscan":
		return portscan.New(), mc.PortScan
	case "subpermute":
		return subpermute.New(), mc.SubPermute
	case "sstiexpand":
		return sstiexpand.New(client), mc.SSTIExpand
	case "nosqlexpand":
		return nosqlexpand.New(client), mc.NoSQLExpand
	case "jssecrets":
		return jssecrets.New(client), mc.JSSecrets
	case "jsluice":
		return jsluice.New(client), mc.Jsluice
	case "hiddenparams":
		return hiddenparams.New(client), mc.HiddenParams
	case "gfclassify":
		return gfclassify.New(), mc.GFClassify
	case "codesecrets":
		return codesecrets.New(), mc.Codesecrets
	case "soap":
		return soap.New(client), mc.Soap
	case "nsecwalk":
		return nsecwalk.New(), mc.Nsecwalk
	case "wafdetect":
		return wafdetect.New(client), mc.Wafdetect
	case "oauthpack":
		return oauthpack.New(client), mc.Oauthpack
	case "ppollute":
		return ppollute.New(client), mc.Ppollute
	case "swscope":
		return swscope.New(client), mc.Swscope
	case "timeoracle":
		return timeoracle.New(client), mc.Timeoracle
	case "jwtconfirm":
		return jwtconfirm.New(client), mc.Jwtconfirm
	case "apiversion":
		return apiversion.New(client), mc.APIVersion
	case "apiconsole":
		return apiconsole.New(client), mc.APIConsole
	case "emailharv":
		return emailharv.New(client), mc.EmailHarv
	case "socialhijack":
		return socialhijack.New(client), mc.SocialHijack
	}
	return nil, false
}

// readTargetLines reads one target per line, ignoring blank lines and
// lines starting with #. It caps input at 100k lines / 10MB to avoid
// runaway memory use from an accidental binary pipe.
func readTargetLines(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
		if len(out) >= 100000 {
			return nil, fmt.Errorf("target list exceeds 100000 entries")
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading targets: %w", err)
	}
	return out, nil
}

func disableAllModules(mc *models.ModuleConfig) {
	*mc = models.ModuleConfig{}
}

// missingBinaries lists enabled wrapper tools whose binaries are absent
// (used by the --auto-install pre-scan alert).
func missingBinaries(modules models.ModuleConfig) []string {
	var out []string
	for _, spec := range integrations.StagedSpecs() {
		on, _ := models.GetModuleByName(modules, spec.ToggleName())
		if !on || binaryPresent(spec.Binary) {
			continue
		}
		out = append(out, spec.Name)
	}
	sort.Strings(out)
	return out
}

// applyModuleToggles handles --disable/--enable/--only (comma-separated, case-insensitive).
// Unknown names are ignored with a warning to stderr so typos don't silently do nothing.
func applyModuleToggles(mc *models.ModuleConfig, disable, enable []string) {
	set := func(name string, on bool) bool {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "recon":
			mc.Recon = on
		case "technology", "tech":
			mc.Technology = on
		case "tls":
			mc.TLS = on
		case "headers", "header":
			mc.Headers = on
		case "cookies", "cookie":
			mc.Cookies = on
		case "endpoints", "endpoint", "crawler":
			mc.Endpoints = on
		case "api":
			mc.API = on
		case "authz":
			mc.AuthZ = on
		case "idor", "bola":
			mc.IDOR = on
		case "adversarial":
			mc.Adversarial = on
		case "subdomains", "subdomain":
			mc.Subdomains = on
		case "takeover":
			mc.Takeover = on
		case "portscan", "port-scan", "ports":
			mc.PortScan = on
		case "dirs", "dir":
			mc.Dirs = on
		case "secrets", "secret":
			mc.Secrets = on
		case "params", "param":
			mc.Params = on
		case "cors":
			mc.CORS = on
		case "methods", "method":
			mc.Methods = on
		case "csrf":
			mc.CSRF = on
		case "sri":
			mc.SRI = on
		case "backup":
			mc.Backup = on
		case "deps", "dep":
			mc.Deps = on
		case "codesecrets", "code-secrets", "codesec":
			mc.Codesecrets = on
		case "active":
			mc.Active = on
		case "nuclei":
			mc.Nuclei = on
		case "zap":
			mc.ZAP = on
		case "katana":
			mc.Katana = on
		case "httpx":
			mc.Httpx = on
		case "subfinder":
			mc.Subfinder = on
		case "dalfox":
			mc.Dalfox = on
		case "dnsintel", "dns-intel":
			mc.DNSIntel = on
		case "ipintel", "ip-intel":
			mc.IPIntel = on
		case "naabu":
			mc.Naabu = on
		case "dnsx":
			mc.DNSx = on
		case "rdap":
			mc.RDAP = on
		case "archiveurls", "archive-urls":
			mc.ArchiveURLs = on
		case "certsan", "cert-san":
			mc.CertSAN = on
		case "emailharv", "email-harvest", "emailharvest":
			mc.EmailHarv = on
		case "dnsaudit", "dns-audit":
			mc.DNSAudit = on
		case "emailauth", "email-auth":
			mc.EmailAuth = on
		case "csprecon", "csp-recon":
			mc.CSPRecon = on
		case "socialhijack", "social-hijack":
			mc.SocialHijack = on
		case "commentminer", "comment-miner":
			mc.CommentMiner = on
		case "brokenlink", "broken-link":
			mc.BrokenLink = on
		case "originip", "origin-ip":
			mc.OriginIP = on
		case "exposedgit", "exposed-git":
			mc.ExposedGit = on
		case "exposedconfig", "exposed-config":
			mc.ExposedConfig = on
		case "actuator":
			mc.Actuator = on
		case "debugpages", "debug-pages":
			mc.DebugPages = on
		case "oauthanalyzer", "oauth":
			mc.OAuthAnalyzer = on
		case "samlmetadata", "saml":
			mc.SAMLMetadata = on
		case "cswsh":
			mc.CSWSH = on
		case "postmessage", "post-message":
			mc.PostMessage = on
		case "jssecrets", "js-secrets":
			mc.JSSecrets = on
		case "jsluice", "js-luice":
			mc.Jsluice = on
		case "hiddenparams", "hidden-params":
			mc.HiddenParams = on
		case "verbtamper", "verb-tamper":
			mc.VerbTamper = on
		case "cachedeception", "cache-deception":
			mc.CacheDeception = on
		case "forbiddenbypass", "forbidden-bypass":
			mc.ForbiddenBypass = on
		case "takeoverplus", "takeover-plus":
			mc.TakeoverPlus = on
		case "clickjack":
			mc.Clickjack = on
		case "policyheaders", "policy-headers":
			mc.PolicyHeaders = on
		case "cookieprefix", "cookie-prefix":
			mc.CookiePrefix = on
		case "apiversion", "api-version":
			mc.APIVersion = on
		case "apiconsole", "api-console":
			mc.APIConsole = on
		case "vhost", "v-host":
			mc.VHost = on
		case "graphqlfp", "graphql-fp":
			mc.GraphQLFP = on
		case "graphqlschema", "graphql-schema":
			mc.GraphQLSchema = on
		case "jwtplus", "jwt-plus":
			mc.JWTPlus = on
		case "sstiexpand", "ssti-expand":
			mc.SSTIExpand = on
		case "nosqlexpand", "nosql-expand":
			mc.NoSQLExpand = on
		case "h2smuggle", "h2-smuggle":
			mc.H2Smuggle = on
		case "h2fp", "h2-fp":
			mc.H2FP = on
		case "redirectpack", "redirect-pack":
			mc.RedirectPack = on
		case "lfipack", "lfi-pack":
			mc.LFIPack = on
		case "cvepack", "cve-pack":
			mc.CVEPack = on
		case "corsplus", "cors-plus":
			mc.CORSPlus = on
		case "certhistory", "cert-history":
			mc.CertHistory = on
		case "axfrplus", "axfr-plus":
			mc.AXFRPlus = on
		case "subpermute", "sub-permute":
			mc.SubPermute = on
		case "backupplus", "backup-plus":
			mc.BackupPlus = on
		case "faviconplus", "favicon-plus":
			mc.FaviconPlus = on
		case "debugmethods", "debug-methods":
			mc.DebugMethods = on
		case "encodepoly", "encode-poly":
			mc.EncodePoly = on
		case "difforacle", "diff-oracle":
			mc.DiffOracle = on
		case "gfclassify", "gf-classify":
			mc.GFClassify = on
		case "soap":
			mc.Soap = on
		case "nsecwalk", "nsec-walk":
			mc.Nsecwalk = on
		case "wafdetect", "waf-detect":
			mc.Wafdetect = on
		case "oauthpack", "oauth-pack":
			mc.Oauthpack = on
		case "ppollute", "pp-pollute":
			mc.Ppollute = on
		case "swscope", "sw-scope", "serviceworker":
			mc.Swscope = on
		case "timeoracle", "time-oracle":
			mc.Timeoracle = on
		case "jwtconfirm", "jwt-confirm":
			mc.Jwtconfirm = on
		case "leak":
			mc.Leak = on
		case "favicon":
			mc.Favicon = on
		case "doh":
			mc.DoH = on
		case "bucket":
			mc.Bucket = on
		case "bgp":
			mc.BGP = on
		default:
			// Wave 2 wrappers resolve by reflection over `wrapper` tags
			// (cspreconext, osv-scanner, jwt_tool, ...).
			if models.SetModuleByName(mc, name, on) {
				return true
			}
			fmt.Fprintf(os.Stderr, "anpu: unknown module %q in --enable/--disable (ignored)\n", name)
			return false
		}
		return true
	}
	for _, n := range disable {
		for _, part := range strings.Split(n, ",") {
			if part = strings.TrimSpace(part); part != "" {
				set(part, false)
			}
		}
	}
	for _, n := range enable {
		for _, part := range strings.Split(n, ",") {
			if part = strings.TrimSpace(part); part != "" {
				set(part, true)
			}
		}
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
