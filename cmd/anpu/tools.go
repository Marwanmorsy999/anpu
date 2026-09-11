package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/anpu-project/anpu/internal/integrations"
	"github.com/spf13/cobra"
)

func newToolsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tools",
		Short: "See which security engines are ready to use",
		Long: `Report the status of ANPU's built-in engines and any optional
external integrations (nuclei). Built-in engines need no installation —
they are compiled into the anpu binary.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runToolsStatus(cmd)
		},
	}
	cmd.AddCommand(newToolsInstallCmd())
	return cmd
}

func runToolsStatus(cmd *cobra.Command) error {
	fmt.Println("ANPU engine status")
	fmt.Println()

	builtin := []struct {
		name string
		desc string
	}{
		{"Recon", "DNS, robots.txt, sitemap.xml, redirects, source maps, historical URLs"},
		{"DNSIntel", "passive DNS enumeration (A/AAAA, CNAME, MX, NS, TXT, SPF, DMARC, PTR + AXFR probe)"},
		{"IPIntel", "reverse PTR, hosting/cloud provider, ASN via Team Cymru DNS + IP RDAP"},
		{"RDAP", "domain registration (registrar, creation/expiry, NS, DNSSEC) via RDAP"},
		{"Leak", "private IP / internal hostname / cloud metadata leak in headers/body"},
		{"Favicon", "favicon mmh3 hash (Shodan http.favicon.hash pivot)"},
		{"DoH", "DNS-over-HTTPS endpoint exposure (RFC 8484)"},
		{"Bucket", "cloud bucket existence probe (S3/Azure/GCS via domain-derived names)"},
		{"BGP", "BGP prefix + RPKI hint via BGPView API"},
		{"Technology", "passive stack fingerprinting (headers, cookies, HTML/JS)"},
		{"TLS", "certificate validity/expiry, protocol versions, HTTPS redirect"},
		{"Headers", "security-header presence and quality"},
		{"Cookies", "Secure/HttpOnly/SameSite attribute audit"},
		{"Endpoints", "HTML/JS link, form, script, and API-path discovery + auth-diff"},
		{"API", "OpenAPI/Swagger + GraphQL schema-driven endpoint expansion"},
		{"Subdomains", "Certificate Transparency logs (+ DNS brute on deep)"},
		{"Takeover", "subdomain takeover (CNAME + body fingerprints)"},
		{"PortScan", "TCP connect scan of common service ports (deep)"},
		{"Dirs", "sensitive-path probing with soft-404 baseline"},
		{"Secrets", "API keys / tokens / private keys + JS route/DOM-sink intel"},
		{"Params", "query-parameter classification (sqli/xss/ssrf/idor/redirect/lfi/rce/ssti)"},
		{"CORS", "origin-reflection and credentials misconfiguration"},
		{"Methods", "OPTIONS audit + live TRACE (XST) verification"},
		{"CSRF", "missing CSRF tokens in forms"},
		{"SRI", "Subresource Integrity for cross-origin scripts/styles"},
		{"Backup", "backup/archive file probing per endpoint"},
		{"Deps", "JS library CVE via fingerprints + manifests (requirements/package.json/pom/go.mod) + OSV"},
		{"Codesecrets", "local code secrets + IaC misconfigs, offline (300 files)"},
		{"Active", "safe active tests: XSS/SQLi/SSRF/path-traversal/bypass-403/blind"},
		{"AuthZ", "dual-identity authorization diff (needs --authz-*)"},
		{"IDOR", "BOLA numeric id+1 replay (advanced/ultra; toggle via --enable/--disable idor)"},
		{"Katana", "crawl — embedded (external katana optional for deeper JS)"},
		{"Httpx", "probe — embedded (external httpx optional for extra tech)"},
		{"Subfinder", "subdomains — embedded brute + CT (external subfinder optional)"},
		{"DNSx", "DNS toolkit — embedded (external dnsx optional)"},
		{"Naabu", "fast port scan — embedded (external naabu optional)"},
		{"Dalfox", "XSS confirm — embedded reflection (external dalfox optional)"},
		{"Nuclei", "exposure templates — embedded subset (external nuclei optional for full)"},
		{"ZAP", "DAST — embedded passive subset (external ZAP/Docker optional for full)"},
		{"ArchiveURLs", "live-page URL + param corpus (homepage/robots/JS, 3 reqs)"},
		{"CertSAN", "TLS certificate SAN subdomain signal (0 HTTP reqs)"},
		{"EmailHarv", "homepage email harvest, placeholders filtered (1 req)"},
		{"DNSAudit", "DNSSEC/CAA/DANE posture (DNS-only)"},
		{"EmailAuth", "SPF/DMARC/DKIM/BIMI/TLS-RPT + MTA-STS audit"},
		{"CSPRecon", "CSP host-source subdomain extraction (1 req)"},
		{"SocialHijack", "dangling social profile links (HEAD verify, max 5)"},
		{"CommentMiner", "interesting HTML comments, control-subtracted"},
		{"BrokenLink", "same-host broken links, soft-404 baseline (max 10)"},
		{"OriginIP", "origin-IP signals CNAME/DNS/direct-IP title (max 3 reqs)"},
		{"ExposedGit", "exposed .git detection-only, dual-marker (4 reqs)"},
		{"ExposedConfig", "exposed SVN/HG/BZR/ENV/DS_Store (7 reqs)"},
		{"Actuator", "Spring Actuator pack, headers-only on heapdump (12 reqs)"},
		{"DebugPages", "Laravel/Django/Rails/phpinfo/server-status (9 reqs)"},
		{"OAuthAnalyzer", "OAuth/OIDC discovery + implicit-flow check (6 reqs)"},
		{"SAMLMetadata", "SAML metadata exposure + endpoint harvest (5 reqs)"},
		{"CSWSH", "WebSocket handshake Origin check (4 raw dials, 0 frames)"},
		{"PostMessage", "postMessage/DOM-sink static analysis (6 reqs)"},
		{"JSSecrets", "JS secret 40+ regex pack, values masked (9 reqs)"},
		{"HiddenParams", "hidden-param miner, dual baseline (64 reqs)"},
		{"VerbTamper", "method-tampering bypass on denied endpoints (21 reqs)"},
		{"CacheDeception", "cache-deception suffix matrix + HIT check (8 reqs)"},
		{"ForbiddenBypass", "header/path 403-bypass matrix, dual baseline (24 reqs)"},
		{"TakeoverPlus", "30 takeover sigs, CNAME+body (20 hosts)"},
		{"Clickjack", "XFO + frame-ancestors analysis (3 reqs)"},
		{"PolicyHeaders", "HSTS-preload/COOP/COEP/CORP readiness (1 req)"},
		{"CookiePrefix", "cookie __Host-/__Secure- rule audit (3 reqs)"},
		{"APIVersion", "API sibling-version fuzz + harvest (11 reqs)"},
		{"APIConsole", "GraphiQL/Altair/RapiDoc/Redoc walk + harvest (11 reqs)"},
		{"VHost", "bounded vhost discovery, 12 names (13 reqs)"},
		{"GraphQLFP", "GraphQL typename probe + engine identify (8 reqs)"},
		{"GraphQLSchema", "introspection disclosure test, read-only (3 reqs)"},
		{"JWTPlus", "observed-JWT decode: none/kid/jku/exp (1 req)"},
		{"SSTIExpand", "SSTI 10-engine benign-math differential (24 reqs)"},
		{"NoSQLExpand", "NoSQL operator differential, no extraction (18 reqs)"},
		{"H2Smuggle", "H2 desync safe-subset timing, adversarial-gated (5 reqs)"},
		{"H2FP", "H2 ALPN + H3 Alt-Svc fingerprint (1 req)"},
		{"RedirectPack", "open-redirect 10-payload pack, no-follow (22 reqs)"},
		{"LFIPack", "LFI wrapper pack, marker + differential (20 reqs)"},
		{"CVEPack", "CVE version-sigs + inert Spring differential (3 reqs)"},
		{"CORSPlus", "null/evil/subdomain credentialed matrix (12 reqs)"},
		{"CertHistory", "crt.sh age + subdomain harvest (1 archive req)"},
		{"AXFRPlus", "AXFR sweep across all NS (DNS-only)"},
		{"SubPermute", "offline permutation + DNS confirm (50 lookups)"},
		{"BackupPlus", "30-suffix backup expansion (61 reqs)"},
		{"FaviconPlus", "8-path icon sweep + hash groups (9 reqs)"},
		{"DebugMethods", "DEBUG/TRACE/TEST live probes, empty bodies (8 reqs)"},
		{"EncodePoly", "encoding canary matrix, no exploits (13 reqs)"},
		{"DiffOracle", "boolean oracle differential, stable-repeat (8 reqs)"},
		{"GFClassify", "GF-pattern URL classifier, offline (0 reqs)"},
		{"Soap", "SOAP/WSDL discovery + op harvest (9 reqs)"},
		{"Nsecwalk", "DNSSEC NSEC chain walk, NSEC3 detect (DNS-only)"},
		{"Wafdetect", "WAF block-behavior fingerprint, canary matrix (5 reqs)"},
		{"Oauthpack", "OAuth redirect_uri confusion pack, no-follow (17 reqs)"},
		{"Ppollute", "proto-pollution merge-sink static analysis (6 reqs)"},
		{"Swscope", "service-worker scope + foreign imports (6 reqs)"},
		{"Timeoracle", "statistical sleep-oracle differential (11 reqs)"},
		{"Jwtconfirm", "alg:none acceptance differential, adversarial (7 reqs)"},
	}
	for _, e := range builtin {
		fmt.Printf("  [built-in] ✓ %-12s %s\n", e.name, e.desc)
	}

	fmt.Println()
	fmt.Println("External tools (registry — binary when installed, embedded otherwise):")
	ctx, cancel := context.WithTimeout(cmd.Context(), integrations.ProbeTimeout()*15)
	defer cancel()
	extCounts := map[string]int{}
	for _, name := range integrations.SortedToolNames() {
		spec, _ := integrations.SpecByName(name)
		level := ""
		if spec != nil {
			level = spec.Level
		}
		if recipe, ok := integrations.Get(name); ok && level == "" {
			level = recipe.Level
		}
		state, detail := integrations.ToolStatus(ctx, name)
		extCounts[state]++
		sym := "~"
		switch state {
		case integrations.ToolExternal:
			sym = "✓"
		case integrations.ToolEmbedded:
			sym = "~"
		default:
			sym = "✗"
		}
		timeout := ""
		if spec != nil {
			timeout = fmt.Sprintf("max %ds", integrations.SpecTimeout(spec))
		}
		fmt.Printf("  [ext] %s %-14s %-8s %s %s\n", sym, name, level, detail, timeout)
	}
	fmt.Printf("  external=%d embedded=%d missing-installable=%d missing-manual=%d\n",
		extCounts[integrations.ToolExternal], extCounts[integrations.ToolEmbedded],
		extCounts[integrations.ToolMissingInstallable], extCounts[integrations.ToolMissingManual])

	fmt.Println()
	fmt.Println("Environment (operator prerequisites):")
	for _, e := range integrations.EnvStatus() {
		sym := "✗"
		val := "unset"
		if e.OK {
			sym = "✓"
			val = e.Value
		} else if e.Value != "" {
			val = e.Value + " (not usable)"
		}
		fmt.Printf("  %s %-20s %s — %s\n", sym, e.Name, val, e.Used)
	}

	fmt.Println()
	worst := integrations.LevelWorstCase()
	fmt.Printf("Worst-case staged external time (every binary present, full timeouts, sequential): advanced ≈ %s, ultra ≈ %s.\n",
		integrations.FormatDuration(worst["advanced"]), integrations.FormatDuration(worst["ultra"]))
	fmt.Println("Set ANPU_TOOL_BUDGET_SEC=N to cap cumulative external-tool seconds (0/unset = uncapped); exhausted tools skip with an explicit reason.")

	fmt.Println()
	fmt.Println("Levels:")
	fmt.Println("  safe      passive only — zero noise (API/AuthZ anonymous probing as designed behavior)")
	fmt.Println("  advanced  safe + polite active (alias: standard)")
	fmt.Println("  ultra     everything (alias: deep) — most thorough")
	fmt.Println()
	fmt.Println("Shortcuts:  anpu safe <target>  |  anpu advanced <target>  |  anpu ultra <target>")
	fmt.Println("Simple flags: --disable <a,b>  --enable <a,b>   (see --help for module names)")
	fmt.Printf("Wave 2 registry: %d tools — binary when installed, native embedded coverage otherwise (anpu tools install --list | anpu tools install <name>)\n", len(integrations.Registry))
	fmt.Println("Scope guard: --scope-file allowlist.txt (hard stop before any request)")
	return nil
}

// newToolsInstallCmd implements `anpu tools install`: managed installation
// for the Wave 2 free-binary registry. A bare name INSTALLS the tool
// (go/pipx/apt/choco/docker, then verifies the binary); --dry-run only
// prints the recipe; --all installs every installable recipe for a level
// (requires --yes). Installing only places the vendor binary on disk —
// run-time safety rules are unchanged.
func newToolsInstallCmd() *cobra.Command {
	var listFlag, dryRunFlag, allFlag, yesBool bool
	var levelFilter string
	cmd := &cobra.Command{
		Use:   "install [name]",
		Short: "Install an optional external tool (managed)",
		Long: `Install an optional external security tool from the Wave 2
registry and verify the binary resolves. Absent tools warn-and-skip
in scans until installed.

Examples:
  anpu tools install --list
  anpu tools install amass
  anpu tools install sqlmap --dry-run
  anpu tools install --all --level advanced --yes`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if listFlag {
				for _, r := range integrations.All() {
					gate := ""
					if r.Adversarial {
						gate = " [adversarial-gated]"
					}
					fmt.Printf("  %-14s %-8s %s%s\n", r.Name, r.Level, r.Notes, gate)
				}
				fmt.Printf("\n%d recipes. Detail: anpu tools install <name>\n", len(integrations.Registry))
				return nil
			}
			if allFlag {
				return runInstallAll(cmd, levelFilter, yesBool)
			}
			if len(args) == 0 {
				return fmt.Errorf("pass a tool name, --list, or --all (try: anpu tools install --list)")
			}
			r, ok := integrations.Get(args[0])
			if !ok {
				if isBuiltinModule(args[0]) {
					fmt.Printf("%s is a built-in engine — no installation needed (run: anpu scan --only %s <target>)\n", args[0], lower(args[0]))
					return nil
				}
				return fmt.Errorf("unknown tool %q — try: anpu tools install --list", args[0])
			}
			if dryRunFlag {
				fmt.Print(integrations.FormatRecipe(r, runtime.GOOS))
				return nil
			}
			if _, ok := integrations.LookupBinary(r.Binary); ok {
				fmt.Printf("%s is already installed (%s)\n", r.Name, r.Binary)
				return nil
			}
			fmt.Print(integrations.FormatRecipe(r, runtime.GOOS))
			if !askConfirm(os.Stdin, os.Stderr, yesBool, stdinInteractive(), true,
				fmt.Sprintf("Install %s now (downloads + builds vendor code)?", r.Name)) {
				fmt.Println("Aborted — nothing installed. Re-run with --yes to skip this prompt.")
				return nil
			}
			fmt.Printf("Installing %s ...\n", r.Name)
			method, err := integrations.Install(cmd.Context(), r, 0)
			if err != nil {
				return err
			}
			fmt.Printf("Installed %s via %s — verified on PATH/Go-bin\n", r.Name, method)
			return nil
		},
	}
	cmd.Flags().BoolVar(&listFlag, "list", false, "list all registry recipes")
	cmd.Flags().BoolVar(&dryRunFlag, "dry-run", false, "print the recipe without installing")
	cmd.Flags().BoolVar(&allFlag, "all", false, "install every installable recipe (requires --yes)")
	cmd.Flags().BoolVar(&yesBool, "yes", false, "confirm installation without prompting")
	cmd.Flags().StringVar(&levelFilter, "level", "", "with --all, limit to safe, advanced, or ultra")
	return cmd
}

// runInstallAll installs every installable recipe, continuing past
// individual failures and reporting a summary table.
func runInstallAll(cmd *cobra.Command, level string, yes bool) error {
	if !yes {
		n := 0
		for _, s := range integrations.InstallableSpecs(runtime.GOOS) {
			r, _ := integrations.Get(s.Name)
			if level != "" && r.Level != strings.ToLower(level) {
				continue
			}
			n++
		}
		return fmt.Errorf("this would install %d tools — re-run with --yes to confirm (anpu tools install --all --yes)", n)
	}
	type result struct {
		name, outcome string
	}
	var results []result
	failed := 0
	for _, s := range integrations.InstallableSpecs(runtime.GOOS) {
		r, _ := integrations.Get(s.Name)
		if level != "" && r.Level != strings.ToLower(level) {
			continue
		}
		if _, ok := integrations.LookupBinary(r.Binary); ok {
			results = append(results, result{s.Name, "already installed"})
			continue
		}
		fmt.Printf("Installing %s ...\n", s.Name)
		method, err := integrations.Install(cmd.Context(), r, 0)
		if err != nil {
			results = append(results, result{s.Name, "FAILED: " + firstLine(err.Error())})
			failed++
			continue
		}
		results = append(results, result{s.Name, "installed via " + method})
	}
	fmt.Println("\nInstall summary:")
	for _, res := range results {
		fmt.Printf("  %-14s %s\n", res.name, res.outcome)
	}
	fmt.Printf("\n%d installed/present, %d failed\n", len(results)-failed, failed)
	if failed > 0 {
		return fmt.Errorf("%d tool(s) failed to install (see above)", failed)
	}
	return nil
}

func firstLine(s string) string {
	if i := strings.Index(s, "\n"); i >= 0 {
		s = s[:i]
	}
	if len(s) > 120 {
		s = s[:120] + "..."
	}
	return s
}

// builtinModules covers native engines (no installation ever needed).
// This mirrors the canonical --only toggle vocabulary in scan.go
// (applyModuleToggles): anything here is compiled in, full stop.
func isBuiltinModule(name string) bool {
	switch lower(name) {
	case "recon", "technology", "tech", "tls", "headers", "header",
		"cookies", "cookie", "endpoints", "endpoint", "crawler",
		"api", "authz", "idor", "bola", "adversarial",
		"subdomains", "subdomain", "takeover", "takeoverplus",
		"portscan", "port-scan", "ports", "dirs", "dir",
		"secrets", "secret", "params", "param", "cors",
		"methods", "method", "csrf", "sri", "backup",
		"deps", "dep", "codesecrets", "code-secrets", "codesec",
		"active", "nuclei", "zap", "katana", "httpx", "subfinder",
		"dalfox", "dnsintel", "dns-intel", "ipintel", "ip-intel",
		"naabu", "dnsx", "rdap", "leak", "favicon", "doh", "bucket", "bgp",
		"archiveurls", "archive-urls", "certsan", "cert-san",
		"emailharv", "email-harvest", "emailharvest",
		"dnsaudit", "dns-audit", "emailauth", "email-auth",
		"csprecon", "csp-recon", "socialhijack", "social-hijack",
		"commentminer", "comment-miner", "brokenlink", "broken-link",
		"originip", "origin-ip", "exposedgit", "exposed-git",
		"exposedconfig", "exposed-config", "actuator",
		"debugpages", "debug-pages", "oauthanalyzer", "oauth",
		"samlmetadata", "saml", "cswsh", "postmessage", "post-message",
		"jssecrets", "js-secrets", "hiddenparams", "hidden-params",
		"verbtamper", "verb-tamper", "cachedeception", "cache-deception",
		"forbiddenbypass", "forbidden-bypass", "clickjack",
		"policyheaders", "policy-headers", "cookieprefix", "cookie-prefix",
		"apiversion", "api-version", "apiconsole", "api-console",
		"vhost", "v-host", "graphqlfp", "graphql-fp",
		"graphqlschema", "graphql-schema", "jwtplus", "jwt-plus",
		"sstiexpand", "ssti-expand", "nosqlexpand", "nosql-expand",
		"h2smuggle", "h2-smuggle", "h2fp", "h2-fp",
		"redirectpack", "redirect-pack", "lfipack", "lfi-pack",
		"cvepack", "cve-pack", "corsplus", "cors-plus",
		"certhistory", "cert-history", "axfrplus", "axfr-plus",
		"subpermute", "sub-permute", "backupplus", "backup-plus",
		"faviconplus", "favicon-plus", "debugmethods", "debug-methods",
		"encodepoly", "encode-poly", "difforacle", "diff-oracle",
		"gfclassify", "gf-classify", "soap", "nsecwalk", "nsec-walk",
		"wafdetect", "waf-detect", "oauthpack", "oauth-pack",
		"ppollute", "pp-pollute", "swscope", "sw-scope", "serviceworker",
		"timeoracle", "time-oracle", "jwtconfirm", "jwt-confirm", "jsluice", "js-luice":
		return true
	}
	return false
}

func lower(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
