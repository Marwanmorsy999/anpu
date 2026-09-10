package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

type toolInfo struct {
	Name  string
	Desc  string
	Level string
	Rank  int
}

func allToolsRanked() []toolInfo {
	// Rank 1 = safe, 2 = advanced, 3 = ultra
	return []toolInfo{
		{"Recon", "DNS, robots.txt, sitemap.xml, historical URLs", "safe", 1},
		{"DNSIntel", "passive DNS enumeration (MX/NS/TXT/SPF/DMARC/PTR + AXFR)", "safe", 1},
		{"IPIntel", "reverse PTR, cloud provider, ASN + IP RDAP", "safe", 1},
		{"RDAP", "domain registration (registrar, creation/expiry)", "safe", 1},
		{"Leak", "private IP / internal host leak", "safe", 1},
		{"Favicon", "favicon mmh3 hash pivot", "safe", 1},
		{"DoH", "DNS-over-HTTPS exposure", "safe", 1},
		{"Bucket", "cloud bucket probe (S3/Azure/GCS)", "safe", 1},
		{"BGP", "BGP prefix / ASN via BGPView", "safe", 1},
		{"Technology", "stack fingerprinting", "safe", 1},
		{"TLS", "cert, protocol, HTTPS redirect", "safe", 1},
		{"Headers", "security headers", "safe", 1},
		{"Cookies", "Secure/HttpOnly/SameSite", "safe", 1},
		{"Endpoints", "HTML/JS discovery + auth-diff", "safe", 1},
		{"SRI", "Subresource Integrity", "safe", 1},
		{"Params", "query-param classification", "safe", 1},
		{"API", "OpenAPI/Swagger + GraphQL discovery", "safe", 1},
		{"AuthZ", "authz anonymous probing as designed", "safe", 1},
		{"Subdomains", "CT logs (+ DNS brute on ultra)", "advanced", 2},
		{"Takeover", "subdomain takeover", "advanced", 2},
		{"Dirs", "sensitive paths + soft-404", "advanced", 2},
		{"Secrets", "keys/tokens + JS route/DOM sink", "advanced", 2},
		{"CORS", "origin reflection", "advanced", 2},
		{"Methods", "OPTIONS + TRACE", "advanced", 2},
		{"CSRF", "missing tokens", "advanced", 2},
		{"Backup", "backup file probe", "advanced", 2},
		{"Deps", "JS library CVE", "advanced", 2},
		{"Active", "XSS/SQLi/SSRF/bypass-403/blind", "advanced", 2},
		{"Katana", "external crawl (go install katana)", "advanced", 2},
		{"Httpx", "external probe (go install httpx)", "advanced", 2},
		{"Subfinder", "external subdomains (go install subfinder)", "advanced", 2},
		{"DNSx", "external DNS toolkit (go install dnsx)", "advanced", 2},
		{"Dalfox", "external XSS confirm (go install dalfox)", "advanced", 2},
		{"Nuclei", "external templates (go install nuclei)", "advanced", 2},
		{"PortScan", "TCP connect scan", "ultra", 3},
		{"Naabu", "external fast scan (go install naabu)", "ultra", 3},
		{"ZAP", "external DAST (Docker zap)", "ultra", 3},
		{"JWT", "adversarial JWT weak verification (alg:none)", "advanced", 2},
		{"MassAssign", "adversarial mass assignment auto-binding", "advanced", 2},
		{"Business", "adversarial business logic tampering", "advanced", 2},
		{"Race", "adversarial race condition", "advanced", 2},
		{"Smuggling", "adversarial HTTP smuggling CL.TE/TE.CL", "advanced", 2},
		{"ProtoPollute", "adversarial prototype pollution", "advanced", 2},
		{"SqliBoolean", "adversarial sqli boolean differential + random control", "advanced", 2},
		{"VectorHeader", "adversarial vector header injection", "advanced", 2},
		{"VectorWebSocket", "adversarial vector WebSocket", "advanced", 2},
		{"VectorGRPC", "adversarial vector gRPC reflection", "advanced", 2},
		{"Soft404", "adversarial soft-404 + route sampler 3-5", "advanced", 2},
		{"EvidenceBundle", "adversarial bundle curl+snippets needs-review", "advanced", 2},
		// Master ghost + overpower additions (P1-P2)
		{"Ldap", "ldap injection CWE-90 *)(uid=*)", "advanced", 2},
		{"Xpath", "xpath injection CWE-643 ' or '1'='1", "advanced", 2},
		{"SSI", "ssi injection <!--#exec", "advanced", 2},
		{"HPP", "http parameter pollution ?id=1&id=2", "advanced", 2},
		{"RFI", "remote file inclusion http://evil", "advanced", 2},
		{"CodeInject", "code injection php eval beyond ssti 4 engines", "advanced", 2},
		{"Buffer", "buffer overflow A*10000", "advanced", 2},
		{"Formula", "formula injection =cmd|", "advanced", 2},
		{"FileUpload", "file upload polyglot multipart", "advanced", 2},
		{"Deserial", "insecure deserialization rO0AB CWE-502", "advanced", 2},
		{"RateLimit", "rate limit missing API4 Low 10x rapid GET 429", "advanced", 2},
		{"SessionFixation", "adversarial session fixation CWE-384", "advanced", 2},
		{"ExposedSession", "adversarial exposed jsessionid ;jsessionid=", "advanced", 2},
		{"Logout", "adversarial logout invalidation", "advanced", 2},
		{"PasswordPolicy", "adversarial password policy", "advanced", 2},
		{"IDOR", "bola/idor numeric id+1 replay RequestBudget 5", "advanced", 2},
		{"Ghost", "ghost undetectable Chrome131 JA3 h2 GREASE Pareto jitter proxy rotation", "advanced", 2},
		{"GRPC", "grpc reflection ListServices application/grpc", "advanced", 2},
		// Wave 1 batch 1 — native passive recon (LIVE).
		{"ArchiveURLs", "live-page URL + param corpus (homepage/robots/JS, 3 reqs)", "safe", 1},
		{"CertSAN", "TLS certificate SAN subdomain signal (0 HTTP reqs)", "safe", 1},
		{"EmailHarv", "homepage email harvest, placeholders filtered (1 req)", "safe", 1},
		{"DNSAudit", "DNSSEC/CAA/DANE posture (DNS-only, 0 HTTP reqs)", "safe", 1},
		{"EmailAuth", "SPF/DMARC/DKIM/BIMI/TLS-RPT + MTA-STS audit", "safe", 1},
		{"CSPRecon", "CSP host-source subdomain extraction (1 req)", "safe", 1},
		{"SocialHijack", "dangling social profile links (HEAD verify, max 5)", "safe", 1},
		{"CommentMiner", "interesting HTML comments, control-subtracted", "safe", 1},
		{"BrokenLink", "same-host broken links, soft-404 baseline (max 10)", "safe", 1},
		{"OriginIP", "origin-IP signals CNAME/DNS/direct-IP title (max 3 reqs)", "safe", 1},
		// Wave 1 batches 2-5 — native engines (preview: landing per wave).
		{"ExposedGit", "exposed .git detection-only, dual-marker (4 reqs)", "advanced", 2},
		{"ExposedConfig", "exposed SVN/HG/BZR/ENV/DS_Store (7 reqs)", "advanced", 2},
		{"Actuator", "Spring Actuator pack, headers-only on heapdump (12 reqs)", "advanced", 2},
		{"DebugPages", "Laravel/Django/Rails/phpinfo/server-status (9 reqs)", "advanced", 2},
		{"OAuthAnalyzer", "OAuth/OIDC discovery + implicit-flow check (6 reqs)", "advanced", 2},
		{"SAMLMetadata", "SAML metadata exposure + endpoint harvest (5 reqs)", "advanced", 2},
		{"CSWSH", "WebSocket cross-site hijack handshake (4 raw dials, 0 frames)", "advanced", 2},
		{"PostMessage", "postMessage/DOM-sink static analysis (6 reqs)", "advanced", 2},
		{"JSSecrets", "JS secret 40+ regex pack, values masked (9 reqs)", "advanced", 2},
		{"Jsluice", "JS URL joinery + secret harvest, native port (9 reqs)", "advanced", 2},
		{"HiddenParams", "hidden-param miner 30-name wordlist, dual baseline (64 reqs)", "advanced", 2},
		{"VerbTamper", "method-tampering bypass on denied endpoints (21 reqs)", "advanced", 2},
		{"CacheDeception", "cache-deception suffix matrix + HIT check (8 reqs)", "advanced", 2},
		{"ForbiddenBypass", "header/path 403-bypass matrix, dual baseline (24 reqs)", "advanced", 2},
		{"TakeoverPlus", "30 takeover sigs dnsReaper-family, CNAME+body (20 hosts)", "advanced", 2},
		{"Clickjack", "XFO + frame-ancestors analysis (3 reqs)", "safe", 1},
		{"PolicyHeaders", "HSTS-preload/COOP/COEP/CORP readiness (1 req)", "safe", 1},
		{"CookiePrefix", "cookie __Host-/__Secure- rule audit (3 reqs)", "safe", 1},
		{"APIVersion", "API sibling-version fuzz + harvest (11 reqs)", "advanced", 2},
		{"APIConsole", "GraphiQL/Altair/RapiDoc/Redoc walk + harvest (11 reqs)", "advanced", 2},
		{"VHost", "bounded vhost discovery, 12 names (13 reqs)", "advanced", 2},
		{"GraphQLFP", "GraphQL typename probe + engine identify (8 reqs)", "advanced", 2},
		{"GraphQLSchema", "introspection disclosure test, read-only (3 reqs)", "advanced", 2},
		{"JWTPlus", "observed-JWT decode: none/kid/jku/exp (1 req)", "safe", 1},
		{"SSTIExpand", "SSTI 10-engine benign-math differential (24 reqs)", "advanced", 2},
		{"NoSQLExpand", "NoSQL operator differential, no extraction (18 reqs)", "advanced", 2},
		{"H2Smuggle", "H2 desync safe-subset timing, adversarial-gated (5 reqs)", "advanced", 2},
		{"H2FP", "H2 ALPN + H3 Alt-Svc fingerprint (1 req)", "safe", 1},
		{"RedirectPack", "open-redirect 10-payload pack, no-follow (22 reqs)", "advanced", 2},
		{"LFIPack", "LFI wrapper pack, marker + differential (20 reqs)", "advanced", 2},
		{"CVEPack", "CVE version-sigs + inert Spring differential (3 reqs)", "advanced", 2},
		{"CORSPlus", "null/evil/subdomain credentialed matrix (12 reqs)", "advanced", 2},
		{"CertHistory", "crt.sh age + subdomain harvest (1 archive req)", "safe", 1},
		{"AXFRPlus", "AXFR sweep across all NS (DNS-only)", "advanced", 2},
		{"SubPermute", "offline permutation + DNS confirm (50 lookups)", "safe", 1},
		{"BackupPlus", "30-suffix backup expansion (61 reqs)", "advanced", 2},
		{"FaviconPlus", "8-path icon sweep + hash groups (9 reqs)", "advanced", 2},
		{"DebugMethods", "DEBUG/TRACE/TEST live probes, empty bodies (8 reqs)", "advanced", 2},
		{"EncodePoly", "encoding canary matrix, no exploits (13 reqs)", "advanced", 2},
		{"DiffOracle", "boolean oracle differential, stable-repeat (8 reqs)", "advanced", 2},
		{"GFClassify", "GF-pattern URL classifier, offline (0 reqs)", "safe", 1},
		{"Soap", "SOAP/WSDL discovery + op harvest (9 reqs)", "advanced", 2},
		{"Nsecwalk", "DNSSEC NSEC chain walk, NSEC3 detect (DNS-only)", "advanced", 2},
		{"Wafdetect", "WAF block-behavior fingerprint, canary matrix (5 reqs)", "advanced", 2},
		{"Oauthpack", "OAuth redirect_uri confusion pack, no-follow (17 reqs)", "advanced", 2},
		{"Ppollute", "proto-pollution merge-sink static analysis (6 reqs)", "advanced", 2},
		{"Swscope", "service-worker scope + foreign imports (6 reqs)", "advanced", 2},
		{"Timeoracle", "statistical sleep-oracle differential (11 reqs)", "advanced", 2},
		{"Jwtconfirm", "alg:none acceptance differential, adversarial (7 reqs)", "advanced", 2},
		{"Codesecrets", "local code secrets + IaC misconfigs, offline (300 files)", "safe", 1},
		// Wave 2 — free-binary wrappers (binary, auto-install, or
		// embedded natives; absent binary never fatal).
		{"Amass", "external passive enum (binary or embedded)", "advanced", 2},
		{"Assetfinder", "external passive subdomains (binary or embedded)", "advanced", 2},
		{"Findomain", "external fast enum (binary or embedded)", "advanced", 2},
		{"Shuffledns", "external massdns brute, needs resolvers+wordlist", "advanced", 2},
		{"Puredns", "external brute, needs resolvers+wordlist", "advanced", 2},
		{"Massdns", "install recipe only (library for shuffledns)", "advanced", 2},
		{"Dnsgen", "external permutation generator (binary or embedded)", "advanced", 2},
		{"Alterx", "external permutation (binary or embedded)", "advanced", 2},
		{"Gotator", "external permutation (binary or embedded)", "advanced", 2},
		{"Dnsrecon", "external DNS enum scripts (binary or embedded)", "advanced", 2},
		{"Metabigor", "manual binary; embedded subdomains+ipintel", "advanced", 2},
		{"TLSx", "external TLS probe (binary or embedded)", "advanced", 2},
		{"Cdncheck", "external CDN detect (binary or embedded)", "advanced", 2},
		{"Asnmap", "external ASN lookup (binary or embedded)", "advanced", 2},
		{"Webanalyze", "external tech fingerprint (binary or embedded)", "advanced", 2},
		{"CspreconExt", "manual binary; embedded csprecon", "advanced", 2},
		{"HakOriginFinder", "manual binary; embedded origin-ip", "advanced", 2},
		{"Gau", "external archive URLs (binary or embedded)", "advanced", 2},
		{"Waybackurls", "external wayback corpus (binary or embedded)", "advanced", 2},
		{"Hakrawler", "external crawler (binary or embedded)", "advanced", 2},
		{"Gospider", "external crawler (binary or embedded)", "advanced", 2},
		{"Cariddi", "external crawler+secrets (binary or embedded)", "advanced", 2},
		{"Unfurl", "manual binary; embedded params+gfclassify", "advanced", 2},
		{"Uro", "external URL dedup (binary or embedded)", "advanced", 2},
		{"Qsreplace", "external query replace (binary or embedded)", "advanced", 2},
		{"Anew", "install recipe only (pipeline util)", "advanced", 2},
		{"Arjun", "external param discovery (binary or embedded)", "advanced", 2},
		{"Paramspider", "external param mining (binary or embedded)", "advanced", 2},
		{"X8", "external hidden-param discovery, needs wordlist", "advanced", 2},
		{"Kiterunner", "external API routes brute, needs wordlist", "advanced", 2},
		{"Ffuf", "external fuzzer ultra, needs wordlist", "ultra", 3},
		{"Gobuster", "external dir fuzzer ultra, needs wordlist", "ultra", 3},
		{"Feroxbuster", "external Rust fuzzer ultra, needs wordlist", "ultra", 3},
		{"Dirsearch", "external dir fuzzer ultra, needs wordlist", "ultra", 3},
		{"Wfuzz", "external fuzzer ultra, needs wordlist", "ultra", 3},
		{"Sqlmap", "external SQLi adversarial read-only flags", "ultra", 3},
		{"Ghauri", "external SQLi adversarial read-only flags", "ultra", 3},
		{"Xsstrike", "external XSS point tool (binary or embedded)", "advanced", 2},
		{"Kxss", "external reflection filter (binary or embedded)", "advanced", 2},
		{"Gxss", "external reflection checker (binary or embedded)", "advanced", 2},
		{"Crlfuzz", "external CRLF scanner (binary or embedded)", "advanced", 2},
		{"Nikto", "external checks no-DoS tuning (binary or embedded)", "ultra", 3},
		{"Whatweb", "external fingerprint polite (binary or embedded)", "advanced", 2},
		{"Wafw00f", "external WAF detect (binary or embedded)", "advanced", 2},
		{"Commix", "external command-injection adversarial read-only", "ultra", 3},
		{"Tplmap", "external SSTI adversarial read-only", "ultra", 3},
		{"Sstimap", "external SSTI adversarial read-only", "ultra", 3},
		{"Ssrfmap", "manual binary; embedded active-ssrf", "ultra", 3},
		{"Nosqlmap", "manual binary; embedded active+nosqlexpand", "ultra", 3},
		{"Graphqlmap", "manual binary; embedded graphql pack", "ultra", 3},
		{"JwtTool", "manual binary; embedded jwtplus", "advanced", 2},
		{"Nomore403", "external 403-bypass pack (binary or embedded)", "advanced", 2},
		{"Oralyzer", "external open-redirect probe (binary or embedded)", "advanced", 2},
		{"Openredirex", "external open-redirect fuzz (binary or embedded)", "advanced", 2},
		{"Smuggler", "external smuggling adversarial safe-subset", "ultra", 3},
		{"Dotdotpwn", "external traversal adversarial read-only", "ultra", 3},
		{"Corsy", "external CORS scanner (binary or embedded)", "advanced", 2},
		{"Wpscan", "external WP enum keyless JSON (binary or embedded)", "advanced", 2},
		{"Cmseek", "external CMS detect (binary or embedded)", "advanced", 2},
		{"Droopescan", "external Drupal scan (binary or embedded)", "advanced", 2},
		{"Joomscan", "external Joomla scan (binary or embedded)", "advanced", 2},
		{"Subzy", "external takeover corroboration (binary or embedded)", "advanced", 2},
		{"Subjack", "external takeover corroboration (binary or embedded)", "advanced", 2},
		{"Gitleaks", "external secret scan (binary needs code; embedded remote)", "advanced", 2},
		{"Trufflehog", "external secret scan (binary needs code; embedded remote)", "advanced", 2},
		{"Noseyparker", "external secret scan (binary needs code; embedded remote)", "advanced", 2},
		{"Jsluice", "JS URL + secret harvest (native port; binary archived upstream)", "advanced", 2},
		{"Subjs", "external JS collect (binary or embedded)", "advanced", 2},
		{"Secretfinder", "external JS secret regex (binary or embedded)", "advanced", 2},
		{"Linkfinder", "external JS endpoint extract (binary or embedded)", "advanced", 2},
		{"GitDumper", "external git dump adversarial-gated", "ultra", 3},
		{"Gitjacker", "external git dump adversarial-gated", "ultra", 3},
		{"Nmap", "external -sV default (binary or embedded portscan)", "ultra", 3},
		{"Masscan", "external rate-capped port scan (binary or embedded)", "ultra", 3},
		{"Rustscan", "external port triage (binary or embedded)", "ultra", 3},
		{"Gowitness", "external screenshots, chrome-dependent", "ultra", 3},
		{"Aquatone", "external screenshots, chrome-dependent", "ultra", 3},
		{"Socialhunter", "manual binary; embedded social+emailharv", "advanced", 2},
		{"Semgrep", "external SAST (binary needs code; embedded remote)", "advanced", 2},
		{"Trivy", "external vuln scan (binary needs code; embedded remote)", "advanced", 2},
		{"OsvScanner", "external SCA via OSV (binary needs code; embedded remote)", "advanced", 2},
		{"Grype", "external vuln scan (binary needs code; embedded remote)", "advanced", 2},
		{"Searchsploit", "local exploit-db mapping only, per technology", "safe", 1},
		{"Mobsf", "mobile static via operator server (ANPU_APK), never dynamic", "ultra", 3},
		// Wave 3 — keyless feeds & wordlists (live).
		{"EPSS", "FIRST exploit-probability scoring (ANPU_EPSS=1 for live)", "safe", 1},
		{"KEV", "CISA exploited-in-wild flag (anpu feeds update)", "safe", 1},
		{"AdvisoryDB", "GitHub Advisory REST keyless notes", "safe", 1},
		{"OSVPlus", "OSV Rust/RubyGems + Cargo/Gemfile lock harvest", "safe", 1},
		{"URLhaus", "URLhaus+ThreatFox reputation (anpu feeds check)", "safe", 1},
		{"PhishTank", "excluded: API needs a key (keyless-only policy)", "safe", 1},
		{"SecLists", "vendored subsets offline (wordlists/)", "safe", 1},
		{"PayloadPacks", "in-code reviewed packs (no vendored exploits)", "safe", 1},
		{"NucleiTags", "nuclei-templates tag-scoped runs (existing flags)", "advanced", 2},
		{"WordlistsUpdate", "anpu wordlists update (opt-in refresh)", "safe", 1},
		// Wave 4 — workflow (live).
		{"ToolsInstall", "managed installer (install | --all --yes) + --auto-install", "safe", 1},
		{"Query", "anpu query finding filter", "safe", 1},
		{"Import", "anpu import Burp/ZAP/HAR", "safe", 1},
		{"Notify", "notify fan-out Slack/Discord/Telegram (watch flags)", "safe", 1},
		{"Export", "CSV/Markdown export (show --format csv|md)", "safe", 1},
		{"ScopeGuard", "scope allowlist hard-stop (--scope-file)", "safe", 1},
		{"BudgetLedger", "global per-tool budget ledger (wired, hiddenparams capped)", "safe", 1},
		{"DriftMonitor", "baseline drift with parser pins (anpu drift)", "advanced", 2},
	}
}

func newSearchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "search [query]",
		Short: "Find a security tool by name or keyword",
		Long: `Search ranked tools. Each tool has its own --enable/--disable/--only name.

Levels: safe (1, passive), advanced (2, polite active), ultra (3, intrusive)

Examples:
  anpu search dns
  anpu search cloud
  anpu search --level ultra
  anpu search --level safe
  anpu tools   # full ranked list`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			levelFilter, _ := cmd.Flags().GetString("level")
			query := ""
			if len(args) > 0 {
				query = strings.ToLower(strings.TrimSpace(args[0]))
			}
			levelFilter = strings.ToLower(strings.TrimSpace(levelFilter))
			tools := allToolsRanked()
			// sort by rank then name
			sort.Slice(tools, func(i, j int) bool {
				if tools[i].Rank != tools[j].Rank {
					return tools[i].Rank < tools[j].Rank
				}
				return tools[i].Name < tools[j].Name
			})
			// filter
			var filtered []toolInfo
			for _, t := range tools {
				if levelFilter != "" && !strings.EqualFold(t.Level, levelFilter) && !strings.HasPrefix(strings.ToLower(t.Level), levelFilter) {
					continue
				}
				if query != "" {
					q := query
					if !strings.Contains(strings.ToLower(t.Name), q) && !strings.Contains(strings.ToLower(t.Desc), q) && !strings.Contains(strings.ToLower(t.Level), q) {
						continue
					}
				}
				filtered = append(filtered, t)
			}
			if len(filtered) == 0 {
				fmt.Println("No tools match. Try: anpu search dns  |  anpu search --level safe  |  anpu tools")
				return nil
			}
			// Header
			fmt.Printf("%-12s %-8s  %s\n", "TOOL", "LEVEL", "DESCRIPTION")
			fmt.Printf("%-12s %-8s  %s\n", strings.Repeat("─", 12), strings.Repeat("─", 8), strings.Repeat("─", 40))
			for _, t := range filtered {
				rankSym := map[int]string{1: "○", 2: "◐", 3: "●"}[t.Rank]
				fmt.Printf("%-12s %-8s  %s %s\n", t.Name, t.Level+" "+rankSym, t.Desc, "")
			}
			fmt.Printf("\nRun single: anpu scan --only %s https://target.com  |  anpu safe https://target.com\n", strings.ToLower(filtered[0].Name))
			if len(filtered) > 1 {
				fmt.Printf("Disable: anpu scan --disable %s https://target.com\n", strings.Join([]string{strings.ToLower(filtered[0].Name), strings.ToLower(filtered[1].Name)}, ","))
			}
			return nil
		},
	}
	cmd.Flags().String("level", "", "filter by level: safe, advanced, ultra")
	return cmd
}
