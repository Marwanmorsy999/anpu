// Package integrations — registry.go: install recipes for every optional
// external binary ANPU can orchestrate (Wave 2 catalog, items 51-134).
//
// The registry is data only: it never executes anything. The `anpu tools
// install <name>` command prints the recipe; absence of a binary always
// degrades to warn-and-skip, never a fatal error (see common.go).
//
// FREE-ONLY, KEYLESS-ONLY: every recipe installs the free edition and
// every wrapper runs without credentials. Anything needing an API key
// is excluded by policy (Chaos, SecurityTrails, Censys, VirusTotal,
// Shodan-keyed, FOFA, ZoomEye, Hunter.how, BinaryEdge, Netlas,
// LeakIX-keyed, BuiltWith, Wappalyzer API, Hunter.io, Farsight,
// DeHashed, Vulners, AbuseIPDB-keyed, GreyNoise-keyed, Safe-Browsing).
//
// Ethos exclusions (never added): hydra/ncrack, Metasploit, DoS tunings.
package integrations

import (
	"fmt"
	"sort"
	"strings"
)

// Level mirrors the search rank: safe=1 passive, advanced=2 polite
// active, ultra=3 intrusive/noisy.
const (
	LevelSafe     = "safe"
	LevelAdvanced = "advanced"
	LevelUltra    = "ultra"
)

// Recipe describes how to install and run one optional external tool.
type Recipe struct {
	// Name is the canonical toggle/search name (lowercase, no spaces).
	Name string
	// Binary is the executable resolved via findExecutable.
	Binary string
	// Level gates the default profile (noisy→ultra, polite→advanced).
	Level string
	// GoInstall is a `go install <mod>@latest` path (Go tools only).
	GoInstall string
	// Pipx is a `pipx install <pkg>` spec (Python tools only).
	Pipx string
	// Apt is a `apt install <pkg>` name (Debian/Kali only).
	Apt string
	// Choco is a `choco install <pkg>` name (Windows only).
	Choco string
	// Docker notes a Docker-gated tool (ZAP, MobSF).
	Docker string
	// Manual points at upstream docs when no one-liner install exists.
	Manual string
	// Adversarial marks state-touching or exfil-capable tools that must
	// run only behind --adversarial --confirm-authorized (git-dumper
	// dump mode, commix, sqlmap intrusive flags, smuggler, mobsf dynamic).
	Adversarial bool
	// Notes carries safety tuning (e.g. "nikto: no-DoS tuning").
	Notes string
}

// registryList holds the full Wave 2 free-binary catalog; entries with
// no automated recipe carry Manual guidance instead of a guessed URL.
var registryList = []Recipe{
	// Recon / subdomains (11) — advanced, passive/keyless.
	{"amass", "amass", LevelAdvanced, "github.com/owasp-amass/amass/v4/cmd/amass@latest", "", "amass", "", "", "", false, "passive enum only (-passive); keyless data sources"},
	{"assetfinder", "assetfinder", LevelAdvanced, "github.com/tomnomnom/assetfinder@latest", "", "", "", "", "", false, "passive subdomain discovery"},
	{"findomain", "findomain", LevelAdvanced, "", "", "", "findomain", "", "https://github.com/Findomain/Findomain/releases", false, "prebuilt binary; keyless sources"},
	{"shuffledns", "shuffledns", LevelAdvanced, "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest", "", "", "", "", "", false, "needs resolver file; massdns-backed"},
	{"puredns", "puredns", LevelAdvanced, "github.com/d3mondev/puredns/v2@latest", "", "", "", "", "", false, "needs resolver file"},
	{"massdns", "massdns", LevelAdvanced, "", "", "massdns", "massdns", "", "", false, "C resolver; build from source on Windows"},
	{"dnsgen", "dnsgen", LevelAdvanced, "", "dnsgen", "", "", "", "", false, "permutation generator (offline)"},
	{"alterx", "alterx", LevelAdvanced, "github.com/projectdiscovery/alterx/cmd/alterx@latest", "", "", "", "", "", false, "offline subdomain permutation"},
	{"gotator", "gotator", LevelAdvanced, "github.com/Josue87/gotator@latest", "", "", "", "", "", false, "offline permutation (stdin wordlist)"},
	{"dnsrecon", "dnsrecon", LevelAdvanced, "", "dnsrecon", "dnsrecon", "", "", "", false, "DNS enumeration scripts"},
	{"metabigor", "metabigor", LevelAdvanced, "github.com/j3ssie/metabigor@latest", "", "", "", "", "", false, "passive intel (keyless sources only)"},
	// Probe / fingerprint (6) — advanced.
	{"tlsx", "tlsx", LevelAdvanced, "github.com/projectdiscovery/tlsx/cmd/tlsx@latest", "", "", "", "", "", false, "TLS probe"},
	{"cdncheck", "cdncheck", LevelAdvanced, "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest", "", "", "", "", "", false, "CDN detection"},
	{"asnmap", "asnmap", LevelAdvanced, "github.com/projectdiscovery/asnmap/cmd/asnmap@latest", "", "", "", "", "", false, "ASN lookup (keyless)"},
	{"webanalyze", "webanalyze", LevelAdvanced, "github.com/rverton/webanalyze/cmd/webanalyze@latest", "", "", "", "", "", false, "tech fingerprint (update -update first)"},
	{"csprecon", "csprecon", LevelAdvanced, "github.com/edoardottt/csprecon/cmd/csprecon@latest", "", "", "", "", "", false, "CSP subdomain recon"},
	{"hakoriginfinder", "hakoriginfinder", LevelAdvanced, "github.com/hakluke/hakoriginfinder@latest", "", "", "", "", "", false, "origin discovery helper"},
	// Crawl / URL / params (13) — advanced (active polite).
	{"gau", "gau", LevelAdvanced, "github.com/lc/gau/v2/cmd/gau@latest", "", "", "", "", "", false, "archive URLs (keyless)"},
	{"waybackurls", "waybackurls", LevelAdvanced, "github.com/tomnomnom/waybackurls@latest", "", "", "", "", "", false, "wayback corpus (keyless)"},
	{"hakrawler", "hakrawler", LevelAdvanced, "github.com/hakluke/hakrawler@latest", "", "", "", "", "", false, "crawler"},
	{"gospider", "gospider", LevelAdvanced, "github.com/jaeles-project/gospider@latest", "", "", "", "", "", false, "crawler"},
	{"cariddi", "cariddi", LevelAdvanced, "github.com/edoardottt/cariddi/cmd/cariddi@latest", "", "", "", "", "", false, "crawler + endpoint secrets"},
	{"unfurl", "unfurl", LevelAdvanced, "github.com/tomnomnom/unfurl@latest", "", "", "", "", "", false, "URL parser (offline)"},
	{"uro", "uro", LevelAdvanced, "", "uro", "", "", "", "", false, "Python via pipx (pipx install uro)"},
	{"qsreplace", "qsreplace", LevelAdvanced, "github.com/tomnomnom/qsreplace@latest", "", "", "", "", "", false, "query replacement (offline)"},
	{"anew", "anew", LevelAdvanced, "github.com/tomnomnom/anew@latest", "", "", "", "", "", false, "dedup append (offline)"},
	{"arjun", "arjun", LevelAdvanced, "", "arjun", "", "", "", "", false, "param discovery (bounded threads)"},
	{"paramspider", "paramspider", LevelAdvanced, "", "", "", "", "", "https://github.com/devanshbatham/ParamSpider (no PyPI entry point — clone and run python3 -m paramspider.main)", false, "param mining via archives"},
	{"x8", "x8", LevelAdvanced, "", "", "", "", "", "https://github.com/Sh1Yo/x8/releases", false, "hidden-param discovery (bounded)"},
	{"kiterunner", "kiterunner", LevelAdvanced, "", "", "", "", "", "https://github.com/assetnote/kiterunner (prebuilt)", false, "API routes brute (bounded wordlist)"},
	// Content fuzz (5) — ultra (noisy).
	{"ffuf", "ffuf", LevelUltra, "github.com/ffuf/ffuf/v2@latest", "", "ffuf", "ffuf", "", "", false, "fuzzer: bounded wordlist + rate limit"},
	{"gobuster", "gobuster", LevelUltra, "github.com/OJ/gobuster/v3@latest", "", "gobuster", "gobuster", "", "", false, "dir fuzzer: bounded wordlist"},
	{"feroxbuster", "feroxbuster", LevelUltra, "", "", "", "", "", "https://github.com/epi052/feroxbuster/releases", false, "Rust fuzzer: bounded + auto-tune off"},
	{"dirsearch", "dirsearch", LevelUltra, "", "dirsearch", "", "", "", "", false, "dir fuzzer: bounded wordlist"},
	{"wfuzz", "wfuzz", LevelUltra, "", "wfuzz", "wfuzz", "", "", "https://github.com/xmendez/wfuzz (pycurl pin unbuildable on Python 3.12+ — needs Python <=3.11 to install)", false, "fuzzer: bounded payload set"},
	// Vuln point-tools (22). Intrusive/read-only flags forced in wrapper
	// args; Adversarial ones additionally gated.
	{"sqlmap", "sqlmap", LevelUltra, "", "", "sqlmap", "", "", "https://github.com/sqlmapproject/sqlmap (PyPI 1.10.x wheel has no working entry point — clone and run sqlmap.py; Windows Defender may quarantine it without an exclusion)", true, "read-only flags forced (--batch --level=1 --risk=1, no --os-shell/--dump-all)"},
	{"ghauri", "ghauri", LevelUltra, "", "git+https://github.com/r0oth3x49/ghauri.git", "", "", "", "https://github.com/r0oth3x49/ghauri (not on PyPI — installed from git)", true, "read-only flags forced (--batch, no --dump-all)"},
	{"xsstrike", "xsstrike", LevelAdvanced, "", "xsstrike", "", "", "", "https://github.com/s0md3v/XSStrike (non-interactive: --skip --skip-dom)", false, "XSS point tool (crawl-only + blind off by default)"},
	{"kxss", "kxss", LevelAdvanced, "github.com/Emoe/kxss@latest", "", "", "", "", "", false, "reflected-param filter (stdin)"},
	{"gxss", "gxss", LevelAdvanced, "github.com/KathanP19/Gxss@latest", "", "", "", "", "", false, "reflection checker (stdin)"},
	{"crlfuzz", "crlfuzz", LevelAdvanced, "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest", "", "", "", "", "", false, "CRLF scanner"},
	{"nikto", "nikto", LevelUltra, "", "", "nikto", "nikto", "", "", false, "no-DoS tuning (-Tuning x to skip DoS checks)"},
	{"whatweb", "whatweb", LevelAdvanced, "", "", "whatweb", "", "", "", false, "fingerprint (polite, --max-redirects bounded)"},
	{"wafw00f", "wafw00f", LevelAdvanced, "", "wafw00f", "wafw00f", "", "", "", false, "WAF detect (few requests)"},
	{"commix", "commix", LevelUltra, "", "", "", "", "", "https://github.com/commixproject/commix (the PyPI 'commix' package is an unrelated stub — clone and run commix.py)", true, "read-only eval only; no os-shell"},
	{"tplmap", "tplmap", LevelUltra, "", "", "", "", "", "https://github.com/epi052/tplmap is gone — use the sstimap fork (python3 sstimap.py)", true, "read-only SSTI confirm only"},
	{"sstimap", "sstimap", LevelUltra, "", "", "", "", "", "https://github.com/vladko312/sstimap (no PyPI entry point — clone and run python3 sstimap.py)", true, "read-only SSTI confirm only"},
	{"ssrfmap", "ssrfmap", LevelUltra, "", "", "", "", "", "https://github.com/swisskyrepo/SSRFmap (python)", true, "read-only SSRF confirm; analyst-owned callback only"},
	{"nosqlmap", "nosqlmap", LevelUltra, "", "", "", "", "", "https://github.com/codingo/NoSQLMap (python)", true, "read-only NoSQL confirm"},
	{"graphqlmap", "graphqlmap", LevelUltra, "", "", "", "", "", "https://github.com/swisskyrepo/GraphQLmap (no PyPI entry point — clone and run bin/graphqlmap)", false, "GraphQL enum (introspection-gated)"},
	{"jwt_tool", "jwt_tool", LevelAdvanced, "", "", "", "", "", "https://github.com/ticarpi/jwt_tool (python3 jwt_tool.py)", false, "JWT checks (offline, local key confusion only with consent)"},
	{"nomore403", "nomore403", LevelAdvanced, "", "", "", "", "", "https://github.com/devanshbatham/NoMore403 is gone — vendored techniques live in ANPU's native ForbiddenBypass/VerbTamper", false, "403-bypass technique pack (bounded)"},
	{"oralyzer", "oralyzer", LevelAdvanced, "", "git+https://github.com/r0075h3ll/Oralyzer.git", "", "", "", "https://github.com/r0075h3ll/Oralyzer (not on PyPI — installed from git)", false, "open-redirect fuzz (bounded payloads)"},
	{"openredirex", "openredirex", LevelAdvanced, "", "", "", "", "", "https://github.com/devanshbatham/openredirex (Python, not Go — clone and run python3 openredirex.py; pip install aiohttp tqdm first)", false, "open-redirect probe (stdin URLs, -c 10 bounded; pip install aiohttp tqdm first)"},
	{"smuggler", "smuggler", LevelUltra, "", "", "", "", "", "https://github.com/defparam/smuggler (python3 smuggler.py)", true, "safe-subset only (CL.TE/TE.CL time-diff); adversarial gate"},
	{"dotdotpwn", "dotdotpwn", LevelUltra, "", "", "dotdotpwn", "", "", "", true, "read-only traversal confirm; adversarial gate"},
	{"corsy", "corsy", LevelAdvanced, "", "", "", "", "", "https://github.com/s0md3v/Corsy (no PyPI entry point — clone and run python3 corsy.py with PYTHONUTF8=1 on Windows)", false, "CORS misconfig scanner"},
	// CMS (4) — advanced; wpscan enum keyless (DB notes token-optional).
	{"wpscan", "wpscan", LevelAdvanced, "", "", "", "wpscan", "", "https://wpscan.com (docker: wpscanteam/wpscan)", false, "enum keyless (--enumerate vp,vt --random-user-agent); vuln DB notes token-optional"},
	{"cmseek", "cmseek", LevelAdvanced, "", "", "", "", "", "https://github.com/Tuhinshubhra/CMSeeK (python3 cmseek.py)", false, "CMS detect"},
	{"droopescan", "droopescan", LevelAdvanced, "", "droopescan", "", "", "", "", false, "Drupal/Silverstripe scan"},
	{"joomscan", "joomscan", LevelAdvanced, "", "", "joomscan", "", "", "", false, "Joomla scan"},
	// Takeover corroboration (2) — advanced.
	{"subzy", "subzy", LevelAdvanced, "github.com/PentestPad/subzy@latest", "", "", "", "", "", false, "takeover corroboration (fingerprint match)"},
	{"subjack", "subjack", LevelAdvanced, "github.com/haccer/subjack@latest", "", "", "", "", "", false, "takeover corroboration (fingerprint match)"},
	// Secrets / JS (7) — advanced; local modes only (no cloud exfil).
	{"gitleaks", "gitleaks", LevelAdvanced, "github.com/zricethezav/gitleaks/v8@latest", "", "", "gitleaks", "", "", false, "local repo/filesystem scan only"},
	{"trufflehog", "trufflehog", LevelAdvanced, "", "", "", "", "", "https://github.com/trufflesecurity/trufflehog/releases (go install unsupported: replace directives — use the prebuilt archive)", false, "local filesystem/git scan only (no --only-verified exfil)"},
	{"noseyparker", "noseyparker", LevelAdvanced, "", "", "", "", "", "https://github.com/praetorian-inc/noseyparker/releases", false, "local secret scan"},
	{"jsluice", "jsluice", LevelAdvanced, "", "", "", "", "", "https://github.com/BishopFox/jsluice (no Windows prebuilt; go build fails on Go 1.24+ — archived upstream)", false, "JS endpoint/secret extract (offline)"},
	{"subjs", "subjs", LevelAdvanced, "github.com/lc/subjs@latest", "", "", "", "", "", false, "JS URL collect (stdin)"},
	{"secretfinder", "secretfinder", LevelAdvanced, "", "", "", "", "", "https://github.com/m4ll0k/SecretFinder (python3 SecretFinder.py)", false, "JS secret regex (offline)"},
	{"linkfinder", "linkfinder", LevelAdvanced, "", "", "", "", "", "https://github.com/GerbenJavado/LinkFinder (no PyPI entry point — clone and run python3 linkfinder.py; needs jsbeautifier)", false, "JS endpoint extract (offline)"},
	// Git exposure (2) — adversarial (dump = state-touching read of history).
	{"git-dumper", "git-dumper", LevelUltra, "", "git-dumper", "", "", "", "", true, "dump mode only under --adversarial --confirm-authorized; detection-only otherwise"},
	{"gitjacker", "gitjacker", LevelUltra, "github.com/liamg/gitjacker/cmd/gitjacker@latest", "", "", "", "", "", true, "dump mode only under --adversarial --confirm-authorized"},
	// Network (3) — ultra; root fallbacks noted.
	{"nmap", "nmap", LevelUltra, "", "", "nmap", "nmap", "", "", false, "default -sV (no -O without root; no DoS scripts)"},
	{"masscan", "masscan", LevelUltra, "", "", "masscan", "", "", "", false, "needs root for raw sockets; rate-capped (--rate 1000)"},
	{"rustscan", "rustscan", LevelUltra, "", "", "", "", "", "https://github.com/RustScan/RustScan/releases", false, "fast port triage; needs root for SYN on Linux"},
	// Screenshots (2) — ultra; headless-chrome dependency noted.
	{"gowitness", "gowitness", LevelUltra, "github.com/sensepost/gowitness@latest", "", "", "", "", "", false, "screenshots (needs headless chrome)"},
	{"aquatone", "aquatone", LevelUltra, "", "", "", "", "", "https://github.com/michenriksen/aquatone/releases", false, "screenshots (needs headless chrome)"},
	// Social (1) — advanced.
	{"socialhunter", "socialhunter", LevelAdvanced, "", "", "", "", "", "https://github.com/utkusen/socialhunter (python)", false, "social surface enum (keyless)"},
	// Code scope SAST/SCA (4) — local, safe to run on owned code.
	{"semgrep", "semgrep", LevelAdvanced, "", "semgrep", "", "", "", "https://semgrep.dev/docs/getting-started (pipx/binary)", false, "SAST on local code (free rulesets)"},
	{"trivy", "trivy", LevelAdvanced, "", "", "", "trivy", "", "https://github.com/aquasecurity/trivy/releases", false, "vuln scan fs/repo (local DB)"},
	{"osv-scanner", "osv-scanner", LevelAdvanced, "github.com/google/osv-scanner/cmd/osv-scanner@v1", "", "", "", "", "", false, "SCA via OSV (keyless)"},
	{"grype", "grype", LevelAdvanced, "", "", "", "grype", "", "https://github.com/anchore/grype/releases", false, "vuln scan dir (local DB)"},
	// Exploit correlation (1) — safe, local clone, mapping only.
	{"searchsploit", "searchsploit", LevelSafe, "", "", "", "", "", "https://gitlab.com/exploit-database/exploitdb (clone to ~/.exploitdb; Windows runs it via Git-bash shim)", false, "local exploit-db clone; mapping only, no exploit run"},
	// Mobile (1) — ultra, docker-gated like ZAP; static first.
	{"mobsf", "mobsf", LevelUltra, "", "", "", "", "opensecurity/mobile-security-framework-mobsf:latest", "https://github.com/MobSF/Mobile-Security-Framework-MobSF", true, "static analysis first; dynamic only with explicit consent"},
}

// Registry maps canonical tool name → install recipe.
var Registry = func() map[string]Recipe {
	m := make(map[string]Recipe, len(registryList))
	for _, r := range registryList {
		m[r.Name] = r
	}
	return m
}()

// Get returns the recipe for name (case-insensitive) or false.
func Get(name string) (Recipe, bool) {
	r, ok := Registry[strings.ToLower(strings.TrimSpace(name))]
	return r, ok
}

// All returns all recipes sorted by name for stable CLI output.
func All() []Recipe {
	out := make([]Recipe, 0, len(Registry))
	for _, r := range Registry {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Names returns all canonical tool names sorted.
func Names() []string {
	all := All()
	names := make([]string, 0, len(all))
	for _, r := range all {
		names = append(names, r.Name)
	}
	return names
}

// InstallHint renders a copy-paste install recipe for the current OS.
func InstallHint(r Recipe, goos string) string {
	var parts []string
	if r.GoInstall != "" {
		parts = append(parts, "go install -v "+r.GoInstall)
	}
	if r.Pipx != "" {
		parts = append(parts, "pipx install "+r.Pipx)
	}
	if r.Apt != "" && (goos == "linux" || goos == "") {
		parts = append(parts, "sudo apt install -y "+r.Apt)
	}
	if r.Choco != "" && (goos == "windows" || goos == "") {
		parts = append(parts, "choco install -y "+r.Choco)
	}
	if r.Docker != "" {
		parts = append(parts, "docker pull "+r.Docker)
	}
	if r.Manual != "" {
		parts = append(parts, "manual: "+r.Manual)
	}
	if len(parts) == 0 {
		return "no automated install recipe — see upstream README for " + r.Name
	}
	return joinLines(parts)
}

func joinLines(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "\n               install: "
		}
		out += p
	}
	return out
}

// FormatRecipe renders one recipe block for `anpu tools install <name>`.
func FormatRecipe(r Recipe, goos string) string {
	var b strings.Builder
	_, _ = fmt.Fprintf(&b, "%s (binary: %s, level: %s)\n", r.Name, r.Binary, r.Level)
	b.WriteString("  install: " + InstallHint(r, goos) + "\n")
	if r.Adversarial {
		b.WriteString("  gate: requires --adversarial --confirm-authorized (state-touching/exfil-capable)\n")
	}
	if r.Notes != "" {
		b.WriteString("  notes: " + r.Notes + "\n")
	}
	return b.String()
}
