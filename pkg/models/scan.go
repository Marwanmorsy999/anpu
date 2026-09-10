package models

import (
	"strings"
	"time"
)

// normalizeForDedup lowercases and trims a string so that superficially
// different but semantically equal values (trailing slash, case, etc.)
// hash to the same dedup key.
func normalizeForDedup(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, "/")
	return s
}

// Profile is a named scan intensity level.
type Profile string

const (
	ProfileSafe     Profile = "safe"
	ProfileStandard Profile = "standard"
	ProfileDeep     Profile = "deep"
	ProfileAdvanced Profile = "advanced"
	ProfileUltra    Profile = "ultra"
)

// Valid reports whether p is a recognized profile name.
func (p Profile) Valid() bool {
	switch p {
	case ProfileSafe, ProfileStandard, ProfileDeep, ProfileAdvanced, ProfileUltra:
		return true
	}
	return false
}

// Normalize canonicalizes profile aliases: standard→advanced, deep→ultra.
func (p Profile) Normalize() Profile {
	switch p {
	case ProfileStandard:
		return ProfileAdvanced
	case ProfileDeep:
		return ProfileUltra
	default:
		return p
	}
}

// Technology represents a detected piece of the target's stack.
type Technology struct {
	Name       string   `json:"name"`
	Category   string   `json:"category"` // web-server, framework, cms, cdn, js-framework, backend, other
	Version    string   `json:"version,omitempty"`
	Confidence float64  `json:"confidence"` // 0.0 - 1.0
	Evidence   Evidence `json:"evidence"`
}

// EndpointCategory buckets a discovered endpoint by apparent purpose.
type EndpointCategory string

const (
	EndpointPage      EndpointCategory = "page"
	EndpointAPI       EndpointCategory = "api"
	EndpointAsset     EndpointCategory = "asset"
	EndpointAuth      EndpointCategory = "authentication"
	EndpointAdminLike EndpointCategory = "admin-like"
	EndpointUnknown   EndpointCategory = "unknown"
)

// Endpoint is a normalized, deduplicated URL discovered during recon.
type Endpoint struct {
	URL      string           `json:"url"`
	Method   string           `json:"method,omitempty"` // known only when observed (e.g. form method)
	Category EndpointCategory `json:"category"`
	Sources  []string         `json:"sources"` // e.g. ["html-link", "robots.txt", "javascript"]
	// Params carries schema-declared API parameters (OpenAPI/GraphQL) so
	// the active engine can build body/header vectors. Empty for
	// crawler-discovered endpoints.
	Params []APIParam `json:"params,omitempty"`
}

// ScanConfig captures the resolved options for a single scan run.
type ScanConfig struct {
	Target       string
	Profile      Profile
	OutputDir    string
	JSON         bool
	HTML         bool
	SARIF        bool
	NoZAP        bool
	Verbose      bool
	Quiet        bool // suppress info-severity findings from terminal output
	SkipPreCheck bool
	Modules      ModuleConfig

	// MinConfidence is the lowest confidence level that passes the filter.
	// Findings below this level are excluded from reports and CI gates.
	// An empty value disables the filter (all findings pass).
	MinConfidence Confidence

	// RateLimit is the maximum requests per second across all stages (0 = unlimited).
	RateLimit float64
	// RequestDelay is a fixed inter-request sleep added after every HTTP request.
	RequestDelay time.Duration

	// Auth is the credential context for this scan.  An empty AuthContext
	// (Method == AuthMethodNone) means the scan runs anonymously.
	// Authentication is always opt-in — this field is never populated
	// from environment variables or implicit sources.
	Auth AuthContext
}

// ModuleConfig toggles individual pipeline stages, mirroring the
// `modules:` section of the YAML config file.
type ModuleConfig struct {
	Recon      bool
	Technology bool
	TLS        bool
	Headers    bool
	Cookies    bool
	Endpoints  bool
	Subdomains bool
	// Takeover enables Phase 11B subdomain takeover detection.
	// Runs after Subdomains; requires Subdomains to be enabled to produce findings.
	Takeover bool
	PortScan bool
	Dirs     bool
	Secrets  bool
	CORS     bool
	Methods  bool
	// CSRF enables the Phase 10A CSRF token detection scanner.
	// Only available on Standard and Deep profiles.
	CSRF bool
	// Deps enables the Phase 10B dependency vulnerability scanner.
	// Only available on Standard and Deep profiles.
	Deps bool
	// SRI enables the Phase 12C Subresource Integrity passive check.
	// Enabled on all profiles (Safe, Standard, Deep) — passive, zero extra
	// HTTP cost beyond the page fetches already performed by other stages.
	SRI bool
	// Backup enables the Phase 12E backup file discovery scanner.
	// Enabled on Standard and Deep profiles; disabled on Safe (active probing).
	Backup bool
	// Active enables the Phase 4 safe active testing engine.
	// Only available on Standard and Deep profiles.
	Active bool
	Nuclei bool
	ZAP    bool
	// Katana enables the optional katana crawl integration (active
	// crawling by an external binary). Standard and Deep only.
	Katana bool
	// Httpx enables the optional httpx probe integration
	// (technology/status corroboration). Standard and Deep only.
	Httpx bool
	// Subfinder enables the optional subfinder passive-subdomain
	// integration. Standard and Deep only.
	Subfinder bool
	// Dalfox enables the optional dalfox XSS confirmation integration
	// against discovered parameterized URLs. Standard and Deep only.
	Dalfox bool
	// DNSIntel enables passive DNS record enumeration (MX/NS/TXT/SPF/DMARC).
	// Safe for all profiles — queries archive DNS only.
	DNSIntel bool
	// IPIntel enables IP enrichment (PTR, cloud provider, ASN via Cymru DNS).
	// Safe for all profiles — passive DNS only.
	IPIntel bool
	// Naabu enables the optional naabu fast port-scan integration.
	// Deep profile by default (active); standard needs explicit enable or binary.
	Naabu bool
	// DNSx enables the optional dnsx DNS toolkit integration.
	// Standard and Deep when available.
	DNSx bool
	// RDAP enables RDAP WHOIS domain registration intel.
	// Passive, safe for all profiles.
	RDAP bool
	// Leak enables private-IP/internal-host leak detection (passive).
	// Safe for all profiles.
	Leak bool
	// Favicon enables favicon hash correlation (passive, one extra GET).
	// Safe for all profiles.
	Favicon bool
	// DoH enables DNS-over-HTTPS endpoint exposure check (passive, 2 GETs max).
	// Safe for all profiles.
	DoH bool
	// Bucket enables cloud storage bucket existence probe (S3/Azure/GCS).
	// Passive provider probes, safe for all profiles.
	Bucket bool
	// BGP enables BGP prefix and ASN enrichment via BGPView API (passive).
	// Safe for all profiles.
	BGP bool
	// API enables schema-driven API testing: auto-discovery of
	// openapi.json/swagger and GraphQL introspection at well-known
	// locations (GET-only), plus explicit --openapi/--graphql inputs.
	// Safe for all profiles.
	API bool
	// AuthZ enables authorization testing: two-identity comparison when
	// credentials are configured, anonymous forced-browsing of sensitive
	// endpoints otherwise. Safe for all profiles (GET-only).
	AuthZ bool
	// Params enables query-parameter classification (passive).
	// Safe for all profiles — runs wherever endpoint discovery runs.
	Params bool
	// Wave 1 batch 1 — passive recon engines (safe for all profiles).
	// Each is independently toggleable via --enable/--disable/--only.
	ArchiveURLs  bool
	CertSAN      bool
	EmailHarv    bool
	DNSAudit     bool
	EmailAuth    bool
	CSPRecon     bool
	SocialHijack bool
	CommentMiner bool
	BrokenLink   bool
	OriginIP     bool
	// Wave 1 batch 2 — bounded exposure probes (advanced/ultra; safe stays passive).
	ExposedGit    bool
	ExposedConfig bool
	Actuator      bool
	DebugPages    bool
	OAuthAnalyzer bool
	SAMLMetadata  bool
	CSWSH         bool
	PostMessage   bool
	JSSecrets     bool
	HiddenParams  bool
	// Wave 1 batch 3 — items 21-30. Clickjack/PolicyHeaders/CookiePrefix
	// are passive header analysis (safe-eligible); the rest are bounded
	// active probes (advanced/ultra; safe stays passive).
	VerbTamper      bool
	CacheDeception  bool
	ForbiddenBypass bool
	TakeoverPlus    bool
	Clickjack       bool
	PolicyHeaders   bool
	CookiePrefix    bool
	APIVersion      bool
	APIConsole      bool
	VHost           bool
	// Wave 1 batches 4-5 — items 31-50. JWTPlus/H2FP/GFClassify are
	// passive analysis (safe-eligible); CertHistory/SubPermute are
	// archive/DNS-only (safe-eligible); the rest are bounded active
	// probes (advanced/ultra; H2Smuggle additionally adversarial-gated).
	GraphQLFP     bool
	GraphQLSchema bool
	JWTPlus       bool
	SSTIExpand    bool
	NoSQLExpand   bool
	H2Smuggle     bool
	H2FP          bool
	RedirectPack  bool
	LFIPack       bool
	CVEPack       bool
	CORSPlus      bool
	CertHistory   bool
	AXFRPlus      bool
	SubPermute    bool
	BackupPlus    bool
	FaviconPlus   bool
	DebugMethods  bool
	EncodePoly    bool
	DiffOracle    bool
	GFClassify    bool
	// Next-wave natives (advanced/ultra; safe stays passive).
	Soap       bool
	Nsecwalk   bool
	Wafdetect  bool
	Oauthpack  bool
	Ppollute   bool
	Swscope    bool
	Timeoracle bool
	Jwtconfirm bool
	// Codesecrets scans a local checkout (ANPU_CODE_DIR) for embedded
	// secrets + IaC misconfigs. Zero target traffic — safe for all.
	Codesecrets bool
	// Wave 2 — free-binary wrappers (items 51-134). Each field carries a
	// `wrapper` tag with the registry name; reflection helpers
	// (modules_byname.go) enumerate them so --only/--enable/--disable,
	// YAML `external:`, defaults, and the pipeline stay in sync without
	// per-tool switch cases. Absent binaries warn-and-skip, never fatal.
	Amass           bool `wrapper:"amass"`
	Assetfinder     bool `wrapper:"assetfinder"`
	Findomain       bool `wrapper:"findomain"`
	Shuffledns      bool `wrapper:"shuffledns"`
	Puredns         bool `wrapper:"puredns"`
	Massdns         bool `wrapper:"massdns"`
	Dnsgen          bool `wrapper:"dnsgen"`
	Alterx          bool `wrapper:"alterx"`
	Gotator         bool `wrapper:"gotator"`
	Dnsrecon        bool `wrapper:"dnsrecon"`
	Metabigor       bool `wrapper:"metabigor"`
	Tlsx            bool `wrapper:"tlsx"`
	Cdncheck        bool `wrapper:"cdncheck"`
	Asnmap          bool `wrapper:"asnmap"`
	Webanalyze      bool `wrapper:"webanalyze"`
	CspreconExt     bool `wrapper:"cspreconext"`
	HakOriginFinder bool `wrapper:"hakoriginfinder"`
	Gau             bool `wrapper:"gau"`
	Waybackurls     bool `wrapper:"waybackurls"`
	Hakrawler       bool `wrapper:"hakrawler"`
	Gospider        bool `wrapper:"gospider"`
	Cariddi         bool `wrapper:"cariddi"`
	Unfurl          bool `wrapper:"unfurl"`
	Uro             bool `wrapper:"uro"`
	Qsreplace       bool `wrapper:"qsreplace"`
	Anew            bool `wrapper:"anew"`
	Arjun           bool `wrapper:"arjun"`
	Paramspider     bool `wrapper:"paramspider"`
	X8              bool `wrapper:"x8"`
	Kiterunner      bool `wrapper:"kiterunner"`
	Ffuf            bool `wrapper:"ffuf"`
	Gobuster        bool `wrapper:"gobuster"`
	Feroxbuster     bool `wrapper:"feroxbuster"`
	Dirsearch       bool `wrapper:"dirsearch"`
	Wfuzz           bool `wrapper:"wfuzz"`
	Sqlmap          bool `wrapper:"sqlmap"`
	Ghauri          bool `wrapper:"ghauri"`
	Xsstrike        bool `wrapper:"xsstrike"`
	Kxss            bool `wrapper:"kxss"`
	Gxss            bool `wrapper:"gxss"`
	Crlfuzz         bool `wrapper:"crlfuzz"`
	Nikto           bool `wrapper:"nikto"`
	Whatweb         bool `wrapper:"whatweb"`
	Wafw00f         bool `wrapper:"wafw00f"`
	Commix          bool `wrapper:"commix"`
	Tplmap          bool `wrapper:"tplmap"`
	Sstimap         bool `wrapper:"sstimap"`
	Ssrfmap         bool `wrapper:"ssrfmap"`
	Nosqlmap        bool `wrapper:"nosqlmap"`
	Graphqlmap      bool `wrapper:"graphqlmap"`
	JwtTool         bool `wrapper:"jwt_tool"`
	Nomore403       bool `wrapper:"nomore403"`
	Oralyzer        bool `wrapper:"oralyzer"`
	Openredirex     bool `wrapper:"openredirex"`
	Smuggler        bool `wrapper:"smuggler"`
	Dotdotpwn       bool `wrapper:"dotdotpwn"`
	Corsy           bool `wrapper:"corsy"`
	Wpscan          bool `wrapper:"wpscan"`
	Cmseek          bool `wrapper:"cmseek"`
	Droopescan      bool `wrapper:"droopescan"`
	Joomscan        bool `wrapper:"joomscan"`
	Subzy           bool `wrapper:"subzy"`
	Subjack         bool `wrapper:"subjack"`
	Gitleaks        bool `wrapper:"gitleaks"`
	Trufflehog      bool `wrapper:"trufflehog"`
	Noseyparker     bool `wrapper:"noseyparker"`
	Jsluice         bool `wrapper:"jsluice"`
	Subjs           bool `wrapper:"subjs"`
	Secretfinder    bool `wrapper:"secretfinder"`
	Linkfinder      bool `wrapper:"linkfinder"`
	GitDumper       bool `wrapper:"git-dumper"`
	Gitjacker       bool `wrapper:"gitjacker"`
	Nmap            bool `wrapper:"nmap"`
	Masscan         bool `wrapper:"masscan"`
	Rustscan        bool `wrapper:"rustscan"`
	Gowitness       bool `wrapper:"gowitness"`
	Aquatone        bool `wrapper:"aquatone"`
	Socialhunter    bool `wrapper:"socialhunter"`
	Semgrep         bool `wrapper:"semgrep"`
	Trivy           bool `wrapper:"trivy"`
	OsvScanner      bool `wrapper:"osv-scanner"`
	Grype           bool `wrapper:"grype"`
	Searchsploit    bool `wrapper:"searchsploit"`
	Mobsf           bool `wrapper:"mobsf"`
	// Adversarial enables hazardous probes (stateful, JWT/mass-assign/race/smuggling/proto-pollute, sqli boolean differential).
	// Only available via --adversarial --confirm-authorized (authorized ultra only).
	Adversarial bool `yaml:"adversarial"`
	// IDOR enables BOLA/IDOR probing (numeric id+1 replay, RequestBudget 5).
	// Read-only GETs like the Active engine: off on safe (keeps safe passive),
	// on for advanced/ultra. Independently toggleable via --enable/--disable idor.
	IDOR bool `yaml:"idor"`
}

// DefaultModuleConfig returns the module set enabled for a given profile.
// Profiles form an intensity ladder:
//
//	safe     — passive analysis only (nothing a target would notice)
//	advanced — + active but polite checks (sensitive-path probing,
//	           CORS/method audits, secrets scan of discovered assets,
//	           passive subdomain enumeration via CT logs)  [alias: standard]
//	ultra     — everything, including DNS brute-force and a TCP port
//	           scan of common ports (most intrusive)  [alias: deep]
func DefaultModuleConfig(p Profile) ModuleConfig {
	p = p.Normalize()
	mc := ModuleConfig{
		Recon:      true,
		Technology: true,
		TLS:        true,
		Headers:    true,
		Cookies:    true,
		Endpoints:  true,
		Params:     true, // passive classification — safe for all
		SRI:        true, // passive — enabled on all profiles
		DNSIntel:   true, // passive DNS — safe for all
		IPIntel:    true, // passive IP/ASN — safe for all
		RDAP:       true, // passive RDAP — safe for all (one HTTP fetch)
		Leak:       true, // passive private-IP leak — safe for all
		Favicon:    true, // passive favicon hash — safe for all
		DoH:        true, // passive DoH probe — safe for all
		Bucket:     true, // passive cloud bucket probe — safe for all
		BGP:        true, // passive BGP/RPKI — safe for all
		API:        true, // schema auto-discovery — safe for all (GET-only)
		AuthZ:      true, // comparison or anonymous forced-browsing — safe for all
		// Wave 1 batch 1 — passive recon, safe for all profiles.
		ArchiveURLs:  true,
		CertSAN:      true,
		EmailHarv:    true,
		DNSAudit:     true,
		EmailAuth:    true,
		CSPRecon:     true,
		SocialHijack: true,
		CommentMiner: true,
		BrokenLink:   true,
		OriginIP:     true,
		// Wave 1 batch 3 — passive header analysis, safe for all profiles.
		Clickjack:     true,
		PolicyHeaders: true,
		CookiePrefix:  true,
		// Wave 1 batches 4-5 — passive/archive analysis, safe for all.
		JWTPlus:     true,
		H2FP:        true,
		GFClassify:  true,
		CertHistory: true,
		SubPermute:  true,
		// Local code scope — zero target traffic, safe for all.
		Codesecrets: true,
		Nuclei:      true,
		ZAP:         false, // enabled on Ultra profile below; off for Safe/Advanced by default
	}
	if p == ProfileSafe {
		// Safe profile stays fully passive: Nuclei (which sends templated
		// requests) and every active engine are left off unless the user
		// explicitly re-enables them via config.
		mc.Nuclei = false
		applyWrapperDefaults(&mc, p)
		return mc
	}

	// advanced and ultra both run the active-but-polite engines.
	// Wave 1 batch 2 — bounded exposure probes (polite, read-only).
	mc.ExposedGit = true
	mc.ExposedConfig = true
	mc.Actuator = true
	mc.DebugPages = true
	mc.OAuthAnalyzer = true
	mc.SAMLMetadata = true
	mc.CSWSH = true
	mc.PostMessage = true
	mc.JSSecrets = true
	mc.HiddenParams = true
	// Wave 1 batch 3 — bounded active probes (advanced/ultra).
	mc.VerbTamper = true
	mc.CacheDeception = true
	mc.ForbiddenBypass = true
	mc.TakeoverPlus = true
	mc.APIVersion = true
	mc.APIConsole = true
	mc.VHost = true
	// Wave 1 batches 4-5 — bounded active probes (advanced/ultra).
	// H2Smuggle additionally requires Modules.Adversarial at runtime.
	mc.GraphQLFP = true
	mc.GraphQLSchema = true
	mc.SSTIExpand = true
	mc.NoSQLExpand = true
	mc.H2Smuggle = true
	mc.RedirectPack = true
	mc.LFIPack = true
	mc.CVEPack = true
	mc.CORSPlus = true
	mc.AXFRPlus = true
	mc.BackupPlus = true
	mc.FaviconPlus = true
	mc.DebugMethods = true
	mc.EncodePoly = true
	mc.DiffOracle = true
	// Next-wave natives — bounded active probes (advanced/ultra).
	mc.Soap = true
	mc.Nsecwalk = true
	mc.Wafdetect = true
	mc.Oauthpack = true
	mc.Ppollute = true
	mc.Swscope = true
	mc.Timeoracle = true
	mc.Jwtconfirm = true
	mc.Secrets = true
	mc.CORS = true
	mc.Methods = true
	mc.CSRF = true
	mc.Deps = true
	mc.Dirs = true
	mc.Subdomains = true
	mc.Takeover = true
	mc.Active = true // enabled on Advanced and Ultra
	mc.Backup = true // enabled on Advanced and Ultra
	mc.IDOR = true   // BOLA id+1 replay (read-only GETs, like Active); safe stays clean
	// External binaries stay off on Safe (they send active requests);
	// on Advanced/Ultra they run when installed, warn-and-skip when not.
	mc.Katana = true
	mc.Httpx = true
	mc.Subfinder = true
	mc.Dalfox = true
	mc.DNSx = true

	if p == ProfileAdvanced {
		// Advanced stops short of the intrusive engines.
		applyWrapperDefaults(&mc, p)
		return mc
	}

	// ultra: everything on.
	mc.PortScan = true
	mc.ZAP = true // Ultra profile enables ZAP (Docker or local zap.sh required)
	mc.Naabu = true
	applyWrapperDefaults(&mc, p)
	return mc
}

// ScanSummary is the top-level record of a completed (or in-progress)
// scan, as stored in SQLite and rendered in reports.
type ScanSummary struct {
	ID           string    `json:"id"`
	Target       string    `json:"target"`
	Profile      Profile   `json:"profile"`
	StartedAt    time.Time `json:"started_at"`
	CompletedAt  time.Time `json:"completed_at"`
	Status       string    `json:"status"` // running, completed, failed
	StatusReason string    `json:"status_reason,omitempty"`

	// AuthRole is the credential identity used for this scan.
	// Credential values are never stored — only the role label.
	AuthRole string `json:"auth_role,omitempty"`

	Technologies []Technology `json:"technologies"`
	Endpoints    []Endpoint   `json:"endpoints"`
	Findings     []Finding    `json:"findings"`

	// CodeFindings holds local-code-scope findings (SAST/dependency/
	// secret scans of operator-supplied local material). They are
	// scored for display but never counted, diffed, persisted to
	// history, or aggregated into RiskScore. Reports render them as
	// a clearly-labeled unscored appendix.
	CodeFindings []Finding `json:"code_findings,omitempty"`

	// PhaseTimings attributes wall time and stage counts per pipeline
	// phase (foundation → discovery → targeted → active) so reports
	// show where scan time went and the next speed pass is data-driven.
	PhaseTimings []PhaseTiming `json:"phase_timings,omitempty"`

	// SlowestStages names the top-5 slowest executed stages of this
	// run (stage wall time, slowest first). Rendered in terminal and
	// HTML next to the phase ledger.
	SlowestStages []StageTiming `json:"slowest_stages,omitempty"`

	SeverityCounts map[Severity]int `json:"severity_counts"`
	RiskScore      float64          `json:"risk_score"` // aggregate 0-10

	Warnings []string `json:"warnings,omitempty"`

	// SuppressedByConfidence is the number of findings that were removed
	// by the --min-confidence filter. They are not in Findings but are
	// counted here so the terminal summary can report them.
	SuppressedByConfidence int `json:"suppressed_by_confidence,omitempty"`
	// SuppressedByRiskAccept counts findings removed by --risk-accept.
	SuppressedByRiskAccept int `json:"suppressed_by_risk_accept,omitempty"`
}

// PhaseTiming is one pipeline phase's wall-time ledger entry.
type PhaseTiming struct {
	Phase   string  `json:"phase"`
	Seconds float64 `json:"seconds"`
	Stages  int     `json:"stages"`
}

// StageTiming is one executed stage's own wall time. The pipeline
// keeps the top-5 slowest so the next speed pass is data, not
// anecdote (concurrent stages overlap in wall time — each entry is
// the stage's own cost, not its share of the phase total).
type StageTiming struct {
	Stage   string  `json:"stage"`
	Seconds float64 `json:"seconds"`
}

// RecomputeSeverityCounts refreshes SeverityCounts from Findings.
// Findings is always target-scope (see pipeline partition), so counts
// and the aggregate risk score never include local-code results.
func (s *ScanSummary) RecomputeSeverityCounts() {
	counts := map[Severity]int{
		SeverityCritical: 0,
		SeverityHigh:     0,
		SeverityMedium:   0,
		SeverityLow:      0,
		SeverityInfo:     0,
	}
	for _, f := range s.Findings {
		counts[f.Severity]++
	}
	s.SeverityCounts = counts
}
