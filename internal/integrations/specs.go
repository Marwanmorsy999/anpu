// Package integrations — specs.go: Wave 2 invocation specs (items
// 51-134). Every spec carries the REAL CLI vector for its binary with
// read-only/bounded flags baked in. Tools whose flags ANPU cannot state
// with confidence carry no Args (install-only: `tools install` still
// works; the pipeline skips with a pointer to upstream docs).
//
// Conventions: {target} full URL, {host} hostname, {paramurl} first
// parameterized endpoint, {wordlist} ANPU_WORDLIST or bundled default,
// {resolvers} ANPU_RESOLVERS, {targetsfile} temp subdomain list,
// {tmpdir} temp dir, {codedir} ANPU_CODE_DIR, {apk} ANPU_APK,
// {term} technology term (PerTech).
package integrations

import "strings"

// S builds a spec with label defaulting to title-cased name.
func spec(name string, args ...string) *ToolSpec {
	return &ToolSpec{Name: name, Binary: name, Args: args}
}

func (s *ToolSpec) label(l string) *ToolSpec  { s.Label = l; return s }
func (s *ToolSpec) toggle(t string) *ToolSpec { s.Toggle = t; return s }
func (s *ToolSpec) binary(b string) *ToolSpec { s.Binary = b; return s }
func (s *ToolSpec) stdin(m string) *ToolSpec  { s.Stdin = m; return s }
func (s *ToolSpec) timeout(n int) *ToolSpec   { s.TimeoutSec = n; return s }
func (s *ToolSpec) json() *ToolSpec           { s.JSON = true; return s }
func (s *ToolSpec) hosts() *ToolSpec          { s.MineHosts = true; return s }
func (s *ToolSpec) verify() *ToolSpec         { s.VerifyDNS = true; return s }
func (s *ToolSpec) wordlist(def string) *ToolSpec {
	s.RequiresWordlist = true
	s.DefaultWordlist = def
	return s
}
func (s *ToolSpec) resolvers() *ToolSpec      { s.RequiresResolvers = true; return s }
func (s *ToolSpec) codedir() *ToolSpec        { s.RequiresCodeDir = true; return s }
func (s *ToolSpec) apk() *ToolSpec            { s.RequiresAPK = true; return s }
func (s *ToolSpec) perTech() *ToolSpec        { s.PerTech = true; return s }
func (s *ToolSpec) targetsFile() *ToolSpec    { s.TargetsFile = true; return s }
func (s *ToolSpec) urlsFile() *ToolSpec       { s.UrlsFile = true; return s }
func (s *ToolSpec) paramURL() *ToolSpec       { s.ParamURL = true; return s }
func (s *ToolSpec) requiresParams() *ToolSpec { s.RequiresParams = true; return s }
func (s *ToolSpec) tmpDir() *ToolSpec         { s.TmpDir = true; return s }
func (s *ToolSpec) adversarial() *ToolSpec    { s.Adversarial = true; return s }
func (s *ToolSpec) unsafeArgs(args ...string) *ToolSpec {
	s.UnsafeArgs = args
	return s
}
func (s *ToolSpec) noStage() *ToolSpec       { s.NoStage = true; return s }
func (s *ToolSpec) level(l string) *ToolSpec { s.Level = l; return s }

// ToolSpecs returns all 84 Wave 2 specs in registry order.
func ToolSpecs() []*ToolSpec {
	return []*ToolSpec{
		// Recon / subdomains (11) — advanced.
		spec("amass", "enum", "-passive", "-d", "{host}", "-silent").label("Amass").hosts().verify().timeout(180).level(LevelAdvanced),
		spec("assetfinder", "--subs-only", "{host}").label("Assetfinder").hosts().level(LevelAdvanced),
		spec("findomain", "-t", "{host}", "-q").label("Findomain").hosts().level(LevelAdvanced),
		spec("shuffledns", "-d", "{host}", "-w", "{wordlist}", "-r", "{resolvers}", "-mode", "bruteforce", "-silent", "-json").label("Shuffledns").hosts().json().wordlist("wordlists/dns-50.txt").resolvers().timeout(300).level(LevelAdvanced),
		spec("puredns", "bruteforce", "{wordlist}", "{host}", "-r", "{resolvers}", "-q").label("Puredns").hosts().wordlist("wordlists/dns-50.txt").resolvers().timeout(300).level(LevelAdvanced),
		spec("massdns").label("Massdns").noStage().level(LevelAdvanced),
		spec("dnsgen", "{targetsfile}").label("Dnsgen").targetsFile().verify().level(LevelAdvanced),
		spec("alterx", "-silent").label("Alterx").stdin(StdinHost).verify().level(LevelAdvanced),
		spec("gotator", "-sub", "{host}", "-depth", "1", "-numbers", "3").label("Gotator").verify().level(LevelAdvanced),
		spec("dnsrecon", "-d", "{host}", "-t", "std").label("Dnsrecon").hosts().timeout(300).level(LevelAdvanced),
		spec("metabigor", "cert", "{host}").label("Metabigor").hosts().verify().timeout(180).level(LevelAdvanced),
		// Probe / fingerprint (6) — advanced.
		spec("tlsx", "-u", "https://{host}", "-json", "-silent").label("TLSx").json().timeout(120).level(LevelAdvanced),
		spec("cdncheck", "-silent").label("Cdncheck").stdin(StdinHost).timeout(120).level(LevelAdvanced),
		spec("asnmap", "-d", "{host}", "-silent").label("Asnmap").timeout(120).level(LevelAdvanced),
		spec("webanalyze", "-host", "{target}", "-crawl", "0", "-silent").label("Webanalyze").timeout(180).level(LevelAdvanced),
		spec("csprecon", "-u", "{target}", "-silent").label("CspreconExt").toggle("cspreconext").hosts().timeout(120).level(LevelAdvanced),
		spec("hakoriginfinder").label("HakOriginFinder").level(LevelAdvanced),
		// Crawl / URL / params (13) — advanced.
		spec("gau", "{host}", "--subs").label("Gau").timeout(180).level(LevelAdvanced),
		spec("waybackurls", "{host}").label("Waybackurls").timeout(180).level(LevelAdvanced),
		spec("hakrawler", "-d", "2", "-subs").label("Hakrawler").stdin(StdinTarget).timeout(300).level(LevelAdvanced),
		spec("gospider", "-s", "{target}", "-d", "1", "-c", "5").label("Gospider").timeout(300).level(LevelAdvanced),
		spec("cariddi", "{target}", "-c", "30").label("Cariddi").timeout(300).level(LevelAdvanced),
		spec("unfurl", "-u", "keys").label("Unfurl").stdin(StdinURLs).timeout(60).level(LevelAdvanced),
		spec("uro").label("Uro").stdin(StdinTarget).timeout(60).level(LevelAdvanced),
		spec("qsreplace", "FUZZ").label("Qsreplace").stdin(StdinTarget).timeout(60).level(LevelAdvanced),
		spec("anew").label("Anew").noStage().level(LevelAdvanced),
		spec("arjun", "-u", "{target}", "-m", "GET", "-t", "5").label("Arjun").timeout(300).level(LevelAdvanced),
		spec("paramspider", "-d", "{host}", "-l", "high").label("Paramspider").timeout(300).level(LevelAdvanced),
		spec("x8", "{target}", "-w", "{wordlist}", "--max", "30", "-t", "10").label("X8").wordlist("wordlists/params-30.txt").timeout(300).level(LevelAdvanced),
		spec("kiterunner", "scan", "{target}", "-w", "{wordlist}").label("Kiterunner").wordlist("wordlists/dirs-40.txt").timeout(300).level(LevelAdvanced),
		// Content fuzz (5) — ultra, wordlist-gated.
		spec("ffuf", "-u", "{target}/FUZZ", "-w", "{wordlist}", "-mc", "200,301,302,401,403", "-t", "20", "-s").label("Ffuf").wordlist("wordlists/dirs-40.txt").timeout(420).level(LevelUltra),
		spec("gobuster", "dir", "-u", "{target}", "-w", "{wordlist}", "-t", "20", "-q", "--no-error").label("Gobuster").wordlist("wordlists/dirs-40.txt").timeout(420).level(LevelUltra),
		spec("feroxbuster", "-u", "{target}", "-w", "{wordlist}", "-s", "200,301", "-t", "20", "--silent", "--json").label("Feroxbuster").wordlist("wordlists/dirs-40.txt").json().timeout(420).level(LevelUltra),
		spec("dirsearch", "-u", "{target}", "-w", "{wordlist}", "-t", "20", "-q").label("Dirsearch").wordlist("wordlists/dirs-40.txt").timeout(420).level(LevelUltra),
		spec("wfuzz", "-c", "-z", "file,{wordlist}", "--hc", "404", "{target}/FUZZ").label("Wfuzz").wordlist("wordlists/dirs-40.txt").timeout(420).level(LevelUltra),
		// Vuln point-tools (22).
		spec("sqlmap", "-u", "{paramurl}", "--batch", "--level=1", "--risk=1", "--random-agent", "--disable-coloring", "--flush-session").label("Sqlmap").paramURL().adversarial().timeout(600).level(LevelUltra).
			unsafeArgs("-u", "{paramurl}", "--batch", "--level=2", "--risk=2", "--random-agent", "--disable-coloring", "--flush-session"),
		spec("ghauri", "-u", "{paramurl}", "--batch", "--level=1").label("Ghauri").paramURL().adversarial().timeout(600).level(LevelUltra).
			unsafeArgs("-u", "{paramurl}", "--batch", "--level=2"),
		spec("xsstrike", "-u", "{paramurl}", "--skip", "--skip-dom", "--crawl", "-l", "2").label("Xsstrike").paramURL().timeout(300).level(LevelAdvanced),
		spec("kxss").label("Kxss").stdin(StdinURLs).requiresParams().timeout(120).level(LevelAdvanced),
		spec("gxss").label("Gxss").stdin(StdinURLs).requiresParams().timeout(120).level(LevelAdvanced),
		spec("crlfuzz", "-u", "{target}").label("Crlfuzz").timeout(180).level(LevelAdvanced),
		spec("nikto", "-h", "{target}", "-Tuning", "x", "-maxtime", "300", "-Format", "txt", "-o", "-").label("Nikto").timeout(420).level(LevelUltra).
			unsafeArgs("-h", "{target}", "-Tuning", "12345789", "-maxtime", "300", "-Format", "txt", "-o", "-"),
		spec("whatweb", "--no-errors", "-a", "1", "--color=never", "--log-brief=-", "{target}").label("Whatweb").timeout(180).level(LevelAdvanced),
		spec("wafw00f", "{target}").label("Wafw00f").timeout(120).level(LevelAdvanced),
		spec("commix", "--url={paramurl}", "--batch", "--level=1", "--random-agent").label("Commix").paramURL().adversarial().timeout(600).level(LevelUltra),
		spec("tplmap", "-u", "{paramurl}").label("Tplmap").paramURL().adversarial().timeout(600).level(LevelUltra),
		spec("sstimap", "-u", "{paramurl}").label("Sstimap").paramURL().adversarial().timeout(600).level(LevelUltra),
		spec("ssrfmap").label("Ssrfmap").level(LevelUltra),
		spec("nosqlmap").label("Nosqlmap").level(LevelUltra),
		spec("graphqlmap").label("Graphqlmap").level(LevelUltra),
		spec("jwt_tool").label("JwtTool").level(LevelAdvanced),
		spec("nomore403", "-u", "{target}").label("Nomore403").timeout(300).level(LevelAdvanced),
		spec("oralyzer", "-u", "{paramurl}").label("Oralyzer").paramURL().timeout(300).level(LevelAdvanced),
		spec("openredirex", "-c", "10").label("Openredirex").stdin(StdinURLs).timeout(300).level(LevelAdvanced),
		spec("smuggler", "-u", "{target}").label("Smuggler").adversarial().timeout(300).level(LevelUltra),
		spec("dotdotpwn", "-m", "http", "-h", "{host}", "-f", "/etc/hosts", "-k", "localhost", "-d", "4", "-t", "50", "-s", "-q").label("Dotdotpwn").adversarial().timeout(600).level(LevelUltra),
		spec("corsy", "-u", "{target}").label("Corsy").timeout(180).level(LevelAdvanced),
		// CMS (4) — advanced.
		spec("wpscan", "--url", "{target}", "--enumerate", "vp,vt", "--random-user-agent", "--no-update", "--format", "json").label("Wpscan").json().timeout(420).level(LevelAdvanced),
		spec("cmseek", "-u", "{target}").label("Cmseek").timeout(300).level(LevelAdvanced),
		spec("droopescan", "scan", "drupal", "-u", "{target}").label("Droopescan").timeout(300).level(LevelAdvanced),
		spec("joomscan", "--url", "{target}").label("Joomscan").timeout(300).level(LevelAdvanced),
		// Takeover corroboration (2) — advanced.
		spec("subzy", "run", "--target", "{target}").label("Subzy").timeout(180).level(LevelAdvanced),
		spec("subjack", "-w", "{targetsfile}", "-t", "50", "-timeout", "15", "-ssl", "-a", "-v").label("Subjack").targetsFile().timeout(300).level(LevelAdvanced),
		// Secrets / JS (7) — advanced; local modes only.
		spec("gitleaks", "detect", "--source", "{codedir}", "--no-git", "--no-banner", "-f", "json", "-r", "-").label("Gitleaks").codedir().json().timeout(300).level(LevelAdvanced),
		spec("trufflehog", "filesystem", "{codedir}", "--json", "--no-update").label("Trufflehog").codedir().json().timeout(300).level(LevelAdvanced),
		spec("noseyparker", "scan", "-d", "{tmpdir}", "{codedir}").label("Noseyparker").codedir().tmpDir().timeout(300).level(LevelAdvanced),
		spec("jsluice").label("Jsluice").level(LevelAdvanced),
		spec("subjs").label("Subjs").stdin(StdinURLs).timeout(180).level(LevelAdvanced),
		spec("secretfinder", "-i", "{target}", "-o", "cli").label("Secretfinder").binary("secretfinder").timeout(180).level(LevelAdvanced),
		spec("linkfinder", "-i", "{target}", "-o", "cli").label("Linkfinder").binary("LinkFinder.py").timeout(180).level(LevelAdvanced),
		// Git exposure (2) — ultra, adversarial-gated dumps.
		spec("git-dumper", "{target}/.git/", "{tmpdir}").label("GitDumper").tmpDir().adversarial().timeout(600).level(LevelUltra),
		spec("gitjacker", "{target}/.git/").label("Gitjacker").adversarial().timeout(600).level(LevelUltra),
		// Network (3) — ultra.
		spec("nmap", "-sV", "-T4", "-F", "-oG", "-", "{host}").label("Nmap").timeout(420).level(LevelUltra),
		spec("masscan", "{host}", "-p1-1024", "--rate", "500", "--wait", "2", "--open-only", "-oL", "-").label("Masscan").timeout(420).level(LevelUltra),
		spec("rustscan", "-a", "{host}", "--ulimit", "3000", "-t", "1500", "-g").label("Rustscan").timeout(420).level(LevelUltra),
		// Screenshots (2) — ultra, chrome-dependent.
		spec("gowitness", "single", "--url", "{target}", "--screenshot-path", "{tmpdir}", "--disable-db").label("Gowitness").tmpDir().timeout(300).level(LevelUltra),
		spec("aquatone", "-out", "{tmpdir}").label("Aquatone").stdin(StdinHost).tmpDir().timeout(300).level(LevelUltra),
		// Social (1) — advanced.
		spec("socialhunter", "-f", "{urlsfile}", "-w", "5").label("Socialhunter").urlsFile().timeout(300).level(LevelAdvanced),
		// Code scope SAST/SCA (4) — advanced, local code only.
		spec("semgrep", "--config", "p/security-audit", "--json", "--quiet", "--metrics", "off", "{codedir}").label("Semgrep").codedir().json().timeout(420).level(LevelAdvanced),
		spec("trivy", "fs", "--format", "json", "--quiet", "--scanners", "vuln", "{codedir}").label("Trivy").codedir().json().timeout(420).level(LevelAdvanced),
		spec("osv-scanner", "--format", "json", "-r", "{codedir}").label("OsvScanner").codedir().json().timeout(420).level(LevelAdvanced),
		spec("grype", "{codedir}", "-o", "json", "-q").label("Grype").codedir().json().timeout(420).level(LevelAdvanced),
		// Exploit correlation (1) — safe, local clone, mapping only.
		spec("searchsploit", "{term}", "-j").label("Searchsploit").perTech().json().timeout(120).level(LevelSafe),
		// Mobile (1) — ultra; static via operator-run server, dynamic never.
		spec("mobsf").label("Mobsf").apk().noStage().level(LevelUltra),
	}
}

// embeddedFallbacks maps each staged tool to the native ANPU modules
// covering its ground when the binary is absent (labels as used by
// pipeline stages and --only names). Empty means genuinely no embedded
// equivalent (browser/APK/file-util prerequisites).
var embeddedFallbacks = map[string][]string{
	"amass":           {"subdomains", "subpermute", "certsan", "csprecon", "dnsaudit"},
	"assetfinder":     {"subdomains", "subpermute", "certsan"},
	"findomain":       {"subdomains", "subpermute"},
	"shuffledns":      {"subdomains", "dnsaudit"},
	"puredns":         {"subdomains", "dnsaudit"},
	"massdns":         {"subdomains", "dnsaudit"},
	"dnsgen":          {"subpermute"},
	"alterx":          {"subpermute"},
	"gotator":         {"subpermute"},
	"dnsrecon":        {"dnsaudit", "subdomains"},
	"metabigor":       {"subdomains", "ipintel"},
	"tlsx":            {"tls"},
	"cdncheck":        {"technology", "ipintel"},
	"asnmap":          {"ipintel", "bgp"},
	"webanalyze":      {"technology"},
	"csprecon":        {"csprecon"},
	"hakoriginfinder": {"originip"},
	"gau":             {"archiveurls", "recon"},
	"waybackurls":     {"archiveurls", "recon"},
	"hakrawler":       {"endpoints"},
	"gospider":        {"endpoints"},
	"cariddi":         {"endpoints", "secrets"},
	"unfurl":          {"params", "gfclassify"},
	"uro":             {"params", "gfclassify"},
	"qsreplace":       {"params"},
	"anew":            {},
	"arjun":           {"hiddenparams"},
	"paramspider":     {"hiddenparams"},
	"x8":              {"hiddenparams"},
	"kiterunner":      {"apiconsole", "apiversion"},
	"ffuf":            {"dirs", "backupplus"},
	"gobuster":        {"dirs", "backupplus"},
	"feroxbuster":     {"dirs", "backupplus"},
	"dirsearch":       {"dirs", "backupplus"},
	"wfuzz":           {"dirs", "backupplus"},
	"sqlmap":          {"active"},
	"ghauri":          {"active"},
	"xsstrike":        {"active"},
	"kxss":            {"active"},
	"gxss":            {"active"},
	"crlfuzz":         {"active"},
	"nikto":           {"debugpages", "headers", "actuator", "exposedconfig"},
	"whatweb":         {"technology"},
	"wafw00f":         {"technology", "ipintel"},
	"commix":          {"active"},
	"tplmap":          {"active", "sstiexpand"},
	"sstimap":         {"active", "sstiexpand"},
	"ssrfmap":         {"active"},
	"nosqlmap":        {"active", "nosqlexpand"},
	"graphqlmap":      {"graphqlfp", "graphqlschema", "apiconsole"},
	"jwt_tool":        {"jwtplus"},
	"nomore403":       {"forbiddenbypass"},
	"oralyzer":        {"redirectpack"},
	"openredirex":     {"redirectpack"},
	"smuggler":        {"h2smuggle", "active"},
	"dotdotpwn":       {"lfipack"},
	"corsy":           {"cors", "corsplus"},
	"wpscan":          {"technology", "deps"},
	"cmseek":          {"technology", "deps"},
	"droopescan":      {"technology", "deps"},
	"joomscan":        {"technology", "deps"},
	"subzy":           {"takeover", "takeoverplus"},
	"subjack":         {"takeover", "takeoverplus"},
	"gitleaks":        {"secrets", "jssecrets", "deps", "codesecrets"},
	"trufflehog":      {"secrets", "jssecrets", "deps", "codesecrets"},
	"noseyparker":     {"secrets", "jssecrets", "deps", "codesecrets"},
	"jsluice":         {"jsluice", "secrets", "jssecrets", "endpoints", "postmessage"},
	"subjs":           {"secrets", "jssecrets", "endpoints"},
	"secretfinder":    {"secrets", "jssecrets"},
	"linkfinder":      {"secrets", "endpoints"},
	"git-dumper":      {"exposedgit"},
	"gitjacker":       {"exposedgit"},
	"nmap":            {"portscan"},
	"masscan":         {"portscan"},
	"rustscan":        {"portscan"},
	"gowitness":       {},
	"aquatone":        {},
	"socialhunter":    {"socialhijack", "emailharv"},
	"semgrep":         {"deps", "secrets", "codesecrets"},
	"trivy":           {"deps", "codesecrets"},
	"osv-scanner":     {"deps", "codesecrets"},
	"grype":           {"deps", "codesecrets"},
	"searchsploit":    {"cvepack", "deps"},
	"mobsf":           {},
}

// EmbeddedFallbacks returns the native labels covering a tool.
func EmbeddedFallbacks(name string) []string {
	return embeddedFallbacks[name]
}

// StagedSpecs returns specs with pipeline stages (NoStage excluded).
func StagedSpecs() []*ToolSpec {
	var out []*ToolSpec
	for _, s := range ToolSpecs() {
		if !s.NoStage {
			out = append(out, s)
		}
	}
	return out
}

// SpecByName finds a spec by registry name (case-insensitive).
func SpecByName(name string) (*ToolSpec, bool) {
	for _, s := range ToolSpecs() {
		if strings.EqualFold(s.Name, strings.TrimSpace(name)) {
			return s, true
		}
	}
	return nil, false
}
