// Package config loads and merges ANPU's YAML configuration file with
// CLI flags. CLI flags always take precedence over file values.
package config

import (
	"fmt"
	"os"

	"github.com/Marwanmorsy999/anpu/pkg/models"
	"gopkg.in/yaml.v3"
)

// TargetConfig mirrors the `target:` section of the YAML config.
type TargetConfig struct {
	URL string `yaml:"url"`
}

// AuthFileConfig mirrors the `auth:` section of the YAML config.
// Credentials supplied here are merged with CLI flags; CLI flags win.
//
// NEVER commit real credentials.  Use environment variable references
// or pass credentials on the command line for sensitive values.
type AuthFileConfig struct {
	Method  string   `yaml:"method"`
	Token   string   `yaml:"token"`
	Cookies []string `yaml:"cookies"`
	Headers []string `yaml:"headers"`
	Role    string   `yaml:"role"`
}

// ScanFileConfig mirrors the `scan:` section.
type ScanFileConfig struct {
	Profile     string `yaml:"profile"`
	Adversarial *bool  `yaml:"adversarial"`
	// AutoInstall self-provisions missing externals mid-scan (CLI wins).
	AutoInstall *bool `yaml:"auto_install"`
	// Unsafe is the operator master override (CLI --unsafe wins).
	Unsafe *bool `yaml:"unsafe"`
	// Ghost undetectable-mode defaults (CLI flags win when set).
	Ghost             *bool   `yaml:"ghost"`
	GhostCanaryPrefix *string `yaml:"ghost_canary_prefix"`
	GhostWorkers      *int    `yaml:"ghost_workers"`
	ProxyPool         *string `yaml:"proxy_pool"`
}

// ModulesFileConfig mirrors the `modules:` section. Pointers distinguish
// "unset" (use profile default) from an explicit true/false.
type ModulesFileConfig struct {
	Recon       *bool `yaml:"recon"`
	Technology  *bool `yaml:"technology"`
	TLS         *bool `yaml:"tls"`
	Headers     *bool `yaml:"headers"`
	Cookies     *bool `yaml:"cookies"`
	Endpoints   *bool `yaml:"endpoints"`
	Params      *bool `yaml:"params"`
	Subdomains  *bool `yaml:"subdomains"`
	Takeover    *bool `yaml:"takeover"`
	PortScan    *bool `yaml:"portscan"`
	Dirs        *bool `yaml:"dirs"`
	Secrets     *bool `yaml:"secrets"`
	CORS        *bool `yaml:"cors"`
	Methods     *bool `yaml:"methods"`
	CSRF        *bool `yaml:"csrf"`
	Deps        *bool `yaml:"deps"`
	Active      *bool `yaml:"active"`
	Nuclei      *bool `yaml:"nuclei"`
	ZAP         *bool `yaml:"zap"`
	SRI         *bool `yaml:"sri"`
	Backup      *bool `yaml:"backup"`
	Katana      *bool `yaml:"katana"`
	Httpx       *bool `yaml:"httpx"`
	Subfinder   *bool `yaml:"subfinder"`
	Dalfox      *bool `yaml:"dalfox"`
	DNSIntel    *bool `yaml:"dnsintel"`
	IPIntel     *bool `yaml:"ipintel"`
	Naabu       *bool `yaml:"naabu"`
	DNSx        *bool `yaml:"dnsx"`
	RDAP        *bool `yaml:"rdap"`
	Leak        *bool `yaml:"leak"`
	Favicon     *bool `yaml:"favicon"`
	DoH         *bool `yaml:"doh"`
	Bucket      *bool `yaml:"bucket"`
	BGP         *bool `yaml:"bgp"`
	API         *bool `yaml:"api"`
	AuthZ       *bool `yaml:"authz"`
	Adversarial *bool `yaml:"adversarial"`
	IDOR        *bool `yaml:"idor"`
	// External maps Wave 2 wrapper toggles (amass, ffuf, nmap, ...) so
	// 84 tools don't need 84 explicit fields. Keys match --only names.
	External map[string]*bool `yaml:"external"`
	// Wave 1 batch 1 — passive recon engines (safe for all profiles).
	ArchiveURLs  *bool `yaml:"archiveurls"`
	CertSAN      *bool `yaml:"certsan"`
	EmailHarv    *bool `yaml:"emailharv"`
	DNSAudit     *bool `yaml:"dnsaudit"`
	EmailAuth    *bool `yaml:"emailauth"`
	CSPRecon     *bool `yaml:"csprecon"`
	SocialHijack *bool `yaml:"socialhijack"`
	CommentMiner *bool `yaml:"commentminer"`
	BrokenLink   *bool `yaml:"brokenlink"`
	OriginIP     *bool `yaml:"originip"`
	// Wave 1 batch 2 — bounded exposure probes (advanced/ultra).
	ExposedGit    *bool `yaml:"exposedgit"`
	ExposedConfig *bool `yaml:"exposedconfig"`
	Actuator      *bool `yaml:"actuator"`
	DebugPages    *bool `yaml:"debugpages"`
	OAuthAnalyzer *bool `yaml:"oauthanalyzer"`
	SAMLMetadata  *bool `yaml:"samlmetadata"`
	CSWSH         *bool `yaml:"cswsh"`
	PostMessage   *bool `yaml:"postmessage"`
	JSSecrets     *bool `yaml:"jssecrets"`
	HiddenParams  *bool `yaml:"hiddenparams"`
	// Wave 1 batch 3 — items 21-30.
	VerbTamper      *bool `yaml:"verbtamper"`
	CacheDeception  *bool `yaml:"cachedeception"`
	ForbiddenBypass *bool `yaml:"forbiddenbypass"`
	TakeoverPlus    *bool `yaml:"takeoverplus"`
	Clickjack       *bool `yaml:"clickjack"`
	PolicyHeaders   *bool `yaml:"policyheaders"`
	CookiePrefix    *bool `yaml:"cookieprefix"`
	APIVersion      *bool `yaml:"apiversion"`
	APIConsole      *bool `yaml:"apiconsole"`
	VHost           *bool `yaml:"vhost"`
	// Wave 1 batches 4-5 — items 31-50.
	GraphQLFP     *bool `yaml:"graphqlfp"`
	GraphQLSchema *bool `yaml:"graphqlschema"`
	JWTPlus       *bool `yaml:"jwtplus"`
	SSTIExpand    *bool `yaml:"sstiexpand"`
	NoSQLExpand   *bool `yaml:"nosqlexpand"`
	H2Smuggle     *bool `yaml:"h2smuggle"`
	H2FP          *bool `yaml:"h2fp"`
	RedirectPack  *bool `yaml:"redirectpack"`
	LFIPack       *bool `yaml:"lfipack"`
	CVEPack       *bool `yaml:"cvepack"`
	CORSPlus      *bool `yaml:"corsplus"`
	CertHistory   *bool `yaml:"certhistory"`
	AXFRPlus      *bool `yaml:"axfrplus"`
	SubPermute    *bool `yaml:"subpermute"`
	BackupPlus    *bool `yaml:"backupplus"`
	FaviconPlus   *bool `yaml:"faviconplus"`
	DebugMethods  *bool `yaml:"debugmethods"`
	EncodePoly    *bool `yaml:"encodepoly"`
	DiffOracle    *bool `yaml:"difforacle"`
	GFClassify    *bool `yaml:"gfclassify"`
	Soap          *bool `yaml:"soap"`
	Nsecwalk      *bool `yaml:"nsecwalk"`
	Wafdetect     *bool `yaml:"wafdetect"`
	Oauthpack     *bool `yaml:"oauthpack"`
	Ppollute      *bool `yaml:"ppollute"`
	Swscope       *bool `yaml:"swscope"`
	Timeoracle    *bool `yaml:"timeoracle"`
	Jwtconfirm    *bool `yaml:"jwtconfirm"`
	Jsluice       *bool `yaml:"jsluice"`
	Codesecrets   *bool `yaml:"codesecrets"`
}

// ReportFileConfig mirrors the `report:` section.
type ReportFileConfig struct {
	HTML  *bool `yaml:"html"`
	JSON  *bool `yaml:"json"`
	SARIF *bool `yaml:"sarif"`
}

// File is the root of anpu's YAML configuration file.
type File struct {
	Target  TargetConfig      `yaml:"target"`
	Scan    ScanFileConfig    `yaml:"scan"`
	Modules ModulesFileConfig `yaml:"modules"`
	Report  ReportFileConfig  `yaml:"report"`
	Auth    AuthFileConfig    `yaml:"auth"`
}

// Load reads and parses a YAML config file at path. It is not an error
// for the file to not exist — callers should treat that as "use
// defaults / CLI flags only".
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- CLI reads operator-specified paths (reports, wordlists, checkpoints, code dir).
	if err != nil {
		if os.IsNotExist(err) {
			return &File{}, nil
		}
		return nil, fmt.Errorf("reading config file: %w", err)
	}
	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parsing config file %s: %w", path, err)
	}
	return &f, nil
}

// ResolveAuth returns the effective AuthContext for a scan, merging YAML
// config with CLI flag values.  CLI flags always win over file values.
// An empty AuthContext (all-zero) is returned when neither source
// provides credentials.
//
// The caller is responsible for calling Validate() on the result.
func ResolveAuth(f *File, cliToken string, cliCookies, cliHeaders []string, cliRole string) (models.AuthContext, error) {
	// Start from file values.
	token := cliToken
	cookies := cliCookies
	hdrs := cliHeaders
	role := cliRole

	if f != nil && f.Auth.Method != "" {
		// Only pull from file if CLI didn't supply a credential.
		if token == "" && len(cookies) == 0 && len(hdrs) == 0 {
			token = f.Auth.Token
			cookies = f.Auth.Cookies
			hdrs = f.Auth.Headers
		}
		if role == "" {
			role = f.Auth.Role
		}
	}

	// Delegate to the auth package constructor for validation logic.
	// We call it directly here to keep config independent of auth, but
	// the logic is: pick the first non-empty credential type, validate,
	// return.
	active := 0
	if token != "" {
		active++
	}
	if len(cookies) > 0 {
		active++
	}
	if len(hdrs) > 0 {
		active++
	}
	if active > 1 {
		return models.AuthContext{}, fmt.Errorf(
			"at most one auth method may be active (bearer_token, cookies, or headers)",
		)
	}

	ctx := models.AuthContext{}
	switch {
	case token != "":
		ctx.Method = models.AuthMethodBearer
		ctx.BearerToken = token
		if role == "" {
			role = "user"
		}
	case len(cookies) > 0:
		ctx.Method = models.AuthMethodCookie
		ctx.Cookies = cookies
		if role == "" {
			role = "user"
		}
	case len(hdrs) > 0:
		ctx.Method = models.AuthMethodHeader
		ctx.Headers = hdrs
		if role == "" {
			role = "user"
		}
	default:
		ctx.Method = models.AuthMethodNone
		if role == "" {
			role = "anonymous"
		}
	}
	ctx.Role = models.AuthRole(role)

	if err := ctx.Validate(); err != nil {
		return models.AuthContext{}, err
	}
	return ctx, nil
}

// applyBool overrides dst with src if src is non-nil.
func applyBool(dst *bool, src *bool) {
	if src != nil {
		*dst = *src
	}
}

// ResolveModules computes the effective ModuleConfig for a scan given
// the profile default, the config file, and the --no-* CLI flags
// (CLI flags win last).
func ResolveModules(profile models.Profile, f *File, noNuclei, noZAP, noActive, noCSRF, noDeps, noTakeover, noSRI, noBackup, noKatana, noHttpx, noSubfinder, noDalfox, noDNSIntel, noIPIntel, noNaabu, noDNSx, noRDAP, noLeak, noFavicon, noDoH, noBucket, noBGP, noAPI, noAuthZ bool) models.ModuleConfig {
	mc := models.DefaultModuleConfig(profile)
	if f != nil {
		applyBool(&mc.Recon, f.Modules.Recon)
		applyBool(&mc.Technology, f.Modules.Technology)
		applyBool(&mc.TLS, f.Modules.TLS)
		applyBool(&mc.Headers, f.Modules.Headers)
		applyBool(&mc.Cookies, f.Modules.Cookies)
		applyBool(&mc.Endpoints, f.Modules.Endpoints)
		applyBool(&mc.Params, f.Modules.Params)
		applyBool(&mc.Subdomains, f.Modules.Subdomains)
		applyBool(&mc.Takeover, f.Modules.Takeover)
		applyBool(&mc.PortScan, f.Modules.PortScan)
		applyBool(&mc.Dirs, f.Modules.Dirs)
		applyBool(&mc.Secrets, f.Modules.Secrets)
		applyBool(&mc.CORS, f.Modules.CORS)
		applyBool(&mc.Methods, f.Modules.Methods)
		applyBool(&mc.CSRF, f.Modules.CSRF)
		applyBool(&mc.Deps, f.Modules.Deps)
		applyBool(&mc.SRI, f.Modules.SRI)
		applyBool(&mc.Backup, f.Modules.Backup)
		applyBool(&mc.Active, f.Modules.Active)
		applyBool(&mc.Nuclei, f.Modules.Nuclei)
		applyBool(&mc.ZAP, f.Modules.ZAP)
		applyBool(&mc.Katana, f.Modules.Katana)
		applyBool(&mc.Httpx, f.Modules.Httpx)
		applyBool(&mc.Subfinder, f.Modules.Subfinder)
		applyBool(&mc.Dalfox, f.Modules.Dalfox)
		applyBool(&mc.DNSIntel, f.Modules.DNSIntel)
		applyBool(&mc.IPIntel, f.Modules.IPIntel)
		applyBool(&mc.Naabu, f.Modules.Naabu)
		applyBool(&mc.DNSx, f.Modules.DNSx)
		applyBool(&mc.RDAP, f.Modules.RDAP)
		applyBool(&mc.Leak, f.Modules.Leak)
		applyBool(&mc.Favicon, f.Modules.Favicon)
		applyBool(&mc.DoH, f.Modules.DoH)
		applyBool(&mc.Bucket, f.Modules.Bucket)
		applyBool(&mc.BGP, f.Modules.BGP)
		applyBool(&mc.API, f.Modules.API)
		applyBool(&mc.AuthZ, f.Modules.AuthZ)
		applyBool(&mc.Adversarial, f.Modules.Adversarial)
		applyBool(&mc.IDOR, f.Modules.IDOR)
		for k, v := range f.Modules.External {
			if v != nil {
				models.SetModuleByName(&mc, k, *v)
			}
		}
		applyBool(&mc.ArchiveURLs, f.Modules.ArchiveURLs)
		applyBool(&mc.CertSAN, f.Modules.CertSAN)
		applyBool(&mc.EmailHarv, f.Modules.EmailHarv)
		applyBool(&mc.DNSAudit, f.Modules.DNSAudit)
		applyBool(&mc.EmailAuth, f.Modules.EmailAuth)
		applyBool(&mc.CSPRecon, f.Modules.CSPRecon)
		applyBool(&mc.SocialHijack, f.Modules.SocialHijack)
		applyBool(&mc.CommentMiner, f.Modules.CommentMiner)
		applyBool(&mc.BrokenLink, f.Modules.BrokenLink)
		applyBool(&mc.OriginIP, f.Modules.OriginIP)
		applyBool(&mc.ExposedGit, f.Modules.ExposedGit)
		applyBool(&mc.ExposedConfig, f.Modules.ExposedConfig)
		applyBool(&mc.Actuator, f.Modules.Actuator)
		applyBool(&mc.DebugPages, f.Modules.DebugPages)
		applyBool(&mc.OAuthAnalyzer, f.Modules.OAuthAnalyzer)
		applyBool(&mc.SAMLMetadata, f.Modules.SAMLMetadata)
		applyBool(&mc.CSWSH, f.Modules.CSWSH)
		applyBool(&mc.PostMessage, f.Modules.PostMessage)
		applyBool(&mc.JSSecrets, f.Modules.JSSecrets)
		applyBool(&mc.HiddenParams, f.Modules.HiddenParams)
		applyBool(&mc.VerbTamper, f.Modules.VerbTamper)
		applyBool(&mc.CacheDeception, f.Modules.CacheDeception)
		applyBool(&mc.ForbiddenBypass, f.Modules.ForbiddenBypass)
		applyBool(&mc.TakeoverPlus, f.Modules.TakeoverPlus)
		applyBool(&mc.Clickjack, f.Modules.Clickjack)
		applyBool(&mc.PolicyHeaders, f.Modules.PolicyHeaders)
		applyBool(&mc.CookiePrefix, f.Modules.CookiePrefix)
		applyBool(&mc.APIVersion, f.Modules.APIVersion)
		applyBool(&mc.APIConsole, f.Modules.APIConsole)
		applyBool(&mc.VHost, f.Modules.VHost)
		applyBool(&mc.GraphQLFP, f.Modules.GraphQLFP)
		applyBool(&mc.GraphQLSchema, f.Modules.GraphQLSchema)
		applyBool(&mc.JWTPlus, f.Modules.JWTPlus)
		applyBool(&mc.SSTIExpand, f.Modules.SSTIExpand)
		applyBool(&mc.NoSQLExpand, f.Modules.NoSQLExpand)
		applyBool(&mc.H2Smuggle, f.Modules.H2Smuggle)
		applyBool(&mc.H2FP, f.Modules.H2FP)
		applyBool(&mc.RedirectPack, f.Modules.RedirectPack)
		applyBool(&mc.LFIPack, f.Modules.LFIPack)
		applyBool(&mc.CVEPack, f.Modules.CVEPack)
		applyBool(&mc.CORSPlus, f.Modules.CORSPlus)
		applyBool(&mc.CertHistory, f.Modules.CertHistory)
		applyBool(&mc.AXFRPlus, f.Modules.AXFRPlus)
		applyBool(&mc.SubPermute, f.Modules.SubPermute)
		applyBool(&mc.BackupPlus, f.Modules.BackupPlus)
		applyBool(&mc.FaviconPlus, f.Modules.FaviconPlus)
		applyBool(&mc.DebugMethods, f.Modules.DebugMethods)
		applyBool(&mc.EncodePoly, f.Modules.EncodePoly)
		applyBool(&mc.DiffOracle, f.Modules.DiffOracle)
		applyBool(&mc.GFClassify, f.Modules.GFClassify)
		applyBool(&mc.Soap, f.Modules.Soap)
		applyBool(&mc.Nsecwalk, f.Modules.Nsecwalk)
		applyBool(&mc.Wafdetect, f.Modules.Wafdetect)
		applyBool(&mc.Oauthpack, f.Modules.Oauthpack)
		applyBool(&mc.Ppollute, f.Modules.Ppollute)
		applyBool(&mc.Swscope, f.Modules.Swscope)
		applyBool(&mc.Timeoracle, f.Modules.Timeoracle)
		applyBool(&mc.Jwtconfirm, f.Modules.Jwtconfirm)
		applyBool(&mc.Jsluice, f.Modules.Jsluice)
		applyBool(&mc.Codesecrets, f.Modules.Codesecrets)
	}
	if noActive {
		mc.Active = false
	}
	if noNuclei {
		mc.Nuclei = false
	}
	if noZAP {
		mc.ZAP = false
	}
	if noCSRF {
		mc.CSRF = false
	}
	if noDeps {
		mc.Deps = false
	}
	if noTakeover {
		mc.Takeover = false
	}
	if noSRI {
		mc.SRI = false
	}
	if noBackup {
		mc.Backup = false
	}
	if noKatana {
		mc.Katana = false
	}
	if noHttpx {
		mc.Httpx = false
	}
	if noSubfinder {
		mc.Subfinder = false
	}
	if noDalfox {
		mc.Dalfox = false
	}
	if noDNSIntel {
		mc.DNSIntel = false
	}
	if noIPIntel {
		mc.IPIntel = false
	}
	if noNaabu {
		mc.Naabu = false
	}
	if noDNSx {
		mc.DNSx = false
	}
	if noRDAP {
		mc.RDAP = false
	}
	if noLeak {
		mc.Leak = false
	}
	if noFavicon {
		mc.Favicon = false
	}
	if noDoH {
		mc.DoH = false
	}
	if noBucket {
		mc.Bucket = false
	}
	if noBGP {
		mc.BGP = false
	}
	if noAPI {
		mc.API = false
	}
	if noAuthZ {
		mc.AuthZ = false
	}
	return mc
}
