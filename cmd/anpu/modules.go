package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// modules.go — module toggle helpers (Phase 6).
// Relocated verbatim from scan.go.

func disableAllModules(mc *models.ModuleConfig) {
	*mc = models.ModuleConfig{}
}

// missingBinaries lists enabled wrapper tools whose binaries are absent
// (used by the --auto-install pre-scan alert).
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
			_, _ = fmt.Fprintf(os.Stderr, "anpu: unknown module %q in --enable/--disable (ignored)\n", name)
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
