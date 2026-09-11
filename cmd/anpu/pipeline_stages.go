package main

import (
	"sort"
	"strings"

	"github.com/anpu-project/anpu/internal/active"
	"github.com/anpu-project/anpu/internal/actuator"
	"github.com/anpu-project/anpu/internal/api"
	"github.com/anpu-project/anpu/internal/apiconsole"
	"github.com/anpu-project/anpu/internal/apiversion"
	"github.com/anpu-project/anpu/internal/archiveurls"
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
	"github.com/anpu-project/anpu/internal/originip"
	"github.com/anpu-project/anpu/internal/params"
	"github.com/anpu-project/anpu/internal/policyheaders"
	"github.com/anpu-project/anpu/internal/portscan"
	"github.com/anpu-project/anpu/internal/postmessage"
	"github.com/anpu-project/anpu/internal/ppollute"
	"github.com/anpu-project/anpu/internal/rdap"
	"github.com/anpu-project/anpu/internal/recon"
	"github.com/anpu-project/anpu/internal/redirectpack"
	"github.com/anpu-project/anpu/internal/saml"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/internal/secrets"
	"github.com/anpu-project/anpu/internal/soap"
	"github.com/anpu-project/anpu/internal/socialhijack"
	"github.com/anpu-project/anpu/internal/sri"
	"github.com/anpu-project/anpu/internal/sstiexpand"
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

// pipeline.go — pipeline construction (Phase 6).
// Relocated verbatim from scan.go: stage table, phase assignment,
// wrapper staging, concurrency sets, native registry, binary inventory.
// Behavior identical; only the file changed.

// buildPipeline wires up every scan stage in pipeline order. This is the
// single place that knows about concrete scanner implementations — the
// orchestrator (internal/scanner) and every analyzer package only know
// about the Scanner interface, so adding a new stage means adding one
// entry here.
func buildPipeline(client *anpuhttp.Client, modules models.ModuleConfig, authzCtx models.AuthContext, apiCfg api.Config, profile models.Profile, unsafe bool, onlyMods []string) *scanner.Pipeline {
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
			{Label: "Httpx", Enabled: modules.Httpx, Scanner: httpx, SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "Codesecrets", Enabled: modules.Codesecrets, Scanner: codesecrets.New()},
			{Label: "TLS", Enabled: modules.TLS, Scanner: tls.New(client)},
			{Label: "Headers", Enabled: modules.Headers, Scanner: headers.New(client)},
			{Label: "Cookies", Enabled: modules.Cookies, Scanner: headers.NewCookieAnalyzer(client)},
			{Label: "Endpoints", Enabled: modules.Endpoints, Scanner: endpoints.New(client)},
			// Deps runs after Technology AND Endpoints so sc.Technologies is
			// already populated and crawler-discovered manifests are visible
			// for harvest (previously it ran before Endpoints and the
			// manifest path could never trigger).
			{Label: "Deps", Enabled: modules.Deps, Scanner: deps.NewWithClient(client), SkipReason: "safe profile is passive — use --profile advanced"},
			// Katana crawls what the built-in crawler misses (JS-heavy
			// routes); its endpoints feed every later stage.
			{Label: "Katana", Enabled: modules.Katana, Scanner: katana, SkipReason: "safe profile is passive — use --profile advanced"},
			// API scanner (Phase 5) runs immediately after endpoint discovery
			// so that schema-derived endpoints are in ScanContext.Endpoints
			// before the AuthZ and Active stages consume them. With no
			// --openapi/--graphql flags it auto-discovers well-known
			// schema locations (GET-only). --only stays absolute: explicit
			// flags never force the stage on (they warn instead, above).
			{Label: "API", Enabled: modules.API, Scanner: api.New(apiCfg)},
			{Label: "Subdomains", Enabled: modules.Subdomains, Scanner: subdomains.New(), SkipReason: "safe profile is passive — use --profile advanced"},
			// Subfinder merges passive subdomains into sc.Subdomains for Takeover.
			{Label: "Subfinder", Enabled: modules.Subfinder, Scanner: subfinder, SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "DNSx", Enabled: modules.DNSx, Scanner: dnsx, SkipReason: "safe profile is passive — use --profile advanced"},
			// Takeover runs after Subdomains so sc.Subdomains is populated.
			{Label: "Takeover", Enabled: modules.Takeover, Scanner: takeover.New(), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "PortScan", Enabled: modules.PortScan, Scanner: portscan.New(), SkipReason: "ultra profile only (--profile ultra)"},
			{Label: "Naabu", Enabled: modules.Naabu, Scanner: naabu, SkipReason: "ultra profile only (--profile ultra)"},
			{Label: "Dirs", Enabled: modules.Dirs, Scanner: dirs.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			// Secrets consumes the endpoints discovered above, so it must
			// stay after the Endpoints stage.
			{Label: "Secrets", Enabled: modules.Secrets, Scanner: secrets.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			// Params classifies query params on all discovered endpoints
			// (including JS routes from Secrets). Passive — independently
			// toggleable via --disable/--enable params (default on).
			{Label: "Params", Enabled: modules.Params, Scanner: params.New(), SkipReason: "disabled via --disable params"},
			{Label: "CORS", Enabled: modules.CORS, Scanner: cors.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "Methods", Enabled: modules.Methods, Scanner: methods.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			// CSRF runs after Endpoints so form action URLs are known.
			{Label: "CSRF", Enabled: modules.CSRF, Scanner: csrf.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			// SRI runs after Endpoints/Crawler so page URLs are populated.
			{Label: "SRI", Enabled: modules.SRI, Scanner: sri.New(client)},
			// Backup probes per-endpoint backup suffixes + root archives.
			// Enabled on Standard and Deep; skipped on Safe profile.
			{Label: "Backup", Enabled: modules.Backup, Scanner: backup.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			// Wave 1 batch 2 — bounded exposure probes (advanced/ultra; safe
			// stays passive). Self-sufficient (homepage + well-known paths);
			// CSWSH/HiddenParams also consume discovered endpoints, and
			// HiddenParams/OAuth/SAML endpoints feed AuthZ/IDOR/Active below.
			{Label: "ExposedGit", Enabled: modules.ExposedGit, Scanner: exposedgit.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "ExposedConfig", Enabled: modules.ExposedConfig, Scanner: exposedconfig.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "Actuator", Enabled: modules.Actuator, Scanner: actuator.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "DebugPages", Enabled: modules.DebugPages, Scanner: debugpages.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "OAuthAnalyzer", Enabled: modules.OAuthAnalyzer, Scanner: oauth.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "SAMLMetadata", Enabled: modules.SAMLMetadata, Scanner: saml.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "CSWSH", Enabled: modules.CSWSH, Scanner: cswsh.New(), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "PostMessage", Enabled: modules.PostMessage, Scanner: postmessage.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "JSSecrets", Enabled: modules.JSSecrets, Scanner: jssecrets.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "Jsluice", Enabled: modules.Jsluice, Scanner: jsluice.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "HiddenParams", Enabled: modules.HiddenParams, Scanner: hiddenparams.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			// Wave 1 batch 3 — items 21-30. Clickjack/PolicyHeaders/CookiePrefix
			// are passive header analysis (safe for all, no SkipReason);
			// TakeoverPlus runs after Takeover while subdomains are hot; the
			// rest are bounded active probes whose endpoints feed AuthZ/Active.
			{Label: "VerbTamper", Enabled: modules.VerbTamper, Scanner: verbtamper.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "CacheDeception", Enabled: modules.CacheDeception, Scanner: cachedeception.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "ForbiddenBypass", Enabled: modules.ForbiddenBypass, Scanner: forbiddenbypass.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "TakeoverPlus", Enabled: modules.TakeoverPlus, Scanner: takeoverplus.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "Clickjack", Enabled: modules.Clickjack, Scanner: clickjack.New(client)},
			{Label: "PolicyHeaders", Enabled: modules.PolicyHeaders, Scanner: policyheaders.New(client)},
			{Label: "CookiePrefix", Enabled: modules.CookiePrefix, Scanner: cookieprefix.New(client)},
			{Label: "APIVersion", Enabled: modules.APIVersion, Scanner: apiversion.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "APIConsole", Enabled: modules.APIConsole, Scanner: apiconsole.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "VHost", Enabled: modules.VHost, Scanner: vhost.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			// Wave 1 batches 4-5 — items 31-50. JWTPlus/H2FP/GFClassify/
			// CertHistory/SubPermute are passive/archive analysis (safe for
			// all, no SkipReason); H2Smuggle additionally requires
			// --adversarial --confirm-authorized at runtime; the rest are
			// bounded active probes whose endpoints feed AuthZ/Active.
			{Label: "GraphQLFP", Enabled: modules.GraphQLFP, Scanner: graphqlfp.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "GraphQLSchema", Enabled: modules.GraphQLSchema, Scanner: graphqlschema.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "JWTPlus", Enabled: modules.JWTPlus, Scanner: jwtplus.New(client)},
			{Label: "SSTIExpand", Enabled: modules.SSTIExpand, Scanner: sstiexpand.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "NoSQLExpand", Enabled: modules.NoSQLExpand, Scanner: nosqlexpand.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "H2Smuggle", Enabled: modules.H2Smuggle, Scanner: h2smuggle.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "H2FP", Enabled: modules.H2FP, Scanner: h2fp.New(client)},
			{Label: "RedirectPack", Enabled: modules.RedirectPack, Scanner: redirectpack.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "LFIPack", Enabled: modules.LFIPack, Scanner: lfipack.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "CVEPack", Enabled: modules.CVEPack, Scanner: cvepack.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "CORSPlus", Enabled: modules.CORSPlus, Scanner: corsplus.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "CertHistory", Enabled: modules.CertHistory, Scanner: certhistory.New(client)},
			{Label: "AXFRPlus", Enabled: modules.AXFRPlus, Scanner: axfrplus.New(), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "SubPermute", Enabled: modules.SubPermute, Scanner: subpermute.New()},
			{Label: "BackupPlus", Enabled: modules.BackupPlus, Scanner: backupplus.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "FaviconPlus", Enabled: modules.FaviconPlus, Scanner: faviconplus.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "DebugMethods", Enabled: modules.DebugMethods, Scanner: debugmethods.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "EncodePoly", Enabled: modules.EncodePoly, Scanner: encodepoly.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "DiffOracle", Enabled: modules.DiffOracle, Scanner: difforacle.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "GFClassify", Enabled: modules.GFClassify, Scanner: gfclassify.New()},
			// Next-wave natives — bounded active probes (advanced/ultra).
			{Label: "Soap", Enabled: modules.Soap, Scanner: soap.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "Nsecwalk", Enabled: modules.Nsecwalk, Scanner: nsecwalk.New(), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "Wafdetect", Enabled: modules.Wafdetect, Scanner: wafdetect.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "Oauthpack", Enabled: modules.Oauthpack, Scanner: oauthpack.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "Ppollute", Enabled: modules.Ppollute, Scanner: ppollute.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "Swscope", Enabled: modules.Swscope, Scanner: swscope.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "Timeoracle", Enabled: modules.Timeoracle, Scanner: timeoracle.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "Jwtconfirm", Enabled: modules.Jwtconfirm, Scanner: jwtconfirm.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			// AuthZ runs after Endpoints/Dirs so both contexts probe the
			// full discovered attack surface.
			{Label: "AuthZ", Enabled: modules.AuthZ, Scanner: authzScanner},
			// IDOR/BOLA (Master P1): numeric id|user_id|order_id id+1 replay under contextB low-priv
			// (authz/scanner.go:40 same-URL diff today; coordination via
			// Session.Vault/ArtifactPool in interface.go).
			// Runs immediately after AuthZ while endpoints are still hot.
			// Enabled on advanced/ultra by default (read-only GETs, like Active);
			// off on safe to keep safe passive. Toggle via --enable/--disable idor.
			{Label: "IDOR", Enabled: modules.IDOR, Scanner: authz.NewIDOR(client), SkipReason: "safe profile is passive — use --profile advanced"},
			// Active runs last among ANPU built-ins so it benefits from
			// the complete endpoint list and technology fingerprints.
			{Label: "Active", Enabled: modules.Active, Scanner: active.New(client), SkipReason: "safe profile is passive — use --profile advanced"},
			// Dalfox confirms XSS on discovered parameterized URLs.
			{Label: "Dalfox", Enabled: modules.Dalfox, Scanner: dalfox, SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "Nuclei", Enabled: modules.Nuclei, Scanner: nuclei, SkipReason: "safe profile is passive — use --profile advanced"},
			{Label: "ZAP", Enabled: modules.ZAP, Scanner: zap, SkipReason: "ultra profile only (--profile ultra)"},
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
	// --only is absolute: anything left disabled was deselected, not
	// profile-gated — say so instead of the static SkipReason.
	if len(onlyMods) > 0 {
		sel := strings.Join(onlyMods, ",")
		for i := range pipe.Stages {
			if !pipe.Stages[i].Enabled {
				pipe.Stages[i].SkipReason = "not selected (--only " + sel + ")"
			}
		}
	}
	return pipe
}

// nativePhase assigns every built-in stage to a pipeline phase.
// Foundation = passive intel needing nothing; Discovery = crawlers and
// enumerators producing endpoints/hosts; Targeted = consumers probing
// discovered surface; Active = differentials, confirmations, and
// timing-sensitive work. Unlisted labels default to Targeted.
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
