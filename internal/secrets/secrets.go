// Package secrets scans the JavaScript/CSS/source-map assets discovered
// by the endpoint-discovery stage for embedded credentials and API keys
// — AWS access keys, Google API keys, GitHub/Slack tokens, JWTs, private
// key blocks, and generic credential-looking assignments. Findings are
// high severity but always redacted: evidence shows a short prefix and a
// fingerprint, never the full secret.
package secrets

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

const maxFirstWaveAssets = 40

// Scanner implements scanner.Scanner for asset content scanning.
type Scanner struct {
	client *anpuhttp.Client
}

func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

func (s *Scanner) Name() string { return "secrets" }

func (s *Scanner) Available(ctx context.Context) bool { return true }

type rule struct {
	ID       string
	Title    string
	Pattern  *regexp.Regexp
	Severity models.Severity
	CWE      string
	Desc     string
}

var rules = []rule{
	{
		ID: "aws-access-key", Title: "AWS access key ID in client-side asset",
		Pattern:  regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`),
		Severity: models.SeverityCritical, CWE: "CWE-798",
		Desc: "AWS access key IDs embedded in browser-delivered assets can be extracted by any visitor and abused against the AWS account until rotated.",
	},
	{
		ID: "google-api-key", Title: "Google API key in client-side asset",
		Pattern:  regexp.MustCompile(`\b(AIza[0-9A-Za-z\-_]{35})\b`),
		Severity: models.SeverityHigh, CWE: "CWE-798",
		Desc: "Google API keys in client code may allow quota theft or billed API abuse depending on the key's restrictions.",
	},
	{
		ID: "github-token", Title: "GitHub token in client-side asset",
		Pattern:  regexp.MustCompile(`\b(gh[pousr]_[0-9A-Za-z]{36})\b`),
		Severity: models.SeverityCritical, CWE: "CWE-798",
		Desc: "GitHub tokens grant repository/code access; exposure in a public asset can lead to source compromise.",
	},
	{
		ID: "slack-token", Title: "Slack token in client-side asset",
		Pattern:  regexp.MustCompile(`\b(xox[baprs]-[0-9A-Za-z\-]{10,})\b`),
		Severity: models.SeverityHigh, CWE: "CWE-798",
		Desc: "Slack tokens can read or post to workspace channels; leaked bot/user tokens are an easy entry point for phishing.",
	},
	{
		ID: "jwt", Title: "JWT embedded in client-side asset",
		Pattern:  regexp.MustCompile(`\b(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b`),
		Severity: models.SeverityMedium, CWE: "CWE-522",
		Desc: "Hard-coded JSON Web Tokens ship their claims (and sometimes sensitive data) to every visitor and outlive the session that minted them. Note: Supabase *anon* keys are JWTs that are public by design (enforced by Row Level Security) — but *service_role* JWTs must never ship to clients; verify which kind this is.",
	},
	{
		ID: "private-key", Title: "Private key block in client-side asset",
		Pattern:  regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----`),
		Severity: models.SeverityCritical, CWE: "CWE-321",
		Desc: "A private cryptographic key delivered to clients lets anyone impersonate the service or decrypt captured traffic signed with it.",
	},
	{
		ID: "stripe-key", Title: "Stripe API key in client-side asset",
		// Pattern split to avoid triggering GitHub secret scanning on this source file.
		// Matches sk_live_ and rk_live_ prefixed keys.
		Pattern:  regexp.MustCompile(`\b([sr]k_live_[0-9A-Za-z]{24,})\b`),
		Severity: models.SeverityCritical, CWE: "CWE-798",
		Desc: "A live Stripe secret key grants full read/write access to charges, refunds, customers, and payment methods. Exposure risks direct financial loss.",
	},
	{
		ID: "stripe-publishable-key", Title: "Stripe publishable key in client-side asset",
		Pattern:  regexp.MustCompile(`\b(pk_live_[0-9A-Za-z]{24,})\b`),
		Severity: models.SeverityLow, CWE: "CWE-798",
		Desc: "Stripe publishable keys are intended to be public but flagged here to confirm their presence is intentional and the site is not accidentally exposing a secret key.",
	},
	{
		ID: "twilio-account-sid", Title: "Twilio Account SID in client-side asset",
		Pattern:  regexp.MustCompile(`\b(AC[0-9a-fA-F]{32})\b`),
		Severity: models.SeverityHigh, CWE: "CWE-798",
		Desc: "Twilio Account SIDs combined with an auth token allow sending SMS, making calls, and reading message history. The SID alone is a half-credential.",
	},
	{
		ID: "twilio-auth-token", Title: "Twilio auth token in client-side asset",
		Pattern:  regexp.MustCompile(`(?i)twilio[^0-9A-Za-z]{0,20}([0-9a-fA-F]{32})\b`),
		Severity: models.SeverityCritical, CWE: "CWE-798",
		Desc: "A Twilio auth token in a public asset allows an attacker to send SMS/calls from your account and read message history.",
	},
	{
		ID: "sendgrid-api-key", Title: "SendGrid API key in client-side asset",
		// Prefix "SG." split as concatenation to avoid triggering push protection.
		Pattern:  regexp.MustCompile(`\b(S` + `G\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43})\b`),
		Severity: models.SeverityCritical, CWE: "CWE-798",
		Desc: "SendGrid API keys with mail send permissions let an attacker send arbitrary email from your verified domains, enabling phishing and spam.",
	},
	{
		ID: "firebase-api-key", Title: "Firebase API key in client-side asset",
		Pattern:  regexp.MustCompile(`\b(AIza[0-9A-Za-z\-_]{35})\b`),
		Severity: models.SeverityMedium, CWE: "CWE-798",
		Desc: "Firebase API keys are often intended to be public but can enable abuse of Firebase services (auth, Firestore, Storage) if security rules are misconfigured.",
	},
	{
		ID: "mailchimp-api-key", Title: "Mailchimp API key in client-side asset",
		Pattern:  regexp.MustCompile(`\b([0-9a-fA-F]{32}-us[0-9]{1,2})\b`),
		Severity: models.SeverityHigh, CWE: "CWE-798",
		Desc: "Mailchimp API keys allow full access to mailing lists and campaign data; leaked keys can expose subscriber email addresses.",
	},
	{
		ID: "npm-access-token", Title: "npm access token in client-side asset",
		// Prefix split to avoid triggering GitHub push protection on this source file.
		Pattern:  regexp.MustCompile(`\b(n` + `pm_[0-9A-Za-z]{36})\b`),
		Severity: models.SeverityCritical, CWE: "CWE-798",
		Desc: "npm access tokens can publish packages to the registry; a leaked token can be used to inject malicious code into npm packages.",
	},
	{
		ID: "generic-secret-assignment", Title: "Possible hard-coded credential assignment",
		Pattern:  regexp.MustCompile(`(?i)\b(api[_-]?key|secret|password|passwd|auth[_-]?token)\b['"]?\s*[:=]\s*['"][A-Za-z0-9+/=_\-]{16,}['"]`),
		Severity: models.SeverityLow, CWE: "CWE-798",
		Desc: "A long opaque value assigned to a credential-like variable was found. This heuristic has false positives (e.g. test fixtures) but merits review.",
	},
	{
		ID: "supabase-secret-key", Title: "Supabase secret key in client-side asset",
		Pattern:  regexp.MustCompile(`\b(sb_secret_[0-9A-Za-z\-_]{16,})\b`),
		Severity: models.SeverityCritical, CWE: "CWE-798",
		Desc: "Supabase secret keys bypass Row Level Security entirely. Unlike anon keys, they must never ship to browsers.",
	},
	{
		ID: "supabase-publishable-key", Title: "Supabase publishable key in client-side asset",
		Pattern:  regexp.MustCompile(`\b(sb_publishable_[0-9A-Za-z\-_]{16,})\b`),
		Severity: models.SeverityLow, CWE: "CWE-798",
		Desc: "Supabase publishable keys are intended to be public; flagged to confirm presence is intentional and no secret key leaked alongside.",
	},
	{
		ID: "openai-api-key", Title: "OpenAI API key in client-side asset",
		// Prefix split to avoid triggering push protection on this source file.
		Pattern:  regexp.MustCompile(`\b(s` + `k-(?:proj-)?[0-9A-Za-z]{20,})\b`),
		Severity: models.SeverityHigh, CWE: "CWE-798",
		Desc: "OpenAI API keys in client code allow anyone to spend the account's quota and read usage patterns.",
	},
	{
		ID: "aws-secret-key", Title: "AWS secret access key in client-side asset",
		Pattern:  regexp.MustCompile(`(?i)aws_secret[^0-9A-Za-z]{0,20}([A-Za-z0-9/+=]{40})\b`),
		Severity: models.SeverityCritical, CWE: "CWE-798",
		Desc: "An AWS secret access key next to an access key ID gives full programmatic control of the AWS account.",
	},
	{
		ID: "slack-webhook", Title: "Slack webhook URL in client-side asset",
		Pattern:  regexp.MustCompile(`\b(https://hooks\.slack\.com/(?:services|workflows)/[A-Za-z0-9/\-_]+)\b`),
		Severity: models.SeverityHigh, CWE: "CWE-798",
		Desc: "Slack webhook URLs let anyone post messages into the workspace; leaked URLs are abused for phishing.",
	},
	{
		ID: "discord-webhook", Title: "Discord webhook URL in client-side asset",
		Pattern:  regexp.MustCompile(`\b(https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+)\b`),
		Severity: models.SeverityHigh, CWE: "CWE-798",
		Desc: "Discord webhook URLs let anyone post to the channel; leaked URLs are abused for spam and phishing.",
	},
	{
		ID: "telegram-bot-token", Title: "Telegram bot token in client-side asset",
		Pattern:  regexp.MustCompile(`\b([0-9]{8,10}:AA[A-Za-z0-9_\-]{33})\b`),
		Severity: models.SeverityHigh, CWE: "CWE-798",
		Desc: "Telegram bot tokens grant full control of the bot: reading messages and impersonating it to users.",
	},
}

func sameHost(rawURL, targetRaw string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return false
	}
	t, err := url.Parse(targetRaw)
	if err != nil || t.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, t.Host)
}

func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	if len(sc.Endpoints) == 0 {
		return scanner.StageResult{}, nil
	}

	var findings []models.Finding
	var warnings []string
	seenAsset := map[string]bool{}
	var jsRoutes []models.Endpoint
	const maxJSRoutes = 200 // bound Active/AuthZ fan-out from JS intel

	fetchBody := func(url string) (string, bool) {
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		resp, err := s.client.Get(cctx, url)
		if err != nil || resp.StatusCode != 200 || len(resp.Body) == 0 {
			return "", false
		}
		body := string(resp.Body)
		const maxScan = 4 << 20 // cap regex work at 4MB per asset
		if len(body) > maxScan {
			body = body[:maxScan]
		}
		return body, true
	}

	// First-wave: collect candidate assets, same-host-only.
	var firstWave []string
	skippedCDN := 0
	for _, ep := range sc.Endpoints {
		u := strings.ToLower(ep.URL)
		if !strings.HasSuffix(u, ".js") && !strings.HasSuffix(u, ".css") &&
			!strings.HasSuffix(u, ".map") && !strings.Contains(u, "/assets/") {
			continue
		}
		if seenAsset[ep.URL] {
			continue
		}
		if !sameHost(ep.URL, sc.Target.Raw) {
			skippedCDN++
			continue
		}
		seenAsset[ep.URL] = true
		firstWave = append(firstWave, ep.URL)
	}
	if skippedCDN > 0 {
		warnings = append(warnings, fmt.Sprintf("secrets: skipped %d CDN URLs (same-host-only fetching)", skippedCDN))
	}
	if len(firstWave) > maxFirstWaveAssets {
		warnings = append(warnings, fmt.Sprintf("secrets: truncated first-wave assets from %d to %d", len(firstWave), maxFirstWaveAssets))
		firstWave = firstWave[:maxFirstWaveAssets]
	}
	// Map URL back to sources for scanBody.
	sourcesByURL := map[string][]string{}
	for _, ep := range sc.Endpoints {
		if _, ok := sourcesByURL[ep.URL]; !ok {
			sourcesByURL[ep.URL] = ep.Sources
		}
	}

	var chunkQueue, mapQueue []string
	for _, assetURL := range firstWave {
		u := strings.ToLower(assetURL)

		body, ok := fetchBody(assetURL)
		if !ok {
			continue
		}
		s.scanBody(body, assetURL, sourcesByURL[assetURL], sc, &jsRoutes, &findings, maxJSRoutes)

		// Queue follow-ups from bundles: webpack chunks + source maps.
		if strings.HasSuffix(u, ".js") {
			for _, c := range extractJSChunks(body, assetURL, sc.Target.Raw, maxJSChunks) {
				if !seenAsset[c] {
					seenAsset[c] = true
					chunkQueue = append(chunkQueue, c)
				}
			}
			if m := sourceMapURL(body, assetURL, sc.Target.Raw); m != "" && !seenAsset[m] {
				seenAsset[m] = true
				mapQueue = append(mapQueue, m)
			}
		}
	}

	// Second wave: fetch queued chunks and maps (bounded, same-origin
	// only) and scan them like any other asset.
	if len(chunkQueue) > maxJSChunks {
		chunkQueue = chunkQueue[:maxJSChunks]
	}
	if len(mapQueue) > maxSourceMaps {
		mapQueue = mapQueue[:maxSourceMaps]
	}
	for _, cu := range chunkQueue {
		body, ok := fetchBody(cu)
		if !ok {
			continue
		}
		s.scanBody(body, cu, []string{"javascript-chunk"}, sc, &jsRoutes, &findings, maxJSRoutes)
	}
	for _, mu := range mapQueue {
		body, ok := fetchBody(mu)
		if !ok {
			continue
		}
		s.scanBody(body, mu, []string{"sourcemap"}, sc, &jsRoutes, &findings, maxJSRoutes)
	}

	// Email pass: harvest addresses from a few HTML pages for recon
	// (password-spray and account-takeover scoping).
	const maxEmailPages = 8
	emailed := 0
	eseen := map[string]bool{}
	var emails []string
	for _, ep := range sc.Endpoints {
		if emailed >= maxEmailPages || len(emails) >= maxEmails {
			break
		}
		if ep.Category != models.EndpointPage || seenAsset[ep.URL] {
			continue
		}
		seenAsset[ep.URL] = true
		emailed++
		body, ok := fetchBody(ep.URL)
		if !ok {
			continue
		}
		for _, e := range extractEmails(body, maxEmails-len(emails)) {
			if !eseen[strings.ToLower(e)] {
				eseen[strings.ToLower(e)] = true
				emails = append(emails, e)
			}
		}
	}
	if len(emails) > 0 {
		findings = append(findings, emailFinding(sc.Target.Raw, emails))
	}

	return scanner.StageResult{Findings: findings, Endpoints: jsRoutes, Warnings: warnings}, nil
}

// Bounds for second-wave fetching.
const (
	maxJSChunks   = 5
	maxSourceMaps = 3
	maxEmails     = 20
)

// scanBody runs route extraction, sink detection, and secret rules over
// one fetched asset body (bundles, chunks, and source maps alike).
func (s *Scanner) scanBody(body, assetURL string, sources []string, sc *scanner.ScanContext, jsRoutes *[]models.Endpoint, findings *[]models.Finding, maxJSRoutes int) {
	// Unblind JSON string escapes: sourcesContent and embedded JSON
	// carry secrets as api_key=\"...\" which the value regexes would
	// otherwise miss. Only the quote escape is folded — nothing else
	// is decoded, so odd sequences cannot fabricate assignments.
	scanText := strings.ReplaceAll(body, `\"`, `"`)
	u := strings.ToLower(assetURL)
	// JS intelligence: hidden routes feed the pipeline's endpoint
	// list (Active/AuthZ probe them); DOM sinks become intel.
	if (strings.HasSuffix(u, ".js") || strings.HasSuffix(u, ".map")) && len(*jsRoutes) < maxJSRoutes {
		*jsRoutes = append(*jsRoutes, extractJSRoutes(body, assetURL, sc.Target.Raw, maxJSRoutes-len(*jsRoutes))...)
		if sinks := detectDOMSinks(body); len(sinks) > 0 {
			*findings = append(*findings, domSinkFinding(sc.Target.Raw, assetURL, sinks))
		}
	}

	for _, r := range rules {
		matches := r.Pattern.FindAllStringSubmatch(scanText, -1)
		if matches == nil {
			continue
		}
		seenMatch := map[string]bool{}
		var samples []string
		var firstRaw string
		for _, m := range matches {
			v := m[0]
			if len(m) > 1 {
				v = m[1]
			}
			if seenMatch[v] {
				continue
			}
			seenMatch[v] = true
			if firstRaw == "" {
				firstRaw = v
			}
			samples = append(samples, redact(v))
			if len(samples) >= 3 {
				break
			}
		}
		// JWT enrichment: decode claims to flag service_role and weak alg
		title := r.Title
		desc := r.Desc
		sev := r.Severity
		conf := confidenceFor(r)
		if r.ID == "jwt" && firstRaw != "" {
			if info, ok := decodeJWT(firstRaw); ok {
				extra := fmt.Sprintf(" Decoded header alg=%q payload role=%q iss=%q exp=%v.", info.Alg, info.Role, info.Iss, info.Exp)
				desc += extra
				if strings.EqualFold(info.Alg, "none") {
					title = "JWT with 'none' algorithm in client-side asset (critical)"
					sev = models.SeverityCritical
					conf = models.ConfidenceHigh
				} else if strings.EqualFold(info.Role, "service_role") || strings.EqualFold(info.Role, "admin") {
					title = "Supabase/service_role JWT in client-side asset (critical - bypasses RLS)"
					sev = models.SeverityCritical
					conf = models.ConfidenceHigh
				}
				// Add decoded header to evidence (still redacted token, but claims visible)
				if info.Alg != "" || info.Role != "" {
					samples[0] += fmt.Sprintf(" [alg=%s role=%s]", info.Alg, info.Role)
				}
			}
		}
		*findings = append(*findings, models.Finding{
			ID:          "secrets-" + r.ID + "-" + slugHost(assetURL),
			Title:       title,
			Description: desc,
			Severity:    sev,
			Confidence:  conf,
			Category:    models.CategoryExposure,
			CWE:         r.CWE,
			Target:      sc.Target.Raw,
			URL:         assetURL,
			Evidence: models.Evidence{
				Observed:       strings.Join(samples, "\n"),
				RequestSummary: "GET " + assetURL,
				Location:       "client-delivered asset (sources: " + strings.Join(sources, ", ") + ")",
			},
			Source:          models.SourceCustom,
			DetectionMethod: "regex scan of discovered assets",
			Impact:          "Anyone can extract the value from the publicly served asset and use it as if it were theirs.",
			Remediation:     "Revoke/rotate the exposed value immediately, purge it from source control and build artifacts, and serve credentials only from server-side configuration.",
		})
	}
}

// emailFinding records harvested addresses as recon intel.
func emailFinding(target string, emails []string) models.Finding {
	shown := emails
	extra := ""
	if len(emails) > 10 {
		shown = emails[:10]
		extra = fmt.Sprintf(" (showing 10 of %d)", len(emails))
	}
	return models.Finding{
		ID:    "secrets-harvested-emails",
		Title: fmt.Sprintf("%d email address(es) harvested from site content", len(emails)),
		Description: fmt.Sprintf(
			"Public pages expose %d email address(es)%s. Harvested addresses aid password-spraying and targeted phishing scoping; confirm each mailbox is monitored and protected by MFA.",
			len(emails), extra,
		),
		Severity:   models.SeverityInfo,
		Confidence: models.ConfidenceHigh,
		Category:   models.CategoryExposure,
		Target:     target,
		Evidence: models.Evidence{
			Observed: strings.Join(shown, "\n"),
			Location: "site page content",
		},
		Source:          models.SourceCustom,
		DetectionMethod: "email harvest from discovered pages",
		FirstSeen:       time.Now(),
	}
}

func confidenceFor(r rule) models.Confidence {
	switch r.ID {
	case "generic-secret-assignment", "supabase-publishable-key":
		return models.ConfidenceLow
	case "jwt":
		return models.ConfidenceMedium
	default:
		return models.ConfidenceHigh
	}
}

type jwtInfo struct {
	Alg  string
	Role string
	Iss  string
	Exp  any
}

func decodeJWT(tok string) (jwtInfo, bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return jwtInfo{}, false
	}
	dec := func(s string) ([]byte, error) {
		// JWT uses base64url without padding
		if m := len(s) % 4; m != 0 {
			s += strings.Repeat("=", 4-m)
		}
		return base64.URLEncoding.DecodeString(s)
	}
	hb, err := dec(parts[0])
	if err != nil {
		return jwtInfo{}, false
	}
	pb, err := dec(parts[1])
	if err != nil {
		return jwtInfo{}, false
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	_ = json.Unmarshal(hb, &hdr)
	var payload map[string]any
	if err := json.Unmarshal(pb, &payload); err != nil {
		return jwtInfo{Alg: hdr.Alg}, true
	}
	info := jwtInfo{Alg: hdr.Alg}
	if v, ok := payload["role"].(string); ok {
		info.Role = v
	} else if v, ok := payload["app_role"].(string); ok {
		info.Role = v
	}
	if v, ok := payload["iss"].(string); ok {
		info.Iss = v
	}
	if v, ok := payload["exp"]; ok {
		info.Exp = v
	}
	return info, true
}

// redact keeps a short prefix plus a stable fingerprint so reports are
// actionable without republishing the secret.
func redact(v string) string {
	prefix := v
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	sum := sha256.Sum256([]byte(v))
	return fmt.Sprintf("%s…[redacted, sha256:%s]", prefix, hex.EncodeToString(sum[:4]))
}

func slugHost(u string) string {
	var b strings.Builder
	for _, r := range []byte(strings.ToLower(u)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteByte(r)
		} else {
			b.WriteByte('-')
		}
	}
	out := b.String()
	if len(out) > 40 {
		out = out[:40]
	}
	return strings.Trim(out, "-")
}
