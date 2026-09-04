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
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

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
		Desc: "Hard-coded JSON Web Tokens ship their claims (and sometimes sensitive data) to every visitor and outlive the session that minted them.",
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
}

func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	if len(sc.Endpoints) == 0 {
		return scanner.StageResult{}, nil
	}

	var findings []models.Finding
	seenAsset := map[string]bool{}

	for _, ep := range sc.Endpoints {
		u := strings.ToLower(ep.URL)
		if !strings.HasSuffix(u, ".js") && !strings.HasSuffix(u, ".css") &&
			!strings.HasSuffix(u, ".map") && !strings.Contains(u, "/assets/") {
			continue
		}
		if seenAsset[ep.URL] {
			continue
		}
		seenAsset[ep.URL] = true

		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		resp, err := s.client.Get(cctx, ep.URL)
		cancel()
		if err != nil || resp.StatusCode != 200 || len(resp.Body) == 0 {
			continue
		}
		body := string(resp.Body)
		const maxScan = 4 << 20 // cap regex work at 4MB per asset
		if len(body) > maxScan {
			body = body[:maxScan]
		}

		for _, r := range rules {
			matches := r.Pattern.FindAllStringSubmatch(body, -1)
			if matches == nil {
				continue
			}
			seenMatch := map[string]bool{}
			var samples []string
			for _, m := range matches {
				v := m[0]
				if len(m) > 1 {
					v = m[1]
				}
				if seenMatch[v] {
					continue
				}
				seenMatch[v] = true
				samples = append(samples, redact(v))
				if len(samples) >= 3 {
					break
				}
			}
			findings = append(findings, models.Finding{
				ID:          "secrets-" + r.ID + "-" + slugHost(ep.URL),
				Title:       r.Title,
				Description: r.Desc,
				Severity:    r.Severity,
				Confidence:  confidenceFor(r),
				Category:    models.CategoryExposure,
				CWE:         r.CWE,
				Target:      sc.Target.Raw,
				URL:         ep.URL,
				Evidence: models.Evidence{
					Observed:       strings.Join(samples, "\n"),
					RequestSummary: "GET " + ep.URL,
					Location:       "client-delivered asset (sources: " + strings.Join(ep.Sources, ", ") + ")",
				},
				Source:          models.SourceCustom,
				DetectionMethod: "regex scan of discovered assets",
				Impact:          "Anyone can extract the value from the publicly served asset and use it as if it were theirs.",
				Remediation:     "Revoke/rotate the exposed value immediately, purge it from source control and build artifacts, and serve credentials only from server-side configuration.",
			})
		}
	}

	return scanner.StageResult{Findings: findings}, nil
}

func confidenceFor(r rule) models.Confidence {
	switch r.ID {
	case "generic-secret-assignment":
		return models.ConfidenceLow
	case "jwt":
		return models.ConfidenceMedium
	default:
		return models.ConfidenceHigh
	}
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
