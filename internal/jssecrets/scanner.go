// Package jssecrets scans same-host JavaScript for embedded secrets
// (Wave 1 item 19): 40+ patterns (cloud keys, tokens, private keys,
// connection strings, generic assignments). 1 homepage GET + up to 8
// JS assets, static analysis only.
//
// Keyless honesty: strings are reported as exposed — never validated
// against providers (that would need credentials and network calls to
// third parties). Values are masked in evidence (prefix + ***).
// Severity High for private keys/cloud secrets, Medium for generic
// keys, all ConfidenceMedium (validity unconfirmed — rotate).
package jssecrets

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// maxAssets bounds JS asset fetches.
const maxAssets = 8

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "jssecrets" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

type pattern struct {
	name string
	re   *regexp.Regexp
	sev  models.Severity
}

func rx(s string) *regexp.Regexp { return regexp.MustCompile(s) }

// patterns is the 40+ secret pack. Order is stable for deterministic output.
func secretPatterns() []pattern {
	return []pattern{
		{"aws-access-key", rx(`\bAKIA[0-9A-Z]{16}\b`), models.SeverityHigh},
		{"aws-secret-key", rx(`(?i)aws[_-]?secret[_-]?access[_-]?key["'\s:=]+[A-Za-z0-9/+=]{30,}`), models.SeverityHigh},
		{"google-api-key", rx(`\bAIza[0-9A-Za-z_\-]{35}\b`), models.SeverityHigh},
		{"github-token", rx(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`), models.SeverityHigh},
		{"github-classic", rx(`\bghp_[A-Za-z0-9]{36}\b`), models.SeverityHigh},
		{"gitlab-token", rx(`\bglpat-[A-Za-z0-9_\-]{20,}\b`), models.SeverityHigh},
		{"slack-token", rx(`\bxox[baprs]-[A-Za-z0-9\-]{10,}\b`), models.SeverityHigh},
		{"slack-webhook", rx(`https://hooks\.slack\.com/services/[A-Za-z0-9/]+`), models.SeverityHigh},
		{"stripe-live", rx(`\bsk_live_[A-Za-z0-9]{10,}\b`), models.SeverityHigh},
		{"stripe-test", rx(`\bsk_test_[A-Za-z0-9]{10,}\b`), models.SeverityMedium},
		{"stripe-publishable", rx(`\bpk_live_[A-Za-z0-9]{10,}\b`), models.SeverityLow},
		{"private-key", rx(`-----BEGIN [A-Z ]*PRIVATE KEY-----`), models.SeverityHigh},
		{"heroku-key", rx(`\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`), models.SeverityLow},
		{"mailgun-key", rx(`\bkey-[0-9a-f]{32}\b`), models.SeverityHigh},
		{"mailchimp-key", rx(`\b[0-9a-f]{32}-us[0-9]{1,2}\b`), models.SeverityHigh},
		{"twilio-sid", rx(`\bAC[0-9a-f]{32}\b`), models.SeverityMedium},
		{"twilio-token", rx(`(?i)twilio[_-]?auth[_-]?token["'\s:=]+[A-Za-z0-9]{20,}`), models.SeverityHigh},
		{"sendgrid-key", rx(`\bSG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b`), models.SeverityHigh},
		{"firebase-url", rx(`https://[a-z0-9\-]+\.firebaseio\.com`), models.SeverityMedium},
		{"firebase-key", rx(`(?i)firebase[_-]?api[_-]?key["'\s:=]+[A-Za-z0-9_\-]{20,}`), models.SeverityMedium},
		{"azure-key", rx(`(?i)(azure|storage)[_-]?account[_-]?key["'\s:=]+[A-Za-z0-9/+=]{40,}`), models.SeverityHigh},
		{"discord-webhook", rx(`https://discord(app)?\.com/api/webhooks/[A-Za-z0-9/]+`), models.SeverityMedium},
		{"npm-token", rx(`\bnpm_[A-Za-z0-9]{20,}\b`), models.SeverityHigh},
		{"pypi-token", rx(`\bpypi-[A-Za-z0-9_\-]{20,}\b`), models.SeverityHigh},
		{"openai-key", rx(`\bsk-[A-Za-z0-9]{20,}\b`), models.SeverityHigh},
		{"anthropic-key", rx(`\bsk-ant-[A-Za-z0-9_\-]{20,}\b`), models.SeverityHigh},
		{"mapbox-key", rx(`\bpk\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`), models.SeverityMedium},
		{"algolia-key", rx(`(?i)algolia[_-]?(api[_-]?key|admin[_-]?key)["'\s:=]+[A-Za-z0-9]{20,}`), models.SeverityMedium},
		{"cloudinary-url", rx(`cloudinary://[A-Za-z0-9:@_\-]+`), models.SeverityHigh},
		{"mongodb-uri", rx(`mongodb(\+srv)?://[A-Za-z0-9_:@.\-/]+`), models.SeverityHigh},
		{"postgres-uri", rx(`postgres(ql)?://[A-Za-z0-9_:@.\-/]+`), models.SeverityHigh},
		{"mysql-uri", rx(`mysql://[A-Za-z0-9_:@.\-/]+`), models.SeverityHigh},
		{"redis-uri", rx(`redis://[A-Za-z0-9_:@.\-/]*:[^/\s]{4,}`), models.SeverityHigh},
		{"amqp-uri", rx(`amqps?://[A-Za-z0-9_:@.\-/]+`), models.SeverityHigh},
		{"jwt-secret-assign", rx(`(?i)jwt[_-]?secret["'\s:=]+[^"'\s;,]{8,}`), models.SeverityHigh},
		{"api-key-assign", rx(`(?i)["']?(api[_-]?key|apikey)["']?\s*[:=]\s*["'][A-Za-z0-9_\-]{12,}["']`), models.SeverityMedium},
		{"api-secret-assign", rx(`(?i)["']?(api[_-]?secret|apisecret|client[_-]?secret)["']?\s*[:=]\s*["'][A-Za-z0-9_\-]{12,}["']`), models.SeverityHigh},
		{"auth-token-assign", rx(`(?i)["']?(auth[_-]?token|access[_-]?token)["']?\s*[:=]\s*["'][A-Za-z0-9_\-.]{16,}["']`), models.SeverityMedium},
		{"password-assign", rx(`(?i)["']?(db[_-]?password|db[_-]?pass|password|passwd|pwd)["']?\s*[:=]\s*["'][^"']{6,}["']`), models.SeverityHigh},
		{"bearer-literal", rx(`(?i)bearer\s+[A-Za-z0-9_\-.]{24,}`), models.SeverityMedium},
		{"basic-auth-uri", rx(`https?://[A-Za-z0-9_\-]+:[A-Za-z0-9_\-]+@[A-Za-z0-9.\-]+`), models.SeverityHigh},
		{"aws-session-token", rx(`(?i)aws[_-]?session[_-]?token["'\s:=]+[A-Za-z0-9/+=]{40,}`), models.SeverityHigh},
		{"digitalocean-token", rx(`\bdop_v1_[A-Za-z0-9]{20,}\b`), models.SeverityHigh},
		{"cloudflare-token", rx(`(?i)cloudflare[_-]?(api[_-]?key|token)["'\s:=]+[A-Za-z0-9_\-]{20,}`), models.SeverityHigh},
		{"notion-token", rx(`\bsecret_[A-Za-z0-9]{20,}\b`), models.SeverityMedium},
		{"linear-key", rx(`\blin_api_[A-Za-z0-9]{20,}\b`), models.SeverityHigh},
		{"posthog-key", rx(`\bphc_[A-Za-z0-9]{20,}\b`), models.SeverityLow},
		{"segment-key", rx(`(?i)segment[_-]?write[_-]?key["'\s:=]+[A-Za-z0-9]{16,}`), models.SeverityMedium},
	}
}

var scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"']+)["']`)

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	made := 0
	get := func(u string) string {
		if made >= 1+maxAssets {
			return ""
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		made++
		resp, err := s.client.Get(cctx, u)
		if err != nil || resp == nil {
			return ""
		}
		if len(resp.Body) > 1024*1024 {
			return string(resp.Body[:1024*1024])
		}
		return string(resp.Body)
	}

	home := get(sc.Target.Raw)
	if home == "" {
		return scanner.StageResult{}, nil
	}
	base, err := url.Parse(sc.Target.Raw)
	if err != nil {
		return scanner.StageResult{}, nil
	}
	bodies := map[string]string{}
	for _, m := range scriptSrcRe.FindAllStringSubmatch(home, -1) {
		if len(bodies) >= maxAssets {
			break
		}
		ref, err := url.Parse(strings.TrimSpace(m[1]))
		if err != nil {
			continue
		}
		abs := base.ResolveReference(ref)
		if abs.Scheme != "http" && abs.Scheme != "https" {
			continue
		}
		if !strings.EqualFold(abs.Hostname(), sc.Target.Host) {
			continue
		}
		abs.Fragment = ""
		if _, ok := bodies[abs.String()]; ok {
			continue
		}
		if body := get(abs.String()); body != "" {
			bodies[abs.String()] = body
		}
	}
	// Also scan inline scripts on the homepage itself.
	bodies[sc.Target.Raw+"#inline"] = home

	type hit struct{ where, kind string }
	seen := map[string]bool{}
	var hits []hit
	pats := secretPatterns()
	for where, body := range bodies {
		for _, p := range pats {
			for _, m := range p.re.FindAllString(body, -1) {
				key := p.name + "|" + mask(m)
				if seen[key] {
					continue
				}
				seen[key] = true
				hits = append(hits, hit{where, p.name + ": " + mask(m)})
			}
		}
	}
	if len(hits) == 0 {
		return scanner.StageResult{}, nil
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].where == hits[j].where {
			return hits[i].kind < hits[j].kind
		}
		return hits[i].where < hits[j].where
	})
	if len(hits) > 6 {
		hits = hits[:6]
	}
	var findings []models.Finding
	for i, h := range hits {
		sev := models.SeverityMedium
		for _, p := range pats {
			if strings.HasPrefix(h.kind, p.name+":") {
				sev = p.sev
				break
			}
		}
		findings = append(findings, models.Finding{
			ID:              fmt.Sprintf("jssecrets-%d", i+1),
			Title:           "Embedded secret in JavaScript: " + kindOf(h.kind),
			Description:     "A shipped JavaScript file contains a secret-shaped string (" + h.kind + "). Anything in client JS is public — move the secret server-side and rotate it; validity was NOT tested (keyless). Reproduce: fetch the script and grep the pattern. Values are masked below.",
			Severity:        sev,
			Confidence:      models.ConfidenceMedium,
			Category:        models.CategoryExposure,
			CWE:             "CWE-798",
			Target:          sc.Target.Raw,
			URL:             h.where,
			Evidence:        models.Evidence{Observed: h.kind, Location: "shipped JavaScript (value masked)"},
			Source:          models.SourceCustom,
			DetectionMethod: "JS secret 40+ regex pack (jssecrets, ≤9 requests)",
			Remediation:     "Remove the secret from client code; rotate it.",
		})
	}
	return scanner.StageResult{Findings: findings}, nil
}

func kindOf(h string) string {
	if i := strings.Index(h, ":"); i > 0 {
		return h[:i]
	}
	return h
}

// mask keeps a short prefix for triage and hides the rest.
func mask(v string) string {
	v = strings.TrimSpace(v)
	if len(v) <= 8 {
		return "***"
	}
	return v[:4] + "***" + v[len(v)-3:]
}
