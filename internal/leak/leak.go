// Package leak detects private-network disclosures in HTTP responses:
// private IPv4 ranges (10/8, 172.16/12, 192.168/16, 127/8), link-local
// 169.254/16, and internal hostnames accidentally leaked into headers or
// bodies (Server, X-Forwarded-*, Via, HTML comments, JS). Such leaks
// help attackers map internal topology for SSRF/pivot.
//
// Passive, one GET to the target only, safe for every profile.
package leak

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// Scanner implements scanner.Scanner for private-IP leak detection.
type Scanner struct {
	client *anpuhttp.Client
}

func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

func (s *Scanner) Name() string                     { return "leak" }
func (s *Scanner) Available(_ context.Context) bool { return true }

var (
	// Private IPv4 patterns. Tight to avoid matching version strings.
	privateIPRe = regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3})\b`)
	// Internal hostname hints.
	internalHostRe = regexp.MustCompile(`(?i)\b([a-z0-9-]+\.internal|[a-z0-9-]+\.local|[a-z0-9-]+\.corp|[a-z0-9-]+\.lan)\b`)
	// Cloud metadata that should never be returned to a public client.
	cloudMetaRe = regexp.MustCompile(`(?i)169\.254\.169\.254|metadata\.google\.internal`)
)

func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	resp, err := s.client.WithAuth(sc.Auth.RequestHeaders()).Get(ctx, sc.Target.Raw)
	if err != nil || resp == nil {
		// Best-effort: don't fail the scan if the target is briefly flaky.
		return scanner.StageResult{Warnings: []string{fmt.Sprintf("leak: fetch %q: %v", sc.Target.Raw, err)}}, nil
	}
	var findings []models.Finding

	// 1) Headers
	for k, vals := range resp.Header {
		joined := strings.Join(vals, " ")
		if m := privateIPRe.FindString(joined); m != "" {
			findings = append(findings, finding(sc.Target.Raw, "header", k+": "+m, fmt.Sprintf("Response header %q leaks private IP %q", k, m)))
		}
		if m := internalHostRe.FindString(joined); m != "" {
			findings = append(findings, finding(sc.Target.Raw, "header", k+": "+m, fmt.Sprintf("Response header %q leaks internal hostname %q", k, m)))
		}
		if cloudMetaRe.MatchString(joined) {
			findings = append(findings, finding(sc.Target.Raw, "header", k+": metadata", "Response header leaks cloud metadata endpoint (169.254.169.254 / metadata.google.internal) — indicates SSRF-able template or debug leak"))
		}
	}

	// 2) Body (cap at 256k to keep regex cheap)
	body := resp.Body
	if len(body) > 256*1024 {
		body = body[:256*1024]
	}
	bs := string(body)
	seenIP := map[string]bool{}
	for _, m := range privateIPRe.FindAllString(bs, 5) {
		if seenIP[m] {
			continue
		}
		seenIP[m] = true
		// Filter version-like false positives: e.g., 10.0.0.1 inside a comment about a library version?
		// Keep it, but cap to 5 distinct IPs and rely on inspector to triage.
		findings = append(findings, finding(sc.Target.Raw, "body", m, fmt.Sprintf("Response body leaks private IP %q", m)))
	}
	seenHost := map[string]bool{}
	for _, m := range internalHostRe.FindAllString(bs, 5) {
		lower := strings.ToLower(m)
		if seenHost[lower] {
			continue
		}
		seenHost[lower] = true
		findings = append(findings, finding(sc.Target.Raw, "body", lower, fmt.Sprintf("Response body leaks internal hostname %q", lower)))
	}
	if cloudMetaRe.MatchString(bs) {
		m := cloudMetaRe.FindString(bs)
		findings = append(findings, finding(sc.Target.Raw, "body", m, "Response body leaks cloud metadata endpoint — indicates SSRF-able template or debug leak"))
	}

	// Deduplicate by title+evidence to keep report tidy (same IP in header+body should not duplicate).
	seenTitle := map[string]bool{}
	var uniq []models.Finding
	for _, f := range findings {
		k := f.Title + "|" + f.Evidence.Observed
		if seenTitle[k] {
			continue
		}
		seenTitle[k] = true
		uniq = append(uniq, f)
	}
	// Cap to avoid flooding on pages that intentionally list private ranges.
	if len(uniq) > 8 {
		uniq = uniq[:8]
	}
	return scanner.StageResult{Findings: uniq}, nil
}

func finding(target, where, observed, title string) models.Finding {
	sev := models.SeverityLow
	if strings.Contains(title, "metadata") {
		sev = models.SeverityMedium
	}
	return models.Finding{
		ID:              fmt.Sprintf("leak-%s-%d", where, hash(observed)),
		Title:           title,
		Description:     title + ". Internal topology disclosure helps attackers craft SSRF, pivot through NAT, or target internal services not meant to be internet-reachable.",
		Severity:        sev,
		Confidence:      models.ConfidenceMedium,
		Category:        models.CategoryExposure,
		CWE:             "CWE-200",
		Target:          target,
		Evidence:        models.Evidence{Observed: observed, Location: "HTTP " + where},
		Source:          models.SourceCustom,
		DetectionMethod: "passive header/body regex for private ranges and internal hostnames",
		Remediation:     "Strip private IPs/hostnames from public responses; use mapping tables or anonymized IDs instead of raw internal addresses.",
	}
}

func hash(s string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}
