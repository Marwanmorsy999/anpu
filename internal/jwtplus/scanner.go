// Package jwtplus analyzes observed JWTs (Wave 1 item 33): 1 homepage
// GET plus already-discovered bodies/headers are scanned for
// JWT-shaped tokens, which are decoded (never verified — verification
// needs the secret) and checked for alg:none, jku/x5u/kid/x5c header
// confusion surface, and missing exp. Passive analysis, safe-eligible.
// No token is replayed, none is sent anywhere.
package jwtplus

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "jwtplus" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

var jwtRe = regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{0,}\b`)

// decodeHeader parses the JWT header without verifying (pure, tested).
func decodeHeader(token string) (map[string]any, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, false
	}
	var h map[string]any
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, false
	}
	if _, ok := h["alg"]; !ok {
		return nil, false
	}
	return h, true
}

// decodePayload parses claims without verifying (pure, tested).
func decodePayload(token string) (map[string]any, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	var c map[string]any
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, false
	}
	return c, true
}

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resp, err := s.client.Get(cctx, sc.Target.Raw)
	if err != nil || resp == nil {
		return scanner.StageResult{}, nil
	}
	corpus := string(resp.Body)
	for _, vals := range resp.Header {
		corpus += "\n" + strings.Join(vals, " ")
	}
	seen := map[string]bool{}
	var tokens []string
	for _, m := range jwtRe.FindAllString(corpus, -1) {
		if seen[m] {
			continue
		}
		if _, ok := decodeHeader(m); !ok {
			continue
		}
		seen[m] = true
		tokens = append(tokens, m)
		if len(tokens) >= 3 {
			break
		}
	}
	sort.Strings(tokens)
	var findings []models.Finding
	for i, tok := range tokens {
		h, _ := decodeHeader(tok)
		alg, _ := h["alg"].(string)
		if strings.ToLower(alg) == "none" {
			findings = append(findings, finding(sc.Target.Raw, fmt.Sprintf("jwtplus-none-%d", i+1),
				"JWT uses alg:none (signatureless token accepted)",
				"A shipped token declares alg:none: if any verifier trusts the header algorithm, signatures are skipped entirely. Never accept none; pin expected algorithms server-side.",
				models.SeverityHigh, "alg: none"))
			continue
		}
		var surface []string
		for _, k := range []string{"jku", "x5u", "kid", "x5c"} {
			if v, ok := h[k]; ok && v != nil && v != "" {
				surface = append(surface, k)
			}
		}
		if len(surface) > 0 {
			findings = append(findings, finding(sc.Target.Raw, fmt.Sprintf("jwtplus-confusion-%d", i+1),
				"JWT carries key-confusion headers ("+strings.Join(surface, ", ")+")",
				"Header parameters jku/x5u/kid/x5c let the token steer key resolution (key confusion, SSRF-to-JKU). Pin keys server-side and reject unlisted parameters.",
				models.SeverityMedium, "headers: "+strings.Join(surface, ", ")))
			continue
		}
		if claims, ok := decodePayload(tok); ok {
			if _, hasExp := claims["exp"]; !hasExp {
				findings = append(findings, finding(sc.Target.Raw, fmt.Sprintf("jwtplus-noexp-%d", i+1),
					"JWT carries no exp claim (non-expiring token)",
					"Without exp, a leaked token is valid indefinitely. Add short expiries plus rotation.",
					models.SeverityInfo, "missing exp claim"))
			}
		}
		if len(findings) >= 3 {
			break
		}
	}
	return scanner.StageResult{Findings: findings}, nil
}

func finding(target, id, title, desc string, sev models.Severity, observed string) models.Finding {
	return models.Finding{
		ID: id, Title: title, Description: desc + " Reproduce: copy the token from page source/headers and decode at jwt.io (offline). Tokens are never replayed.", Severity: sev,
		Confidence: models.ConfidenceHigh, Category: models.CategoryVulnerability, CWE: "CWE-347",
		Target: target, Evidence: models.Evidence{Observed: observed, Location: "shipped page/headers (decode-only)"},
		Source: models.SourceCustom, DetectionMethod: "JWT header/claims analysis (jwtplus, 1 request)",
		Remediation: "Pin algorithms and keys; add exp; never trust header key URLs.",
	}
}
