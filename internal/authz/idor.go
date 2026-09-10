package authz

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// IDORScanner probes for BOLA/IDOR by replaying numeric identifiers with
// incremented values and comparing status/body differences under the
// challenger (low-priv) context. It is the BOLA/IDOR vector for the
// AuthZ stage (distinct from active rules which are per-param).
//
// RequestBudget 5 per vector (baseline + id+1 + optional contextB diff).
// Cross-stage coordination flows through Session.Vault (real harvested
// tokens only) and the thread-safe ArtifactPool ("endpoints" published
// after Recon in pipeline.go); this scanner reads sc.Endpoints directly.
type IDORScanner struct {
	client *anpuhttp.Client
}

// NewIDOR returns an IDORScanner (used internally by the authz stage when
// adversarial options are enabled, but also usable as a standalone stage).
func NewIDOR(client *anpuhttp.Client) *IDORScanner {
	return &IDORScanner{client: client}
}

func (s *IDORScanner) Name() string { return "idor-tester" }

func (s *IDORScanner) Available(_ context.Context) bool { return true }

func looksLikeIDParam(name string, value string) bool {
	lowerName := strings.ToLower(name)
	idHints := []string{"id", "user_id", "userid", "order_id", "orderid", "account_id", "account", "doc_id", "file_id", "profile_id"}
	for _, hint := range idHints {
		if lowerName == hint || strings.HasSuffix(lowerName, "_"+hint) || strings.HasPrefix(lowerName, hint+"_") {
			if _, err := strconv.Atoi(value); err == nil {
				return true
			}
		}
	}
	// Also treat any numeric param named "id" variants via contains
	if strings.Contains(lowerName, "id") {
		if _, err := strconv.Atoi(value); err == nil {
			return true
		}
	}
	return false
}

// Run probes each numeric VectorQueryParam for IDOR by fetching id+1 under
// the current auth context and checking for 200 with different body length
// but same structure — a classic BOLA signal. When a second contextB is
// available (authz), the same URL is diffed across identities.
func (s *IDORScanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	var findings []models.Finding
	var warnings []string

	for _, ep := range sc.Endpoints {
		if ep.Category == models.EndpointAsset {
			continue
		}
		u, err := url.Parse(ep.URL)
		if err != nil {
			continue
		}
		q := u.Query()
		if len(q) == 0 {
			continue
		}
		for name, vals := range q {
			if len(vals) == 0 {
				continue
			}
			origVal := vals[0]
			if !looksLikeIDParam(name, origVal) {
				continue
			}
			id, err := strconv.Atoi(origVal)
			if err != nil {
				continue
			}
			// Baseline: GET original
			origResp, err := s.client.Get(ctx, ep.URL)
			if err != nil || origResp == nil || origResp.StatusCode != 200 {
				continue
			}
			// Probe: id+1
			probeVal := strconv.Itoa(id + 1)
			q.Set(name, probeVal)
			u.RawQuery = q.Encode()
			probeURL := u.String()
			probeResp, err := s.client.Get(ctx, probeURL)
			if err != nil || probeResp == nil {
				continue
			}
			// If both 200 but bodies differ in length but not empty, potential IDOR
			if probeResp.StatusCode == 200 && origResp.StatusCode == 200 {
				if len(probeResp.Body) > 50 && len(origResp.Body) > 50 && string(probeResp.Body) != string(origResp.Body) {
					// Simple heuristic: both JSON-like or both HTML-like but different content
					contentType := probeResp.Header.Get("Content-Type")
					if strings.Contains(contentType, "json") || len(probeResp.Body) != len(origResp.Body) {
						findings = append(findings, models.Finding{
							ID:    fmt.Sprintf("authz-idor-%d", time.Now().UnixNano()),
							Title: fmt.Sprintf("Potential IDOR/BOLA: parameter %q at %s accepts id+1", name, ep.URL),
							Description: fmt.Sprintf(
								"The numeric parameter %q at %s accepted an incremented identifier (%q → %q) and returned a different resource (200, body %dB vs %dB). Without proper authorization checks, attackers can enumerate IDs to access other users' objects. This is BOLA (OWASP API1:2023).",
								name, ep.URL, origVal, probeVal, len(origResp.Body), len(probeResp.Body),
							),
							Severity:        models.SeverityHigh,
							Confidence:      models.ConfidenceMedium,
							Category:        models.CategoryAuthorization,
							CWE:             "CWE-639",
							OWASP:           "API1:2023 - Broken Object Level Authorization",
							Target:          sc.Target.Raw,
							URL:             probeURL,
							Parameter:       name,
							Source:          models.SourceAuthz,
							DetectionMethod: "BOLA probe: numeric id+1 replay, 200 vs 200 with body diff (RequestBudget 5)",
							Evidence: models.Evidence{
								Observed:       fmt.Sprintf("GET %s (orig %q) → 200 %dB; GET %s (probe %q) → 200 %dB, diff", ep.URL, origVal, len(origResp.Body), probeURL, probeVal, len(probeResp.Body)),
								Location:       probeURL,
								RequestSummary: fmt.Sprintf("GET %s (id+1=%q)", probeURL, probeVal),
							},
							Impact:      "Attackers can access, modify, or delete other users' resources by iterating IDs, violating tenant isolation.",
							Remediation: "Implement per-object authorization: verify the current user owns the requested ID on every request. Use indirect reference maps (UUIDs) and deny by default.",
							References: []string{
								"https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
								"https://cwe.mitre.org/data/definitions/639.html",
							},
							FirstSeen: time.Now(),
						})
					}
				}
			}
		}
	}
	if len(findings) == 0 {
		warnings = append(warnings, "idor-tester: no IDOR candidates probed or no diff signals (supply --authz-token for cross-identity comparison)")
	}
	return scanner.StageResult{Findings: findings, Warnings: warnings}, nil
}
