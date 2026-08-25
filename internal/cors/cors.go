// Package cors checks whether the target reflects arbitrary Origins in
// Access-Control-Allow-Origin and/or pairs a permissive policy with
// credentials — the classic exploitable CORS misconfiguration that lets
// any website read authenticated responses cross-origin.
package cors

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// Scanner implements scanner.Scanner for CORS posture checks.
type Scanner struct {
	client *anpuhttp.Client
}

func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

func (s *Scanner) Name() string { return "cors" }

func (s *Scanner) Available(ctx context.Context) bool { return true }

var testOrigins = []string{
	"https://anpu-cors-probe.example.com",
	"null",
}

func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	var findings []models.Finding

	for _, origin := range testOrigins {
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		resp, err := s.client.DoWithHeaders(cctx, "GET", sc.Target.Raw,
			map[string]string{"Origin": origin})
		cancel()
		if err != nil {
			return scanner.StageResult{}, fmt.Errorf("CORS probe failed: %w", err)
		}
		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Credentials"))
		if acao == "" {
			continue
		}

		switch {
		case acao == "*" && strings.EqualFold(acac, "true"):
			findings = append(findings, corsFinding(sc, resp,
				"Wildcard CORS combined with credentials",
				"The response declares Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true. Per the fetch specification browsers reject this combination, but it signals confused intent; some non-browser clients and misbehaving middleware will honor both.",
				models.SeverityMedium))
		case acao == "*":
			findings = append(findings, corsFinding(sc, resp,
				"CORS allows any origin (no credentials)",
				"The response sets Access-Control-Allow-Origin: *, so any website can read this endpoint's responses from a visitor's browser. If the endpoint ever returns user-specific data without authentication cookies being required, that data is effectively public.",
				models.SeverityLow))
		case strings.Contains(acao, origin):
			if strings.EqualFold(acac, "true") {
				findings = append(findings, corsFinding(sc, resp,
					"CORS reflects arbitrary origins with credentials",
					fmt.Sprintf("The server reflected attacker-controlled Origin %q into Access-Control-Allow-Origin and allowed credentials. Any website can therefore make a visitor's browser read authenticated responses from %s cross-origin — full account-data disclosure for visitors of an attacker-chosen page.", origin, sc.Target.Host),
					models.SeverityHigh))
			} else {
				findings = append(findings, corsFinding(sc, resp,
					"CORS reflects arbitrary origins (credentials disabled)",
					fmt.Sprintf("The server reflected attacker-controlled Origin %q into Access-Control-Allow-Origin. Without Allow-Credentials the direct impact is limited to unauthenticated data, but the reflection itself is a misconfiguration worth fixing before credentials get enabled.", origin),
					models.SeverityMedium))
			}
		}
	}

	return scanner.StageResult{Findings: findings}, nil
}

func corsFinding(sc *scanner.ScanContext, resp *anpuhttp.Response, title, desc string, sev models.Severity) models.Finding {
	return models.Finding{
		ID:          "cors-" + slug(title),
		Title:       title,
		Description: desc,
		Severity:    sev,
		Confidence:  models.ConfidenceHigh,
		Category:    models.CategoryConfiguration,
		CWE:         "CWE-942",
		Target:      sc.Target.Raw,
		URL:         resp.FinalURL,
		Evidence: models.Evidence{
			Observed: fmt.Sprintf("Access-Control-Allow-Origin: %s\nAccess-Control-Allow-Credentials: %s",
				orNone(resp.Header.Get("Access-Control-Allow-Origin")),
				orNone(resp.Header.Get("Access-Control-Allow-Credentials"))),
			RequestSummary: "GET with Origin: <attacker-controlled>",
			Location:       "HTTP response headers",
		},
		Source:          models.SourceCustom,
		DetectionMethod: "origin-reflection probe",
		Impact:          "Cross-origin reads of API responses leak whatever the endpoint returns for the victim's session.",
		Remediation:     "Maintain an explicit allow-list of origins instead of reflecting request input; never combine wildcard origins with credentials.",
	}
}

func orNone(v string) string {
	if v == "" {
		return "(not set)"
	}
	return v
}

func slug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
