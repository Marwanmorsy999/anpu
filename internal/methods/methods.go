// Package methods audits the HTTP methods the target advertises and
// accepts. TRACE is actively verified (cross-site tracing / XST) while
// other risky verbs reported in Allow/OPTIONS are flagged without being
// exercised, keeping the check polite.
package methods

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// Scanner implements scanner.Scanner for HTTP method auditing.
type Scanner struct {
	client *anpuhttp.Client
}

func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

func (m *Scanner) Name() string { return "methods" }

func (m *Scanner) Available(ctx context.Context) bool { return true }

// riskyMethods maps advertised methods to severity. TRACE is special:
// it is verified with a live request because browsers block it, so only
// a server-side echo matters for XST.
var riskyMethods = map[string]struct {
	Sev models.Severity
	Why string
	Fix string
	CWE string
}{
	"TRACE": {models.SeverityMedium,
		"TRACE echoes requests back; combined with browser-side flaws it enables Cross-Site Tracing to read cookies marked HttpOnly.",
		"Disable TRACE at the web server (e.g. TraceEnable off in Apache, limit_except in nginx).", "CWE-693"},
	"PUT": {models.SeverityLow,
		"The server advertises PUT; if actually enabled on writable paths it allows arbitrary file/resource creation.",
		"Verify PUT is rejected outside intended API routes and requires authentication.", "CWE-650"},
	"DELETE": {models.SeverityLow,
		"The server advertises DELETE; if enabled on unintended paths it allows resource destruction via crafted requests.",
		"Verify DELETE is rejected outside intended API routes and requires authentication.", "CWE-650"},
	"CONNECT": {models.SeverityMedium,
		"An open CONNECT method can turn the server into an outbound proxy (SSRF pivot).",
		"Disable CONNECT unless the server is an explicit proxy.", "CWE-441"},
}

func (m *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	var findings []models.Finding

	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	opts, err := m.client.DoWithHeaders(cctx, "OPTIONS", sc.Target.Raw, nil)
	cancel()
	if err != nil {
		return scanner.StageResult{}, fmt.Errorf("OPTIONS probe failed: %w", err)
	}

	allow := parseAllow(opts.Header.Get("Allow"), opts.Header.Get("Access-Control-Allow-Methods"))

	for verb, info := range riskyMethods {
		if !allow[verb] && !(verb == "TRACE") {
			continue
		}
		if verb == "TRACE" {
			ok, err := m.traceEchoes(ctx, sc.Target.Raw)
			if err != nil {
				continue
			}
			if !ok {
				continue
			}
			findings = append(findings, traceFinding(sc, info))
			continue
		}
		findings = append(findings, models.Finding{
			ID:          "methods-advertised-" + strings.ToLower(verb),
			Title:       fmt.Sprintf("Server advertises %s method", verb),
			Description: fmt.Sprintf("The OPTIONS response lists %s among allowed methods. %s", verb, info.Why),
			Severity:    info.Sev,
			Confidence:  models.ConfidenceLow,
			Category:    models.CategoryConfiguration,
			CWE:         info.CWE,
			Target:      sc.Target.Raw,
			URL:         sc.Target.Raw,
			Evidence: models.Evidence{
				Observed:       fmt.Sprintf("Allow: %s", opts.Header.Get("Allow")),
				RequestSummary: "OPTIONS /",
				Location:       "HTTP response headers",
			},
			Source:          models.SourceCustom,
			DetectionMethod: "OPTIONS probe",
			Impact:          "Depends on route-level enforcement; misconfigured generic handlers make these verbs exploitable.",
			Remediation:     info.Fix,
		})
	}

	return scanner.StageResult{Findings: findings}, nil
}

func (m *Scanner) traceEchoes(ctx context.Context, url string) (bool, error) {
	marker := "anpu-xst-marker-7f3a"
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resp, err := m.client.DoWithHeaders(cctx, "TRACE", url, map[string]string{"X-Anpu-Probe": marker})
	if err != nil || resp.StatusCode >= 400 {
		return false, nil
	}
	return strings.Contains(string(resp.Body), marker) ||
		strings.Contains(resp.Header.Get("X-Anpu-Probe"), marker), nil
}

func parseAllow(values ...string) map[string]bool {
	out := map[string]bool{}
	for _, v := range values {
		for _, part := range strings.Split(strings.ToUpper(v), ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				out[part] = true
			}
		}
	}
	return out
}

func traceFinding(sc *scanner.ScanContext, info struct {
	Sev models.Severity
	Why string
	Fix string
	CWE string
}) models.Finding {
	return models.Finding{
		ID:          "methods-trace-enabled",
		Title:       "HTTP TRACE is enabled (Cross-Site Tracing)",
		Description: "A TRACE request was echoed back by the server, confirming the method is active. " + info.Why,
		Severity:    info.Sev,
		Confidence:  models.ConfidenceConfirmed,
		Category:    models.CategoryConfiguration,
		CWE:         info.CWE,
		Target:      sc.Target.Raw,
		URL:         sc.Target.Raw,
		Evidence: models.Evidence{
			Observed:       "TRACE request echoed marker header/body",
			RequestSummary: "TRACE / with X-Anpu-Probe header",
			Location:       "HTTP response",
		},
		Source:          models.SourceCustom,
		DetectionMethod: "TRACE probe with unique marker",
		Impact:          "Historically used to bypass HttpOnly cookie protection via XST in old browsers; indicates permissive handler configuration.",
		Remediation:     info.Fix,
	}
}
