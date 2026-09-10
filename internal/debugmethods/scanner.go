// Package debugmethods probes dangerous HTTP methods (Wave 1 item 47):
// DEBUG, TRACE, TRACK, TEST via direct requests plus an OPTIONS
// Allow-header parse. A 200 to TRACE with echo (XST) is Medium; DEBUG
// executing (200 + distinct body vs GET baseline) is Medium; TEST/
// TRACK enabled is Low; 405/501 everywhere is silent. 8 requests max,
// empty bodies, read-only. Complements the Methods stage's OPTIONS
// audit with live dangerous-method verification.
package debugmethods

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// maxRequests bounds all HTTP traffic: OPTIONS + 4 methods + baselines.
const maxRequests = 8

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "debugmethods" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	made := 0
	do := func(method string, headers map[string]string) *anpuhttp.Response {
		if made >= maxRequests {
			return nil
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		made++
		var resp *anpuhttp.Response
		var err error
		if len(headers) == 0 && method == "GET" {
			resp, err = s.client.Get(cctx, sc.Target.Raw)
		} else {
			resp, err = s.client.DoWithHeaders(cctx, method, sc.Target.Raw, headers)
		}
		if err != nil || resp == nil {
			return nil
		}
		return resp
	}

	base := do("GET", nil)
	var baseWords map[string]struct{}
	if base != nil {
		baseWords = wordSet(base.Body)
	}
	_ = do("OPTIONS", nil) // warms Allow-header caches; verdicts come from live probes

	var findings []models.Finding
	// TRACE with echo = cross-site tracing (XST): cookies readable via TRACE.
	if resp := do("TRACE", map[string]string{"X-Anpu-Probe": "anputest9"}); resp != nil && resp.StatusCode == 200 && strings.Contains(string(resp.Body), "anputest9") {
		findings = append(findings, mkFinding(sc, "debugmethods-trace", "TRACE enabled with echo (XST)",
			"TRACE reflects the probe header: with HttpOnly bypass history, TRACE enables cross-site tracing cookie theft. Disable TRACE (TraceEnable Off). Empty-body probe — nothing executed.",
			models.SeverityMedium, "TRACE→200 echoes request"))
	}
	// DEBUG executing server-side logic (distinct from GET baseline).
	if resp := do("DEBUG", nil); resp != nil && resp.StatusCode == 200 && base != nil {
		if overlap(wordSet(resp.Body), baseWords) < 0.5 && len(resp.Body) > 0 {
			findings = append(findings, mkFinding(sc, "debugmethods-debug", "DEBUG method executes (distinct response)",
				"DEBUG returns 200 with content clearly different from GET: the method runs server-side logic. Disable DEBUG in production.",
				models.SeverityMedium, fmt.Sprintf("DEBUG→200 (%d bytes, dissimilar)", len(resp.Body))))
		}
	}
	// TEST/TRACK enabled (informational method-surface gap).
	for _, m := range []string{"TEST", "TRACK"} {
		if made >= maxRequests {
			break
		}
		if resp := do(m, nil); resp != nil && resp.StatusCode == 200 {
			findings = append(findings, mkFinding(sc, "debugmethods-"+strings.ToLower(m), m+" method enabled",
				"The "+m+" method answers 200: unnecessary method surface. Restrict to GET/HEAD/POST (+ app needs) explicitly.",
				models.SeverityLow, m+"→200"))
			break
		}
	}
	return scanner.StageResult{Findings: findings}, nil
}

func mkFinding(sc *scanner.ScanContext, id, title, desc string, sev models.Severity, observed string) models.Finding {
	return models.Finding{
		ID: id, Title: title,
		Description: desc + " Reproduce: curl -s -X METHOD -D- TARGET.",
		Severity:    sev, Confidence: models.ConfidenceHigh, Category: models.CategoryConfiguration, CWE: "CWE-749",
		Target: sc.Target.Raw, URL: sc.Target.Raw,
		Evidence: models.Evidence{Observed: observed, Location: "live method probe"},
		Source:   models.SourceCustom, DetectionMethod: "dangerous-method live probes (debugmethods, ≤8 requests)",
		Remediation: "Allowlist methods; disable TRACE/DEBUG/TRACK/TEST.",
	}
}

func wordSet(b []byte) map[string]struct{} {
	out := map[string]struct{}{}
	for _, w := range strings.Fields(strings.ToLower(string(b))) {
		if len(w) > 2 {
			out[w] = struct{}{}
		}
	}
	return out
}

func overlap(a, b map[string]struct{}) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	n := 0
	for w := range a {
		if _, ok := b[w]; ok {
			n++
		}
	}
	return float64(n) / float64(len(a))
}
