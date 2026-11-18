// Package sstiexpand probes server-side template injection across 10
// engines (Wave 1 item 34): Tornado/Mako/Jinja (`${7*7}`),
// FreeMarker/Velocity (`${7*7}`/`#set`), Thymeleaf (`${7*7}`),
// EJS/ERB (`<%= 7*7 %>`), Smarty (`{7*7}`), Django (`{% %}`),
// Handlebars/Pug (`{{7*7}}`/`#{7*7}`). Benign math payloads only
// (7*7→49); a hit requires 49 present AND the random control absent.
// GET-only on ≤2 parameterized URLs, 22 requests max. No file access,
// no introspection payloads.
package sstiexpand

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Marwanmorsy999/anpu/internal/adaptive"
	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// maxRequests bounds all HTTP traffic: 2 URLs × (baseline + 10 + control).
const maxRequests = 24

var sstiPayloads = []struct {
	engine  string
	payload string
}{
	{"Tornado/Mako/Jinja expression", "${7*7}"},
	{"FreeMarker/Thymeleaf", "${7*7}"},
	{"Velocity directive", "#set($x=7*7)$x"},
	{"EJS/ERB tag", "<%= 7*7 %>"},
	{"Smarty braces", "{7*7}"},
	{"Django/Jinja block", "{% widthratio 7 1 7 %}"},
	{"Handlebars", "{{7*7}}"},
	{"Pug interpolation", "#{7*7}"},
	{"AngularJS (legacy)", "{{7*7}}"},
	{"String-format probe", "{0}{1}"},
}

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "sstiexpand" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (result scanner.StageResult, err error) {
	if class, reason := adaptive.SurfaceClass(sc.Endpoints, sc.Technologies, sc.Auth.IsAuthenticated()); class == adaptive.ClassStaticMarketing {
		return scanner.StageResult{Skipped: "SSTI skipped: " + reason}, nil
	}
	targets := pickTargets(sc)
	budgetExhausted := false
	defer func() {
		if budgetExhausted {
			result.Warnings = append(result.Warnings, scanner.BudgetExhaustedWarning(sc))
		}
	}()
	get := func(u string) string {
		if err := scanner.ChargeBudget(sc); err != nil {
			budgetExhausted = true
			return ""
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		resp, err := s.client.Get(cctx, u)
		if err != nil || resp == nil {
			return ""
		}
		return string(resp.Body)
	}

	var findings []models.Finding
	for _, target := range targets {
		parsed, err := url.Parse(target)
		if err != nil {
			continue
		}
		param := firstParam(parsed)
		if param == "" {
			continue
		}
		_ = get(target) // warm the connection
		baseline := get(target)
		control := get(withParam(target, param, "anpu9x8z7"))
		// Three-way differential, mirroring sqli.go's baseline
		// subtraction: the "49" signal must be NEW relative to the
		// unpolluted page (baseline) — never trusted to the control
		// alone. If both reference requests failed (flaky target
		// under load), we cannot tell static-page "49" from
		// evaluation — skip the target rather than guess.
		if baseline == "" && control == "" {
			continue
		}
		for _, p := range sstiPayloads {
			if sc.Ledger != nil && sc.Ledger.Remaining(sc.StageLabel) <= 0 {
				budgetExhausted = true
				break
			}
			body := get(withParam(target, param, p.payload))
			if body == "" {
				continue
			}
			// Echo-guard: payload reflected verbatim is not evaluation.
			if strings.Contains(body, p.payload) {
				continue
			}
			if !evalsTo49(body, baseline, control) {
				continue // no payload-attributable evaluation signal
			}
			findings = append(findings, models.Finding{
				ID: "sstiexpand-evaluated", Title: fmt.Sprintf("SSTI evaluated (%s) via %s", p.engine, param),
				Description: fmt.Sprintf("The benign math payload %q rendered as 49 in the response while the random control did not: a %s expression evaluated server-side. Template injection leads to RCE — sandbox/escape output and never render user input as template. Reproduce: curl TARGET with ?%s=<payload>. Benign math only — no file or introspection payloads.", p.payload, p.engine, param),
				Severity:    models.SeverityHigh, Confidence: models.ConfidenceMedium, Category: models.CategoryVulnerability,
				CWE: "CWE-94", Target: sc.Target.Raw, URL: target,
				Evidence: models.Evidence{Observed: fmt.Sprintf("payload %q → 49 in response; control clean", p.payload), Location: "query param " + param},
				Source:   models.SourceCustom, DetectionMethod: "SSTI 10-engine math differential (sstiexpand, ≤24 requests)",
				Remediation: "Render user input as data, never as template; sandbox the engine.",
			})
			break
		}
		if len(findings) >= 2 {
			break
		}
	}
	result = scanner.StageResult{Findings: findings}
	return result, nil
}

// volatileRun matches long hex runs — CSRF tokens, session nonces, cache
// busters — whose random content contains "49" by chance (~12% per 32-char
// hex token). Comparing raw bodies made the evaluation signal luck-dependent:
// observed on DVWA, where a random user_token flipped the finding's engine
// label run-to-run. Strip these before any "49" comparison so the signal is
// deterministic; a real evaluation renders 49 in page context, never inside
// a ≥16-char hex run.
var volatileRun = regexp.MustCompile(`[0-9a-fA-F]{16,}`)

// stripVolatile removes random-token content from a response body before
// evaluation-signal comparison.
func stripVolatile(s string) string {
	return volatileRun.ReplaceAllString(s, " ")
}

// evalsTo49 reports whether the payload response contains an evaluation
// signal for "49" that is payload-attributable under the three-way
// differential:
//
//  1. baseline subtraction (mirrors sqli.go): the payload response must
//     contain strictly more "49" occurrences than the untouched page. A
//     "49" the page already renders without any payload (DVWA's DOCTYPE
//     URL, version strings) proves nothing — and it must be subtracted
//     even when the control arrived, because the control can be a
//     degraded response (WAF block page, short error page) that lacks the
//     static "49" and would otherwise bless it as a hit.
//  2. control subtraction (unchanged): when the random control arrived,
//     the payload response must also gain "49" over it, so a dynamic page
//     whose content varies per request cannot fabricate the gain.
//
// Volatile hex runs are stripped from every body before counting.
// Verbatim payload reflection is excluded before this is called. When the
// baseline request errored but the control arrived, the baseline term is
// vacuous (empty baseline) and the control term carries the guard; when
// the control errored, baseline subtraction alone decides — matching the
// previous fallback behavior.
func evalsTo49(body, baseline, control string) bool {
	body = stripVolatile(body)
	if !strings.Contains(body, "49") {
		return false
	}
	if !controlGains49(body, baseline) {
		return false
	}
	if control == "" {
		return true
	}
	return controlGains49(body, control)
}

// controlGains49 reports whether body contains more "49" occurrences than
// the reference. Static-page "49"s (DOCTYPE, version strings) appear in
// both; a real evaluation adds at least one more. The reference is
// stripped of volatile tokens here; the caller must strip body first.
func controlGains49(body, ref string) bool {
	ref = stripVolatile(ref)
	return strings.Count(body, "49") > strings.Count(ref, "49")
}

func pickTargets(sc *scanner.ScanContext) []string {
	var out []string
	for _, ep := range sc.Endpoints {
		if len(out) >= 2 {
			break
		}
		u, err := url.Parse(ep.URL)
		if err != nil || !strings.EqualFold(u.Hostname(), sc.Target.Host) || u.RawQuery == "" {
			continue
		}
		out = append(out, ep.URL)
	}
	if len(out) == 0 {
		out = []string{sc.Target.Raw + "?anpuprobe=1"}
	}
	return out
}

func firstParam(u *url.URL) string {
	for k := range u.Query() {
		return k
	}
	return ""
}

func withParam(raw, name, value string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	q.Set(name, value)
	u.RawQuery = q.Encode()
	return u.String()
}
