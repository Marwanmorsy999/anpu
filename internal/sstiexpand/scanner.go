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
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
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
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	targets := pickTargets(sc)
	made := 0
	get := func(u string) string {
		if made >= maxRequests {
			return ""
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		made++
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
		_ = get(target) // baseline warms connection; detection is control-gated
		control := get(withParam(target, param, "anpu9x8z7"))
		for _, p := range sstiPayloads {
			if made >= maxRequests {
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
			if !strings.Contains(body, "49") {
				continue
			}
			if strings.Contains(control, "49") {
				continue // control already contains 49 — ambiguous
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
	return scanner.StageResult{Findings: findings}, nil
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
