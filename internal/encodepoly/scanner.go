// Package encodepoly detects decoding/normalization layers (Wave 1
// item 48): double-encoding, case, and null-byte variants of a benign
// canary against one parameterized URL. Outcomes: (a) variant decoded
// and handled differently → Info "normalization layer present" (filter-
// evasion review); (b) 400/WAF-block on encoded but 200 on plain → Info
// "filter engages on encoding" (useful for tuning, not a vuln).
// GET-only, 13 requests max. No exploit payloads — canary strings only.
package encodepoly

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// maxRequests bounds all HTTP traffic: baseline + 11 variants + control.
const maxRequests = 13

var encodeVariants = []struct {
	name  string
	value string
}{
	{"plain", "anputest"},
	{"upper", "ANPUTEST"},
	{"double-encoded", "%2561nputest"},
	{"dot-encoded", "anputest%2e"},
	{"slash-encoded", "anputest%2f"},
	{"null-suffix", "anputest%00"},
	{"null-prefix", "%00anputest"},
	{"utf8-overlong", "%c0%asputest"},
	{"mixed-case-hex", "anputest%2E"},
	{"tab-infix", "anpu%09test"},
	{"newline-infix", "anpu%0atest"},
}

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "encodepoly" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	target, param := pickTarget(sc)
	if target == "" {
		return scanner.StageResult{}, nil
	}
	made := 0
	get := func(v string) *anpuhttp.Response {
		if made >= maxRequests {
			return nil
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		made++
		resp, err := s.client.Get(cctx, withRawParam(target, param, v))
		if err != nil || resp == nil {
			return nil
		}
		return resp
	}

	base := get("anputest")
	if base == nil {
		return scanner.StageResult{}, nil
	}
	baseSig := of(base)
	var decoded, blocked []string
	for _, ev := range encodeVariants[1:] {
		if made >= maxRequests {
			break
		}
		resp := get(ev.value)
		if resp == nil {
			continue
		}
		got := of(resp)
		if got == baseSig {
			continue
		}
		if resp.StatusCode == 400 || resp.StatusCode == 403 || resp.StatusCode == 406 {
			blocked = append(blocked, ev.name)
			continue
		}
		decoded = append(decoded, ev.name)
	}
	var findings []models.Finding
	if len(decoded) > 0 {
		findings = append(findings, models.Finding{
			ID: "encodepoly-normalization", Title: fmt.Sprintf("Decoding/normalization layer handles: %s", strings.Join(decoded, ", ")),
			Description: "Encoded canary variants decode server-side and change handling vs the plain baseline: a normalization layer sits before filters — the classic filter-evasion precondition. Re-test security filters with encoded equivalents. Canary strings only — no exploit payloads.",
			Severity:    models.SeverityInfo, Confidence: models.ConfidenceMedium, Category: models.CategoryExposure,
			Target: sc.Target.Raw, URL: target,
			Evidence: models.Evidence{Observed: "decoded variants: " + strings.Join(decoded, ", "), Location: "encoded canary matrix"},
			Source:   models.SourceCustom, DetectionMethod: "encoding-polymorphism canary matrix (encodepoly, ≤13 requests)",
		})
	}
	if len(blocked) > 0 {
		findings = append(findings, models.Finding{
			ID: "encodepoly-filter", Title: fmt.Sprintf("Filter engages on encoded input: %s", strings.Join(blocked, ", ")),
			Description: "Encoded variants are rejected (400/403/406) while plain passes: a filter/WAF normalizes before deciding. Useful tuning signal — verify it also normalizes double-encoding before allow decisions.",
			Severity:    models.SeverityInfo, Confidence: models.ConfidenceMedium, Category: models.CategoryExposure,
			Target: sc.Target.Raw, URL: target,
			Evidence: models.Evidence{Observed: "blocked variants: " + strings.Join(blocked, ", "), Location: "encoded canary matrix"},
			Source:   models.SourceCustom, DetectionMethod: "encoding-polymorphism canary matrix (encodepoly, ≤13 requests)",
		})
	}
	return scanner.StageResult{Findings: findings}, nil
}

func pickTarget(sc *scanner.ScanContext) (string, string) {
	for _, ep := range sc.Endpoints {
		u, err := url.Parse(ep.URL)
		if err != nil || !strings.EqualFold(u.Hostname(), sc.Target.Host) || u.RawQuery == "" {
			continue
		}
		for k := range u.Query() {
			return ep.URL, k
		}
	}
	return sc.Target.Raw + "?anpuprobe=1", "anpuprobe"
}

// withRawParam injects the value WITHOUT re-encoding (variants carry
// their own percent-encoding).
func withRawParam(raw, name, value string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	q.Del(name)
	enc := q.Encode()
	if enc != "" {
		enc += "&"
	}
	enc += url.QueryEscape(name) + "=" + value
	u.RawQuery = enc
	return u.String()
}

type sig struct {
	status int
	length int
}

func of(resp *anpuhttp.Response) sig {
	return sig{status: resp.StatusCode, length: len(resp.Body) / 64}
}
