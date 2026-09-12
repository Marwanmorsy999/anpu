// Package difforacle detects boolean response oracles (Wave 1 item 49):
// a true/false canary pair (anputrue/anpufalse values) plus a repeat-
// ability check against one parameterized URL. A consistent content
// difference between true and false — stable across repeats — is an
// Info "boolean oracle present" finding (blind-injection primitive
// for manual follow-up). Random-control equality kills the signal.
// GET-only, 8 requests max. Benign canaries only.
package difforacle

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

// maxRequests bounds all HTTP traffic: baseline + 2×(true+false) + control + repeats.
const maxRequests = 8

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "difforacle" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	target, param := pickTarget(sc)
	if target == "" {
		return scanner.StageResult{}, nil
	}
	made := 0
	get := func(v string) string {
		if made >= maxRequests {
			return ""
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		made++
		resp, err := s.client.Get(cctx, withParam(target, param, v))
		if err != nil || resp == nil {
			return ""
		}
		return string(resp.Body)
	}

	true1 := get("anputrue")
	false1 := get("anpufalse")
	if true1 == "" || false1 == "" || true1 == false1 {
		return scanner.StageResult{}, nil // no differential
	}
	// Stability: repeat both; flapping kills the signal.
	true2 := get("anputrue")
	false2 := get("anpufalse")
	if true2 == "" || false2 == "" || true1 != true2 || false1 != false2 {
		return scanner.StageResult{}, nil
	}
	// Random control must match one side (else the page is just unstable
	// per unique input — reflection, not a boolean oracle).
	control := get("anpuxyz9")
	if control != true1 && control != false1 {
		return scanner.StageResult{}, nil
	}
	return scanner.StageResult{Findings: []models.Finding{{
		ID: "difforacle-boolean", Title: fmt.Sprintf("Stable boolean response oracle on %s", param),
		Description: "True/false canaries produce two stable, distinct responses while a random control matches one side: the parameter drives a boolean decision visible in output — the primitive blind SQLi/NoSQL/SSTI extraction uses. Follow up manually with single-condition probes. Benign canaries only — no extraction attempted.",
		Severity:    models.SeverityInfo, Confidence: models.ConfidenceMedium, Category: models.CategoryExposure,
		Target: sc.Target.Raw, URL: target,
		Evidence: models.Evidence{Observed: fmt.Sprintf("true→%d bytes stable, false→%d bytes stable, control matches a side", len(true1), len(false1)), Location: "canary pair vs control"},
		Source:   models.SourceCustom, DetectionMethod: "boolean oracle differential (difforacle, ≤8 requests)",
	}}}, nil
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
