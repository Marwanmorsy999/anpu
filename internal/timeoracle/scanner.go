// Package timeoracle detects timing oracles with statistical gates
// (Wave next, item 7): baseline distribution (5 plain samples), random
// control pair, then short-bounded sleep probes from two benign
// families (SQL SLEEP, command sleep). A probe median ≥1500ms above
// baseline median — with control inside 750ms and both probe repeats
// agreeing — is a Medium needs-review finding. GET-only, ≤11 requests,
// 2-second sleeps max. Flapping or ambiguous distributions stay
// silent: timing without stability is noise, never a finding.
package timeoracle

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// Budget and statistical gates.
const (
	maxRequests   = 11
	baselineN     = 5
	minSeparation = 1500 * time.Millisecond
	maxControlGap = 750 * time.Millisecond
)

var timeProbes = []struct {
	name    string
	payload string
}{
	{"sql-sleep", "1 AND SLEEP(2)-- -"},
	{"cmd-sleep", "$(sleep 2)"},
}

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "timeoracle" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

// median of durations (pure).
func median(ds []time.Duration) time.Duration {
	cp := append([]time.Duration(nil), ds...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	return cp[len(cp)/2]
}

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	target, param := pickTarget(sc)
	if target == "" {
		return scanner.StageResult{}, nil
	}
	made := 0
	timed := func(v string) (time.Duration, bool) {
		if made >= maxRequests {
			return 0, false
		}
		cctx, cancel := context.WithTimeout(ctx, 12*time.Second)
		defer cancel()
		made++
		start := time.Now()
		resp, err := s.client.Get(cctx, withParam(target, param, v))
		el := time.Since(start)
		if err != nil || resp == nil {
			return 0, false
		}
		return el, true
	}

	// Baseline distribution first: unstable baselines abort the test.
	var base []time.Duration
	for i := 0; i < baselineN; i++ {
		d, ok := timed("anputest")
		if !ok {
			return scanner.StageResult{}, nil
		}
		base = append(base, d)
	}
	bMed := median(base)
	sorted := append([]time.Duration(nil), base...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	if sorted[len(sorted)-1]-sorted[0] > maxControlGap {
		return scanner.StageResult{}, nil // jittery host: no oracle claims
	}
	// Random control must sit inside the baseline band.
	c1, ok1 := timed("anpuxyz9")
	c2, ok2 := timed("anpuxyz9")
	if !ok1 || !ok2 {
		return scanner.StageResult{}, nil
	}
	if absDur(c1-bMed) > maxControlGap || absDur(c2-bMed) > maxControlGap {
		return scanner.StageResult{}, nil
	}

	var findings []models.Finding
	for _, p := range timeProbes {
		if made+2 > maxRequests {
			break
		}
		p1, ok1 := timed(p.payload)
		p2, ok2 := timed(p.payload)
		if !ok1 || !ok2 {
			continue
		}
		// Both repeats must clear the separation bar (no single spike).
		if p1-bMed < minSeparation || p2-bMed < minSeparation {
			continue
		}
		findings = append(findings, models.Finding{
			ID: "timeoracle-sleep", Title: fmt.Sprintf("Timing oracle: %s sleeps consistently (%s)", p.name, param),
			Description: fmt.Sprintf("The %s sleep probe answers ~%s/~%s against a ~%s baseline median (control inside %s, both repeats agree): server-side execution reaches a sleep primitive — the blind-injection timing oracle. Confirm manually with single-condition probes before acting. Bounded 2s sleeps only. Reproduce: time curl TARGET with ?%s=<payload>.", p.name, p1.Round(time.Millisecond), p2.Round(time.Millisecond), bMed.Round(time.Millisecond), maxControlGap, param),
			Severity:    models.SeverityMedium, Confidence: models.ConfidenceLow, Category: models.CategoryVulnerability,
			CWE: "CWE-208", Target: sc.Target.Raw, URL: target,
			Evidence: models.Evidence{Observed: fmt.Sprintf("baseline ~%s, control ~%s/~%s, probe ~%s/~%s", bMed.Round(time.Millisecond), c1.Round(time.Millisecond), c2.Round(time.Millisecond), p1.Round(time.Millisecond), p2.Round(time.Millisecond)), Location: "repeat-timed differential"},
			Source:   models.SourceCustom, DetectionMethod: "statistical timing oracle (timeoracle, ≤11 requests)",
			Remediation: "Parameterize queries; block shell metacharacters; needs-review.",
		})
		break
	}
	return scanner.StageResult{Findings: findings}, nil
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
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
	// Fallback honors a query string already on the target instead of
	// appending a second "?" (which would orphan the injection).
	if u, err := url.Parse(sc.Target.Raw); err == nil && u.RawQuery != "" {
		for k := range u.Query() {
			return sc.Target.Raw, k
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
