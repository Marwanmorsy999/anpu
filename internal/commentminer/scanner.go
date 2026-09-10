// Package commentminer extracts HTML comments from the homepage (Wave 1
// item 8): 2 requests max (page + soft-404 control). Comments matching
// fixme/todo/secret-like patterns become Low findings; everything else
// stays silent. Baseline-subtract: comments byte-identical on the
// control 404 page are template chrome and dropped. Echo-guard:
// conditional ([if IE]) and empty comments are skipped.
package commentminer

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// maxRequests bounds all HTTP traffic for this stage.
const maxRequests = 2

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "commentminer" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

var (
	commentRe   = regexp.MustCompile(`(?s)<!--(.*?)-->`)
	interestRe  = regexp.MustCompile(`(?i)\b(todo|fixme|hack|xxx|debug|secret|password|passwd|pwd|api[_-]?key|token|private[_-]?key|aws_|mongodb(\+srv)?://|BEGIN [A-Z ]*PRIVATE KEY)\b`)
	commentSkip = regexp.MustCompile(`(?i)^\s*(\[if|#|google|facebook|webpack|vite|gatsby)`)
)

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
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
	body := get(sc.Target.Raw)
	if body == "" {
		// Distinguish "no body" from fetch failure only by silence:
		// nothing to mine means no findings, never an error.
		return scanner.StageResult{}, nil
	}
	controlSet := map[string]bool{}
	if control := get(strings.TrimSuffix(sc.Target.Raw, "/") + "/anpu-comment-control-404"); control != "" {
		for _, c := range extractComments(control) {
			controlSet[c] = true
		}
	}
	seen := map[string]bool{}
	var hits []string
	for _, c := range extractComments(body) {
		if controlSet[c] || seen[c] {
			continue // baseline-subtract template chrome
		}
		seen[c] = true
		if interestRe.MatchString(c) {
			hits = append(hits, c)
		}
	}
	if len(hits) == 0 {
		return scanner.StageResult{}, nil
	}
	sort.Strings(hits)
	shown := hits
	if len(shown) > 5 {
		shown = shown[:5]
	}
	snippets := make([]string, 0, len(shown))
	for _, h := range shown {
		h = strings.Join(strings.Fields(h), " ")
		if len(h) > 160 {
			h = h[:160] + "..."
		}
		snippets = append(snippets, h)
	}
	return scanner.StageResult{Findings: []models.Finding{{
		ID:              "commentminer-interesting",
		Title:           fmt.Sprintf("%d interesting HTML comment(s)", len(hits)),
		Description:     "HTML comments mention TODO/credentials/internal paths. Comments ship to every visitor — move internal notes out of shipped HTML and rotate any exposed secret. Reproduce: curl the homepage and grep for '<!--'.",
		Severity:        models.SeverityLow,
		Confidence:      models.ConfidenceMedium,
		Category:        models.CategoryExposure,
		Target:          sc.Target.Raw,
		URL:             sc.Target.Raw,
		Evidence:        models.Evidence{Observed: strings.Join(snippets, " | "), Location: "HTML comments"},
		Source:          models.SourceRecon,
		DetectionMethod: "HTML comment mining (commentminer, 2 requests)",
		Remediation:     "Strip internal comments from production HTML; rotate any exposed credential.",
	}}}, nil
}

// extractComments returns cleaned, non-empty, non-conditional comments.
func extractComments(body string) []string {
	var out []string
	for _, m := range commentRe.FindAllStringSubmatch(body, -1) {
		c := strings.TrimSpace(m[1])
		if c == "" || commentSkip.MatchString(c) {
			continue // echo-guard
		}
		out = append(out, c)
	}
	return out
}
