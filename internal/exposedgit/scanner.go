// Package exposedgit detects exposed .git repositories (Wave 1 item 11,
// detection-only): at most 4 requests (soft-404 control, /.git/HEAD,
// /.git/config, /HEAD fallback). It never fetches objects, packs, or
// logs — dumping history is adversarial-gated and lives in the
// git-dumper/gitjacker wrappers, not here.
//
// Baseline-subtract: a control 404 page filters catch-all fallbacks.
// Both markers (ref: line + [core] config) are required for High.
package exposedgit

import (
	"context"
	"strings"
	"time"

	"github.com/Marwanmorsy999/anpu/internal/fpmatch"
	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// maxRequests bounds all HTTP traffic for this stage.
const maxRequests = 4

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "exposedgit" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	made := 0
	get := func(path string) *anpuhttp.Response {
		if made >= maxRequests {
			return nil
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		made++
		resp, err := s.client.Get(cctx, strings.TrimSuffix(sc.Target.Raw, "/")+path)
		if err != nil || resp == nil {
			return nil
		}
		return resp
	}

	base := strings.TrimSuffix(sc.Target.Raw, "/")
	controlWords := map[string]struct{}{}
	if control := get("/anpu-exposedgit-control-404"); control != nil {
		controlWords = wordSet(control.Body)
		_ = base
	}

	head := get("/.git/HEAD")
	if head == nil || head.StatusCode != 200 {
		// Fallback: some deployments strip the dotfile but leave /HEAD.
		if h2 := get("/HEAD"); h2 == nil || h2.StatusCode != 200 || fpmatch.IsWAFBlockPage(h2.Body) || !isGitHead(string(h2.Body)) {
			return scanner.StageResult{}, nil
		} else if overlap(wordSet(h2.Body), controlWords) > 0.85 {
			return scanner.StageResult{}, nil // baseline-subtract
		} else {
			return singleMarker(sc, "/HEAD")
		}
	}
	body := string(head.Body)
	// Strict first-line markers (ref:/40-hex) cannot match SPA shells,
	// so no root fetch is needed here — but a WAF block page served as
	// 200 is still vetoed explicitly.
	if fpmatch.IsWAFBlockPage(head.Body) {
		return scanner.StageResult{}, nil
	}
	if !isGitHead(body) || overlap(wordSet(head.Body), controlWords) > 0.85 {
		return scanner.StageResult{}, nil // baseline-subtract: fallback page
	}
	// Confirm with config (second independent marker).
	conf := get("/.git/config")
	if conf != nil && conf.StatusCode == 200 && !fpmatch.IsWAFBlockPage(conf.Body) && strings.Contains(string(conf.Body), "[core]") {
		return scanner.StageResult{Findings: []models.Finding{{
			ID:              "exposedgit-repository",
			Title:           "Exposed .git repository (source code downloadable)",
			Description:     "Both /.git/HEAD and /.git/config are publicly readable: the full git history (source, secrets, past vulnerabilities) can be reconstructed with git-dumper. Block /.git at the edge, rotate any secret ever committed, and rewrite published history. Reproduce: curl -s TARGET/.git/HEAD (expect 'ref: refs/...'). Detection-only: ANPU never fetches objects.",
			Severity:        models.SeverityHigh,
			Confidence:      models.ConfidenceHigh,
			Category:        models.CategoryExposure,
			CWE:             "CWE-538",
			Target:          sc.Target.Raw,
			URL:             strings.TrimSuffix(sc.Target.Raw, "/") + "/.git/HEAD",
			Evidence:        models.Evidence{Observed: firstLine(body) + " + [core] in .git/config", Location: "/.git/HEAD + /.git/config"},
			Source:          models.SourceRecon,
			DetectionMethod: "exposed .git markers with 404 baseline (exposedgit, ≤4 requests)",
			Remediation:     "Deny /.git at the CDN/WAF/server; rotate exposed secrets.",
		}}}, nil
	}
	return singleMarker(sc, "/.git/HEAD")
}

func singleMarker(sc *scanner.ScanContext, path string) (scanner.StageResult, error) {
	return scanner.StageResult{Findings: []models.Finding{{
		ID:              "exposedgit-partial",
		Title:           "Possible exposed .git metadata (single marker)",
		Description:     "One git marker path returned git-like content but the second confirmatory marker did not. Verify manually before acting. Reproduce: curl -s TARGET" + path,
		Severity:        models.SeverityMedium,
		Confidence:      models.ConfidenceMedium,
		Category:        models.CategoryExposure,
		CWE:             "CWE-538",
		Target:          sc.Target.Raw,
		URL:             strings.TrimSuffix(sc.Target.Raw, "/") + path,
		Evidence:        models.Evidence{Observed: "single git marker matched", Location: path},
		Source:          models.SourceRecon,
		DetectionMethod: "exposed .git marker (exposedgit, ≤4 requests)",
	}}}, nil
}

// isGitHead matches "ref: refs/heads/..." or a bare 40-hex SHA.
func isGitHead(body string) bool {
	line := firstLine(body)
	if strings.HasPrefix(line, "ref: refs/") {
		return true
	}
	if len(line) == 40 && isHex(line) {
		return true
	}
	return false
}

func isHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return len(s) > 0
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	if len(s) > 120 {
		s = s[:120]
	}
	return strings.TrimSpace(s)
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
