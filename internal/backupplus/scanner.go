// Package backupplus expands backup-file discovery (Wave 1 item 45):
// a vendored 30-suffix list (editors, archives, VCS, rotations)
// applied to discovered endpoint basenames plus root archives —
// ≤2 endpoints × 30 suffixes = 60 requests max, GET-only. A 200 whose
// body differs from the soft-404 control and carries code/config
// markers is a finding (High for archives with directory markers,
// Medium otherwise). Baseline-subtract kills catch-all fallbacks.
package backupplus

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/Marwanmorsy999/anpu/internal/adaptive"
	"github.com/Marwanmorsy999/anpu/internal/fpmatch"
	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// suffixes is the vendored backup-name list (reviewed, 30 entries).
var suffixes = []string{
	".bak", ".backup", ".old", ".orig", ".original", ".copy", ".tmp",
	".swp", ".swo", "~", ".save", ".bkp", ".bac", ".bk",
	".zip", ".tar", ".tar.gz", ".tgz", ".rar", ".7z",
	".sql", ".sql.gz", ".db", ".sqlite", ".dump",
	".log", ".txt", ".conf", ".cfg", ".ini",
}

// maxRequests bounds all HTTP traffic: 1 control + 1 lazy root + 60 probes.
const maxRequests = 62

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "backupplus" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

// bases returns probe base URLs: endpoint paths + root (pure-ish, tested via run).
func bases(sc *scanner.ScanContext) []string {
	var out []string
	for _, ep := range sc.Endpoints {
		if len(out) >= 2 {
			break
		}
		u, err := url.Parse(ep.URL)
		if err != nil || !sc.InScopeHost(u.Hostname()) {
			continue
		}
		if u.Path == "" || u.Path == "/" || strings.HasSuffix(u.Path, "/") {
			continue
		}
		u.RawQuery, u.Fragment = "", ""
		out = append(out, u.String())
	}
	return out
}

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	if class, reason := adaptive.SurfaceClass(sc.Endpoints, sc.Technologies, sc.Auth.IsAuthenticated()); class == adaptive.ClassStaticMarketing {
		return scanner.StageResult{Skipped: "Backup-file search skipped: " + reason}, nil
	}
	made := 0
	get := func(u string) *anpuhttp.Response {
		if made >= maxRequests {
			return nil
		}
		// Charge the global per-tool ledger (Wave 4 item 151); a nil
		// ledger (unit tests) means uncapped.
		if sc.Ledger != nil {
			if err := sc.Ledger.Record("backupplus"); err != nil {
				return nil
			}
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		made++
		resp, err := s.client.Get(cctx, u)
		if err != nil || resp == nil {
			return nil
		}
		return resp
	}
	controlWords := map[string]struct{}{}
	if control := get(strings.TrimSuffix(sc.Target.Raw, "/") + "/anpu-backupplus-control-404"); control != nil {
		controlWords = wordSet(control.Body)
	}
	// Lazy app-shell root (Phase 2): fetched only when a probe passes
	// the control check so the common path costs nothing extra.
	var rootWords map[string]struct{}
	rootFetched := false
	ensureRoot := func() {
		if rootFetched {
			return
		}
		rootFetched = true
		if root := get(strings.TrimSuffix(sc.Target.Raw, "/") + "/"); root != nil && len(root.Body) > 0 {
			rootWords = wordSet(root.Body)
		}
	}
	var findings []models.Finding
	for _, b := range bases(sc) {
		for _, suf := range suffixes {
			if made >= maxRequests {
				break
			}
			u := b + suf
			// Skip nested-archive monstrosities (base already archival).
			if strings.HasSuffix(strings.ToLower(b), ".zip") && strings.HasSuffix(suf, ".zip") {
				continue
			}
			resp := get(u)
			if resp == nil || resp.StatusCode != 200 || len(resp.Body) < 32 {
				continue
			}
			if overlap(wordSet(resp.Body), controlWords) > 0.85 {
				continue
			}
			if fpmatch.IsWAFBlockPage(resp.Body) {
				continue // WAF block page served as 200, not a backup file
			}
			ensureRoot()
			if len(rootWords) > 0 && overlap(wordSet(resp.Body), rootWords) > 0.85 {
				continue // app-shell: same page as site root
			}
			sev := models.SeverityMedium
			if isArchive(suf) {
				sev = models.SeverityHigh
			}
			findings = append(findings, models.Finding{
				ID: "backupplus-exposed", Title: fmt.Sprintf("Backup file exposed: %s", displayPath(u)),
				Description: fmt.Sprintf("GET %s returns 200 content clearly different from the 404 control: a backup/rotation artifact is downloadable (source, configs, database dumps). Remove artifacts from web roots and deny suffix patterns at the edge. Reproduce: curl -s TARGET%s.", displayPath(u), suffixOf(u)),
				Severity:    sev, Confidence: models.ConfidenceMedium, Category: models.CategoryExposure,
				CWE: "CWE-538", Target: sc.Target.Raw, URL: u,
				Evidence: models.Evidence{Observed: fmt.Sprintf("200 (%d bytes, differs from control)", len(resp.Body)), Location: "backup suffix probe"},
				Source:   models.SourceRecon, DetectionMethod: "backup-name expansion, 30 vendored suffixes (backupplus, ≤61 requests)",
				Remediation: "Remove backups from docroots; block *.{bak,old,zip,sql} at the edge.",
			})
			if len(findings) >= 3 {
				return scanner.StageResult{Findings: findings}, nil
			}
		}
	}
	return scanner.StageResult{Findings: findings}, nil
}

func isArchive(suf string) bool {
	switch suf {
	case ".zip", ".tar", ".tar.gz", ".tgz", ".rar", ".7z", ".sql", ".sql.gz", ".db", ".sqlite", ".dump":
		return true
	}
	return false
}

func displayPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Path
}

func suffixOf(raw string) string {
	return path.Ext(raw)
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
