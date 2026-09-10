// Package codesecrets scans a local code checkout for embedded secrets
// and infrastructure misconfigurations (Phase C): Terraform state and
// variables, dotenv files, Docker Compose files, Kubernetes manifests,
// and Dockerfiles. Zero target traffic — pure local file analysis, so
// it is safe-profile eligible. Gated on ANPU_CODE_DIR pointing at code
// you own; without it the stage warn-skips.
//
// Bounds: 300 files max, 2MB per file, version-control and dependency
// directories skipped, secret values masked in evidence (prefix + ***).
package codesecrets

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// Bounds for the local walk.
const (
	maxFiles    = 300
	maxFileSize = 2 << 20 // 2MB
	maxFindings = 15
)

// Scanner implements scanner.Scanner for local code scope.
type Scanner struct{}

// New builds a Scanner.
func New() *Scanner { return &Scanner{} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "codesecrets" }

// codeDir resolves the scan root (overridable via CodeDirOverride).
var codeDirOverride string

func codeDir() string {
	if codeDirOverride != "" {
		return codeDirOverride
	}
	return strings.TrimSpace(os.Getenv("ANPU_CODE_DIR"))
}

// Available implements scanner.Scanner: a code directory is configured.
func (s *Scanner) Available(_ context.Context) bool {
	info, err := os.Stat(codeDir())
	return err == nil && info.IsDir()
}

type pattern struct {
	name string
	re   *regexp.Regexp
	sev  models.Severity
	cwe  string
	kind string // "secret" or "misconfig"
}

func rx(s string) *regexp.Regexp { return regexp.MustCompile(s) }

// filePatterns targets IaC/config secret shapes beyond generic JS.
func filePatterns() []pattern {
	return []pattern{
		{"aws-secret", rx(`(?i)aws_secret_access_key["'\s:=]+[A-Za-z0-9/+=]{30,}`), models.SeverityHigh, "CWE-798", "secret"},
		{"generic-secret-assign", rx(`(?i)["']?(api[_-]?secret|secret[_-]?key|client[_-]?secret)["']?\s*[:=]\s*["'][A-Za-z0-9_\-]{12,}["']`), models.SeverityHigh, "CWE-798", "secret"},
		{"generic-token-assign", rx(`(?i)["']?(auth[_-]?token|access[_-]?token|bearer)["']?\s*[:=]\s*["'][A-Za-z0-9_\-.]{16,}["']`), models.SeverityMedium, "CWE-798", "secret"},
		{"db-password-assign", rx(`(?i)["']?(db[_-]?password|db[_-]?pass|mysql[_-]?root[_-]?password|postgres[_-]?password)["']?\s*[:=]\s*["'][^"']{4,}["']`), models.SeverityHigh, "CWE-798", "secret"},
		{"private-key", rx(`-----BEGIN [A-Z ]*PRIVATE KEY-----`), models.SeverityHigh, "CWE-798", "secret"},
		{"conn-string-creds", rx(`(?i)(mongodb(\+srv)?|postgres(ql)?|mysql|redis|amqp)s?://[^/\s]*:[^/\s]+@[A-Za-z0-9.\-]+`), models.SeverityHigh, "CWE-798", "secret"},
		{"slack-token", rx(`\bxox[baprs]-[A-Za-z0-9\-]{10,}\b`), models.SeverityHigh, "CWE-798", "secret"},
		{"github-token", rx(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`), models.SeverityHigh, "CWE-798", "secret"},
		{"stripe-key", rx(`\bsk_(live|test)_[A-Za-z0-9]{10,}\b`), models.SeverityHigh, "CWE-798", "secret"},
		{"tf-public-acl", rx(`(?i)acl\s*=\s*"(public-read|authenticated-read|bucket-owner-full-control)"`), models.SeverityMedium, "CWE-732", "misconfig"},
		{"k8s-privileged", rx(`(?i)privileged\s*:\s*true`), models.SeverityHigh, "CWE-250", "misconfig"},
		{"k8s-host-network", rx(`(?i)host[Nn]etwork\s*:\s*true`), models.SeverityMedium, "CWE-250", "misconfig"},
		{"k8s-priv-esc", rx(`(?i)allowPrivilegeEscalation\s*:\s*true`), models.SeverityMedium, "CWE-250", "misconfig"},
		{"docker-privileged", rx(`(?im)^\s*privileged\s*:\s*true`), models.SeverityHigh, "CWE-250", "misconfig"},
		{"docker-host-network", rx(`(?im)^\s*network_mode\s*:\s*["']?host["']?`), models.SeverityMedium, "CWE-250", "misconfig"},
		{"docker-sock-mount", rx(`(?i)/var/run/docker\.sock`), models.SeverityHigh, "CWE-250", "misconfig"},
		{"tf-unencrypted-state", rx(`(?i)encrypt\s*=\s*false`), models.SeverityMedium, "CWE-311", "misconfig"},
	}
}

// skipDirs prunes version-control and dependency trees from the walk.
var skipDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true, "node_modules": true,
	"vendor": true, "__pycache__": true, ".venv": true, "venv": true,
	"dist": true, "build": true, ".terraform": true, "target": true,
}

// skipExts drops obvious binary/media formats.
var skipExts = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".ico": true,
	".pdf": true, ".zip": true, ".tar": true, ".gz": true, ".exe": true,
	".bin": true, ".dll": true, ".so": true, ".woff": true, ".woff2": true,
	".mp4": true, ".mp3": true, ".ogg": true, ".lockb": true,
}

// Run implements scanner.Scanner.
func (s *Scanner) Run(_ context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	root := codeDir()
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		return scanner.StageResult{Warnings: []string{
			"codesecrets skipped: set ANPU_CODE_DIR=/path/to/local/code (local code scope only)"}}, nil
	}
	pats := filePatterns()
	type hit struct {
		file    string
		kind    string
		finding models.Finding
	}
	var hits []hit
	filesSeen := 0
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || len(hits) >= maxFindings || filesSeen >= maxFiles {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if skipExts[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() == 0 || info.Size() > maxFileSize {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		filesSeen++
		rel, _ := filepath.Rel(root, path)
		if rel == "" {
			rel = path
		}
		body := string(data)
		for _, p := range pats {
			for _, m := range p.re.FindAllString(body, -1) {
				hits = append(hits, hit{file: rel, kind: p.name, finding: models.Finding{
					ID: "codesecrets-" + p.name, Title: describe(p, rel),
					Description: "Local code review hit (" + p.kind + "). " + remediate(p.kind),
					Severity:    p.sev, Confidence: models.ConfidenceMedium, Category: models.CategoryExposure,
					CWE: p.cwe, Target: sc.Target.Raw,
					Evidence: models.Evidence{Observed: p.name + ": " + mask(m), Location: rel},
					Source:   models.SourceCustom, DetectionMethod: "local IaC/config review (codesecrets, offline)",
				}})
				break // one finding per pattern per file
			}
			if len(hits) >= maxFindings {
				break
			}
		}
		return nil
	})
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].file == hits[j].file {
			return hits[i].kind < hits[j].kind
		}
		return hits[i].file < hits[j].file
	})
	var findings []models.Finding
	for _, h := range hits {
		h.finding.Scope = models.ScopeLocalCode
		findings = append(findings, h.finding)
	}
	return scanner.StageResult{Findings: findings}, nil
}

func describe(p pattern, file string) string {
	if p.kind == "secret" {
		return "Embedded secret in " + file + " (" + p.name + ")"
	}
	return "Risky configuration in " + file + " (" + p.name + ")"
}

func remediate(kind string) string {
	if kind == "secret" {
		return "Move the value to a secret manager; rotate it; purge history."
	}
	return "Apply least privilege; re-scan after hardening."
}

// mask keeps a short prefix for triage and hides the rest.
func mask(v string) string {
	v = strings.TrimSpace(v)
	if len(v) <= 8 {
		return "***"
	}
	return v[:4] + "***" + v[len(v)-3:]
}
