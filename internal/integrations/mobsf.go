// Package integrations — mobsf.go: MobSF static-analysis wrapper.
//
// Mobile scope is file-gated, never URL-driven: ANPU_APK points at an
// APK/IPA you own, ANPU_MOBSF_URL at your operator-run MobSF server,
// ANPU_MOBSF_KEY at its API key (your own infra credential, like
// --auth-token — never a third-party service key). Static analysis
// only; dynamic analysis is never implemented or invoked.
//
// Every step is fail-soft: missing APK/server/key skip with guidance,
// HTTP/API mismatches warn with trimmed bodies. Nothing uploads
// anywhere except the operator-configured server.
package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// MobSF timeouts: upload/scan/report are each bounded; the report is
// polled a few times because static analysis takes a while.
const (
	mobsfOpTimeout = 30 * time.Second
	mobsfPollWait  = 5 * time.Second
	mobsfPollTries = 3
)

// MobSFScanner implements scanner.Scanner against an operator server.
type MobSFScanner struct {
	// Overrides (tests + programmatic use). Empty falls back to env.
	ServerURL string
	APIKey    string
	APKPath   string
}

// NewMobSFScanner builds a MobSFScanner.
func NewMobSFScanner() *MobSFScanner { return &MobSFScanner{} }

// Name implements scanner.Scanner.
func (m *MobSFScanner) Name() string { return "mobsf" }

func (m *MobSFScanner) server() string {
	if m.ServerURL != "" {
		return strings.TrimSuffix(m.ServerURL, "/")
	}
	return strings.TrimSuffix(os.Getenv("ANPU_MOBSF_URL"), "/")
}

func (m *MobSFScanner) key() string {
	if m.APIKey != "" {
		return m.APIKey
	}
	return os.Getenv("ANPU_MOBSF_KEY")
}

func (m *MobSFScanner) apk() string {
	if m.APKPath != "" {
		return m.APKPath
	}
	return os.Getenv("ANPU_APK")
}

// Available implements scanner.Scanner: an APK file is configured.
// Server reachability is checked at run time (fail-soft).
func (m *MobSFScanner) Available(_ context.Context) bool {
	info, err := os.Stat(m.apk())
	return err == nil && !info.IsDir()
}

// Run implements scanner.Scanner: upload → scan → report_json → findings.
func (m *MobSFScanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	apk := m.apk()
	if info, err := os.Stat(apk); err != nil || info.IsDir() {
		return scanner.StageResult{Warnings: []string{
			"mobsf skipped: set ANPU_APK=/path/to/app.apk (mobile scope; static first, dynamic never auto-run)"}}, nil
	}
	server, key := m.server(), m.key()
	if server == "" || key == "" {
		return scanner.StageResult{Warnings: []string{
			"mobsf skipped: set ANPU_MOBSF_URL + ANPU_MOBSF_KEY to your operator-run MobSF server (static analysis only)"}}, nil
	}
	hash, err := m.upload(ctx, server, key, apk)
	if err != nil {
		return scanner.StageResult{Warnings: []string{fmt.Sprintf("mobsf upload failed: %v", trimMiddle(err.Error(), 200))}}, nil
	}
	_ = m.startScan(ctx, server, key, hash) // best-effort: uploads often auto-scan
	var report []byte
	for i := 0; i < mobsfPollTries; i++ {
		report, err = m.fetchReport(ctx, server, key, hash)
		if err == nil && len(report) > 0 {
			break
		}
		select {
		case <-ctx.Done():
			return scanner.StageResult{}, nil
		case <-time.After(mobsfPollWait):
		}
	}
	if len(report) == 0 {
		return scanner.StageResult{Warnings: []string{"mobsf: static report not ready (upload ok, analysis pending)"}}, nil
	}
	findings := parseMobSFReport(report, sc.Target.Raw, apk)
	for i := range findings {
		findings[i].Scope = models.ScopeLocalCode
	}
	findings = append(findings, models.Finding{
		ID: "mobsf-static", Title: "MobSF static analysis completed",
		Description: fmt.Sprintf("Static analysis of %s finished via the operator MobSF server (%d finding(s) below). Dynamic analysis is never run by ANPU.", apk, len(findings)),
		Severity:    models.SeverityInfo, Confidence: models.ConfidenceHigh, Category: models.CategoryExposure,
		Scope:    models.ScopeLocalCode,
		Target:   sc.Target.Raw,
		Evidence: models.Evidence{Observed: "hash " + hash, Location: "mobsf static report"},
		Source:   models.SourceCustom, DetectionMethod: "mobsf static (operator server)",
	})
	return scanner.StageResult{Findings: findings}, nil
}

func (m *MobSFScanner) doJSON(ctx context.Context, server, key, method, path string, form url.Values, fileField, filePath string) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, mobsfOpTimeout)
	defer cancel()
	var body io.Reader
	var contentType string
	if fileField != "" {
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		fw, err := w.CreateFormFile(fileField, fileNameOf(filePath))
		if err != nil {
			return nil, err
		}
		f, err := os.Open(filePath) // #nosec G304 -- operator-supplied APK path (ANPU_APK) for upload to the operator MobSF server.
		if err != nil {
			return nil, err
		}
		defer f.Close()
		if _, err := io.Copy(fw, f); err != nil {
			return nil, err
		}
		for k, vs := range form {
			for _, v := range vs {
				_ = w.WriteField(k, v)
			}
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
		body = &buf
		contentType = w.FormDataContentType()
	} else if form != nil {
		body = strings.NewReader(form.Encode())
		contentType = "application/x-www-form-urlencoded"
	}
	req, err := http.NewRequestWithContext(cctx, method, server+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", key)
	req.Header.Set("User-Agent", "anpu-mobsf/1.0")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, trimMiddle(string(data), 200))
	}
	return data, nil
}

func fileNameOf(p string) string {
	if i := strings.LastIndexAny(p, "/\\"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func (m *MobSFScanner) upload(ctx context.Context, server, key, apk string) (string, error) {
	data, err := m.doJSON(ctx, server, key, http.MethodPost, "/api/v1/upload", nil, "file", apk)
	if err != nil {
		return "", err
	}
	var doc struct {
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal(data, &doc); err != nil || doc.Hash == "" {
		return "", fmt.Errorf("unexpected upload response: %s", trimMiddle(string(data), 200))
	}
	return doc.Hash, nil
}

func (m *MobSFScanner) startScan(ctx context.Context, server, key, hash string) error {
	_, err := m.doJSON(ctx, server, key, http.MethodPost, "/api/v1/scan",
		url.Values{"hash": {hash}, "scan_type": {"apk"}}, "", "")
	return err
}

func (m *MobSFScanner) fetchReport(ctx context.Context, server, key, hash string) ([]byte, error) {
	return m.doJSON(ctx, server, key, http.MethodGet, "/api/v1/report_json?hash="+url.QueryEscape(hash), nil, "", "")
}

// parseMobSFReport maps appsec high/warning items to findings (cap 10).
// Shapes vary across MobSF versions, so parsing is defensive: items
// with a title-like and description-like field count.
func parseMobSFReport(data []byte, target, apk string) []models.Finding {
	var doc struct {
		AppSec map[string][]map[string]any `json:"appsec"`
	}
	var findings []models.Finding
	if err := json.Unmarshal(data, &doc); err != nil || len(doc.AppSec) == 0 {
		return nil
	}
	sevOf := map[string]models.Severity{"high": models.SeverityHigh, "warning": models.SeverityMedium, "info": models.SeverityInfo}
	order := []string{"high", "warning", "info"}
	for _, level := range order {
		for _, item := range doc.AppSec[level] {
			if len(findings) >= maxToolFinds {
				return findings
			}
			title := strField(item, "title", "name", "rule")
			desc := strField(item, "description", "detail", "message")
			if title == "" {
				continue
			}
			where := strField(item, "file", "path", "location")
			findings = append(findings, models.Finding{
				ID: "mobsf-" + level, Title: "MobSF [" + level + "] " + trimMiddle(title, 120),
				Description: trimMiddle(desc, 500) + " (MobSF static finding in " + apk + "; triage in code context.)",
				Severity:    sevOf[level], Confidence: models.ConfidenceMedium, Category: models.CategoryVulnerability,
				Scope:    models.ScopeLocalCode,
				Target:   target,
				Evidence: models.Evidence{Observed: trimMiddle(title+" "+where, 200), Location: "mobsf static appsec"},
				Source:   models.SourceCustom, DetectionMethod: "mobsf static (operator server)",
				Remediation: "Fix in source; rebuild and re-scan.",
			})
		}
	}
	return findings
}

func strField(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
