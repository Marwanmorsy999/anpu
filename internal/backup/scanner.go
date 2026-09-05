// Package backup implements backup file discovery for Phase 12E.
//
// # What it detects
//
// Web servers often retain editor swap files, backup copies, and archive
// snapshots of files that were originally intended to be private.  Common
// causes:
//
//   - Text editors: vi/vim leave .swp files; nano leaves backups as file~
//   - Deployment tools: copying files with cp -p creates .bak/.orig/.old copies
//   - Compressed archives left in place after extraction
//
// When a source file (e.g. /config.php) is accidentally exposed alongside its
// backup (/config.php.bak), the backup typically serves the raw source code
// rather than executing it — the web server does not recognise the extension
// and serves it as text/plain.  This reveals application logic, credentials,
// database connection strings, and API keys embedded in code.
//
// # Strategy
//
// For each discovered endpoint URL:
//  1. Derive candidate backup paths by appending common backup suffixes
//     (.bak, .old, .orig, ~, .swp, .save, .backup, .copy, .1, .2).
//  2. Probe each candidate with GET.
//  3. Report a finding when:
//     - HTTP 200 (or 206 partial) is returned, AND
//     - Response body is non-trivial (> 200 bytes), AND
//     - Content-Type is NOT application/* that would indicate intentional content,
//     OR Content-Type is text/plain/text/html with a body that looks like source code.
//     - Response body differs from the soft-404 baseline (avoids catch-all routers).
//  4. Additionally probe a fixed list of root-level backup archives and database
//     dumps not covered by the dirs scanner.
//
// # Concurrency
//
// Probes are issued with bounded concurrency (8 goroutines) to avoid
// overwhelming the target.
//
// # CWE / OWASP
//
// CWE-530: Exposure of Backup File to an Unauthorized Control Sphere
// OWASP A05:2021 — Security Misconfiguration
package backup

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// backupSuffixes are appended to each discovered endpoint path to produce
// candidate backup file paths.
var backupSuffixes = []string{
	".bak",
	".old",
	".orig",
	"~",
	".swp",
	".save",
	".backup",
	".copy",
	".1",
	".tmp",
}

// rootBackupPaths are probed unconditionally at the target root.
// These complement (not duplicate) the dirs scanner wordlist.
var rootBackupPaths = []struct {
	path string
	note string
}{
	{"/backup.tar.bz2", "compressed backup archive"},
	{"/backup.7z", "compressed backup archive"},
	{"/site.tar.gz", "site archive"},
	{"/www.zip", "site archive"},
	{"/htdocs.zip", "site archive"},
	{"/web.zip", "site archive"},
	{"/app.zip", "application archive"},
	{"/database.sql", "database dump"},
	{"/db_backup.sql", "database dump"},
	{"/mysqldump.sql", "database dump"},
	{"/schema.sql", "database schema"},
	{"/data.sql", "database dump"},
	{"/prod.sql", "production database dump"},
	{"/config.yml.bak", "configuration backup"},
	{"/config.yaml.bak", "configuration backup"},
	{"/application.properties.bak", "Spring Boot configuration backup"},
	{"/appsettings.json.bak", "ASP.NET configuration backup"},
	{"/.env.bak", "environment file backup"},
	{"/.env.save", "environment file backup"},
	{"/wp-config.php~", "WordPress configuration vim swap"},
	{"/LocalSettings.php.bak", "MediaWiki configuration backup"},
	{"/configuration.php.bak", "Joomla configuration backup"},
}

// minBodyBytes is the minimum response body size to be considered non-trivial.
// Responses shorter than this are likely empty 200s from misconfigured servers.
const minBodyBytes = 200

// sourceCodeSignatures are patterns that suggest the response body is source
// code (rather than an intentional resource with a backup-like extension).
var sourceCodeSignatures = []string{
	"<?php",
	"<?=",
	"#!/usr/bin/",
	"#!/usr/bin/env",
	"import os",
	"import sys",
	"from django",
	"require 'rails'",
	"package main",
	"using System",
	"public class",
	"def initialize",
	"database_password",
	"db_password",
	"secret_key",
	"api_key",
	"password =",
	"passwd =",
	"DB_PASS",
	"DB_PASSWORD",
}

// Scanner implements scanner.Scanner for backup file discovery.
type Scanner struct {
	client *anpuhttp.Client
}

func New(client *anpuhttp.Client) *Scanner          { return &Scanner{client: client} }
func (s *Scanner) Name() string                     { return "backup-scanner" }
func (s *Scanner) Available(_ context.Context) bool { return true }

type probeResult struct {
	url     string
	finding *models.Finding
}

func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	var findings []models.Finding
	var warnings []string
	var mu sync.Mutex

	// --- Soft-404 baseline ---
	// Fetch a randomly-named path to detect catch-all routers.
	soft404Body := s.soft404Baseline(ctx, sc.Target.Raw)

	// --- Build probe list ---
	type probe struct {
		url  string
		note string
	}
	var probes []probe
	seen := map[string]bool{}

	// Per-endpoint backup suffix probes.
	for _, ep := range sc.Endpoints {
		// Only generate backup probes for page and asset endpoints with file-like paths.
		if ep.Category == models.EndpointAPI {
			continue
		}
		path := pathOf(ep.URL)
		if path == "" || path == "/" || !hasFileExtension(path) {
			continue
		}
		for _, suffix := range backupSuffixes {
			candidate := baseURL(ep.URL) + path + suffix
			if seen[candidate] {
				continue
			}
			seen[candidate] = true
			probes = append(probes, probe{candidate, "backup of " + path})
		}
	}

	// Root-level backup probes.
	base := baseURL(sc.Target.Raw)
	for _, rb := range rootBackupPaths {
		u := base + rb.path
		if seen[u] {
			continue
		}
		seen[u] = true
		probes = append(probes, probe{u, rb.note})
	}

	// --- Concurrent probe dispatch ---
	sem := make(chan struct{}, 8)
	results := make(chan probeResult, len(probes))
	var wg sync.WaitGroup

	for _, p := range probes {
		select {
		case <-ctx.Done():
			break
		default:
		}
		wg.Add(1)
		go func(p probe) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			f := s.probe(ctx, p.url, p.note, soft404Body, sc.Target.Raw)
			results <- probeResult{url: p.url, finding: f}
		}(p)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for pr := range results {
		if pr.finding != nil {
			mu.Lock()
			findings = append(findings, *pr.finding)
			mu.Unlock()
		}
	}

	if len(probes) > 0 && sc.Verbose {
		warnings = append(warnings, fmt.Sprintf(
			"backup-scanner: probed %d candidate backup paths, found %d exposed files",
			len(probes), len(findings),
		))
	}

	return scanner.StageResult{Findings: findings, Warnings: warnings}, nil
}

// probe GETs a single candidate URL and returns a Finding if it looks like
// an exposed backup file.  Returns nil for non-findings.
func (s *Scanner) probe(ctx context.Context, url, note, soft404Body, target string) *models.Finding {
	resp, err := s.client.Get(ctx, url)
	if err != nil {
		return nil
	}

	// Only 200/206 count as present.
	if resp.StatusCode != 200 && resp.StatusCode != 206 {
		return nil
	}

	body := string(resp.Body)

	// Ignore trivially short responses (catch-all soft 404s).
	if len(body) < minBodyBytes {
		return nil
	}

	// Soft-404 check: if the body is similar to our baseline, skip.
	if soft404Body != "" && stringsAreSimilar(body, soft404Body) {
		return nil
	}

	// Determine severity: source-code exposure is High; archive/dump exposure is High;
	// generic backup exposure is Medium.
	severity := models.SeverityMedium
	detail := note
	ct := strings.ToLower(resp.Header.Get("Content-Type"))

	lowerBody := strings.ToLower(body)
	for _, sig := range sourceCodeSignatures {
		if strings.Contains(lowerBody, strings.ToLower(sig)) {
			severity = models.SeverityHigh
			detail = fmt.Sprintf("%s — response body contains source code indicator %q", note, sig)
			break
		}
	}

	// Archives and SQL dumps are always High regardless of body content.
	for _, ext := range []string{".zip", ".tar", ".gz", ".bz2", ".7z", ".sql", ".bak", ".dump"} {
		if strings.HasSuffix(strings.ToLower(url), ext) {
			severity = models.SeverityHigh
			break
		}
	}

	// Warn if Content-Type suggests this might be intentional binary content.
	if strings.HasPrefix(ct, "application/") && !strings.Contains(ct, "text") && !strings.Contains(ct, "json") && !strings.Contains(ct, "xml") {
		// Could be a legitimate binary served intentionally — lower severity.
		severity = models.SeverityMedium
	}

	return &models.Finding{
		ID:    fmt.Sprintf("backup-file-exposed-%d", time.Now().UnixNano()),
		Title: fmt.Sprintf("Backup file exposed: %s (%s)", url, detail),
		Description: fmt.Sprintf(
			"The backup file at %s returned HTTP 200 with a %d-byte body. "+
				"Backup files typically bypass application-level access controls and may reveal "+
				"source code, credentials, database connection strings, or configuration secrets. "+
				"Note: %s.",
			url, len(body), detail,
		),
		Severity:        severity,
		Confidence:      models.ConfidenceMedium,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-530",
		OWASP:           "A05:2021 - Security Misconfiguration",
		Target:          target,
		URL:             url,
		Source:          models.SourceBackup,
		DetectionMethod: fmt.Sprintf("GET %s → HTTP 200, body %d bytes", url, len(body)),
		Evidence: models.Evidence{
			Observed:       fmt.Sprintf("HTTP 200 at %s — %d bytes, Content-Type: %s", url, len(body), ct),
			Location:       url,
			RequestSummary: fmt.Sprintf("GET %s", url),
		},
		Impact: "Exposed backup files may contain hard-coded credentials, API keys, database passwords, " +
			"and application logic that enables further attacks. Source code disclosure significantly " +
			"reduces the effort required to find injection vulnerabilities and business logic flaws.",
		Remediation: "Remove backup files from web-accessible directories. Configure your web server to " +
			"return 403 for common backup extensions (*.bak, *.old, *~, *.swp). " +
			"Add these patterns to your .gitignore and deployment pipeline exclude list. " +
			"Use a secrets manager (AWS Secrets Manager, HashiCorp Vault) instead of embedding credentials in config files.",
		References: []string{
			"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
			"https://cwe.mitre.org/data/definitions/530.html",
		},
		FirstSeen: time.Now(),
	}
}

// soft404Baseline fetches a randomly-named path to detect servers that return
// 200 for all requests.  Returns the response body, or empty string on error.
func (s *Scanner) soft404Baseline(ctx context.Context, targetRaw string) string {
	base := baseURL(targetRaw)
	// Use a fixed but unlikely path rather than random so tests are deterministic.
	resp, err := s.client.Get(ctx, base+"/anpu-backup-baseline-check-xyz123")
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	return string(resp.Body)
}

// stringsAreSimilar returns true when a and b share more than 80% of their
// characters — a heuristic for catch-all soft-404 pages that return the same
// template regardless of path.
func stringsAreSimilar(a, b string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	// If lengths differ by more than 20%, they're not similar enough.
	ratio := float64(len(a)) / float64(len(b))
	if ratio < 0.8 || ratio > 1.2 {
		return false
	}
	// Simple prefix comparison: if first 200 chars match, consider similar.
	aPrefix := a
	bPrefix := b
	if len(aPrefix) > 200 {
		aPrefix = aPrefix[:200]
	}
	if len(bPrefix) > 200 {
		bPrefix = bPrefix[:200]
	}
	return aPrefix == bPrefix
}

// pathOf returns the path component of a URL string.
func pathOf(rawURL string) string {
	for _, prefix := range []string{"https://", "http://"} {
		if strings.HasPrefix(strings.ToLower(rawURL), prefix) {
			rest := rawURL[len(prefix):]
			slash := strings.Index(rest, "/")
			if slash < 0 {
				return "/"
			}
			path := rest[slash:]
			// Strip query and fragment.
			if q := strings.IndexAny(path, "?#"); q >= 0 {
				path = path[:q]
			}
			return path
		}
	}
	return ""
}

// baseURL returns scheme://host from a URL string.
func baseURL(rawURL string) string {
	for _, prefix := range []string{"https://", "http://"} {
		lower := strings.ToLower(rawURL)
		if strings.HasPrefix(lower, prefix) {
			rest := rawURL[len(prefix):]
			slash := strings.Index(rest, "/")
			if slash < 0 {
				return rawURL
			}
			return prefix + rest[:slash]
		}
	}
	return rawURL
}

// hasFileExtension returns true when the path ends with a file extension
// (i.e. the last path segment contains a dot after the first character).
func hasFileExtension(path string) bool {
	// Get the last segment after the final slash.
	last := path
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		last = path[idx+1:]
	}
	// A dot after the first character indicates an extension.
	return len(last) > 1 && strings.Contains(last[1:], ".")
}
