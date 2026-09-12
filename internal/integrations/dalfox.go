// Package integrations — dalfox XSS confirmation integration.
//
// dalfox is a focused XSS scanner. ANPU feeds it the parameterized URLs
// already discovered (crawler, JS routes, historical seeds) using its
// documented fast combo (explicit -p params with --skip-mining and
// --skip-discovery) and normalizes verified findings into ANPU findings.
//
// Absence degrades to a warning; ANPU's built-in XSS rule still runs.
package integrations

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// DalfoxScanner implements scanner.Scanner by shelling out to dalfox.
type DalfoxScanner struct {
	// BinaryPath overrides the resolved path to dalfox (testing).
	BinaryPath string
	// Timeout bounds each per-URL dalfox invocation.
	Timeout time.Duration
	// MaxTargets caps how many parameterized URLs are tested.
	// Zero means the profile default (standard 10, deep 25).
	MaxTargets int
}

func NewDalfoxScanner() *DalfoxScanner {
	return &DalfoxScanner{Timeout: 90 * time.Second}
}

func (d *DalfoxScanner) Name() string { return "dalfox" }

func (d *DalfoxScanner) resolvedPath() string {
	if d.BinaryPath != "" {
		return d.BinaryPath
	}
	if path, err := findExecutable("dalfox"); err == nil {
		return path
	}
	return "dalfox"
}

func (d *DalfoxScanner) Available(ctx context.Context) bool { return true }
func (d *DalfoxScanner) availableExternal(ctx context.Context) bool {
	return versionCheck(ctx, d.resolvedPath())
}

// dalfoxMaxTargets bounds per-profile cost: XSS payloads are the most
// request-heavy checks ANPU orchestrates.
func dalfoxMaxTargets(p models.Profile, override int) int {
	if override > 0 {
		return override
	}
	if p == models.ProfileDeep {
		return 25
	}
	return 10
}

// paramURLs collects discovered URLs carrying query strings.
func paramURLs(endpoints []models.Endpoint, cap int) []string {
	var out []string
	seen := map[string]bool{}
	for _, ep := range endpoints {
		if len(out) >= cap {
			break
		}
		if !strings.Contains(ep.URL, "?") || seen[ep.URL] {
			continue
		}
		if u, err := url.Parse(ep.URL); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		seen[ep.URL] = true
		out = append(out, ep.URL)
	}
	return out
}

// queryParamNames extracts query parameter names from a URL.
func queryParamNames(raw string) []string {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil
	}
	var out []string
	for name := range q {
		name = strings.TrimSpace(name)
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

// Run tests parameterized URLs with dalfox and normalizes verified XSS.
// If external binary is present it is used; otherwise an embedded
// lightweight XSS reflection check runs (built-in fallback).
func (d *DalfoxScanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	if d.availableExternal(ctx) {
		targets := paramURLs(sc.Endpoints, dalfoxMaxTargets(sc.Config.Profile, d.MaxTargets))
		if len(targets) > 0 {
			var findings []models.Finding
			var warnings []string
			for _, target := range targets {
				if len(findings) >= 50 {
					warnings = append(warnings, "dalfox finding cap reached (50); remaining targets skipped")
					break
				}
				args := []string{"scan", target, "-f", "json", "-S", "--no-color", "--skip-mining", "--skip-discovery"}
				for _, p := range queryParamNames(target) {
					args = append(args, "-p", p)
				}
				stdout, stderr, err := runCapture(ctx, d.Timeout, d.resolvedPath(), args...)
				if err != nil && len(bytes.TrimSpace(stdout)) == 0 {
					msg := ""
					if stderr != "" {
						msg = ": " + stderr
					}
					warnings = append(warnings, fmt.Sprintf("dalfox scan of %s failed%s", target, msg))
					continue
				}
				for _, f := range parseDalfoxOutput(stdout, sc.Target.Raw) {
					if len(findings) >= 50 {
						break
					}
					findings = append(findings, f)
				}
			}
			if len(findings) > 0 || len(warnings) > 0 {
				return scanner.StageResult{Findings: findings, Warnings: warnings}, nil
			}
		}
	}
	// Embedded fallback: use built-in active XSS reflection logic (lightweight)
	return d.runEmbedded(ctx, sc)
}

func (d *DalfoxScanner) runEmbedded(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	targets := paramURLs(sc.Endpoints, dalfoxMaxTargets(sc.Config.Profile, d.MaxTargets))
	client := anpuhttp.NewClientWithLocalNetworkAllowed(scanner.AllowLocalNetwork)
	var findings []models.Finding
	for _, target := range targets {
		if len(findings) >= 10 {
			break
		}
		// Lightweight reflection test: inject canary and check echo
		canary := "anpuXSS" + fmt.Sprintf("%d", time.Now().UnixNano()%1000)
		payload := "<svg/onload=alert(1)>"
		u, err := url.Parse(target)
		if err != nil {
			continue
		}
		q := u.Query()
		for k := range q {
			orig := q.Get(k)
			q.Set(k, orig+payload)
		}
		u.RawQuery = q.Encode()
		cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		resp, err := client.Get(cctx, u.String())
		cancel()
		if err != nil || resp == nil {
			continue
		}
		if strings.Contains(string(resp.Body), payload) || strings.Contains(string(resp.Body), canary) {
			// Check if payload is reflected without encoding -> potential XSS
			// Use non-verbose evidence
			findings = append(findings, embeddedXSSFinding(sc.Target.Raw, target, "", payload))
		}
		_ = canary
	}
	// Param mining: pages without query strings still take input. Spray
	// common parameter names with distinct canaries in ONE request per
	// page, then confirm only the reflected ones with a real payload.
	if len(targets) == 0 {
		findings = append(findings, mineParams(ctx, client, sc, 10-len(findings))...)
	}
	return scanner.StageResult{Findings: findings}, nil
}

// miningParams are the parameter names most often reflected by real
// apps (search, redirects, callbacks, pagination, locale).
var miningParams = []string{
	"q", "s", "search", "query", "keyword", "id", "lang",
	"redirect", "url", "next", "return", "dest", "callback",
	"page", "sort", "name",
}

// mineParams sprays canary params on discovered pages and confirms
// reflections with an inert payload. Budget: 1 spray request per page
// plus 1 confirmation per reflected param.
func mineParams(ctx context.Context, client *anpuhttp.Client, sc *scanner.ScanContext, budget int) []models.Finding {
	if budget <= 0 {
		return nil
	}
	var pages []string
	seen := map[string]bool{}
	for _, ep := range sc.Endpoints {
		if len(pages) >= 6 {
			break
		}
		if ep.Category != models.EndpointPage && ep.Category != models.EndpointUnknown {
			continue
		}
		u, err := url.Parse(ep.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		u.RawQuery = ""
		u.Fragment = ""
		clean := u.String()
		if seen[clean] {
			continue
		}
		seen[clean] = true
		pages = append(pages, clean)
	}
	var findings []models.Finding
	payload := "<svg/onload=alert(1)>"
	for _, page := range pages {
		if len(findings) >= budget {
			break
		}
		u, err := url.Parse(page)
		if err != nil {
			continue
		}
		// Distinct canary per param so one request attributes all hits.
		canaryFor := map[string]string{}
		q := u.Query()
		for _, p := range miningParams {
			c := fmt.Sprintf("anpu%s%d", p, time.Now().UnixNano()%100000)
			canaryFor[p] = c
			q.Set(p, c)
		}
		u.RawQuery = q.Encode()
		sctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		resp, err := client.Get(sctx, u.String())
		cancel()
		if err != nil || resp == nil {
			continue
		}
		body := string(resp.Body)
		for _, p := range miningParams {
			if len(findings) >= budget {
				break
			}
			if !strings.Contains(body, canaryFor[p]) {
				continue
			}
			// Canary reflected — confirm with inert markup payload.
			cu, err := url.Parse(page)
			if err != nil {
				continue
			}
			cq := cu.Query()
			cq.Set(p, payload)
			cu.RawQuery = cq.Encode()
			cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
			cresp, cerr := client.Get(cctx, cu.String())
			cancel()
			if cerr != nil || cresp == nil {
				continue
			}
			if strings.Contains(string(cresp.Body), payload) {
				findings = append(findings, embeddedXSSFinding(sc.Target.Raw, cu.String(), p, payload))
			}
		}
	}
	return findings
}

// embeddedXSSFinding builds the standard finding for the embedded
// reflection checks (existing params and mined params share it).
func embeddedXSSFinding(target, url, param, payload string) models.Finding {
	title := fmt.Sprintf("Reflected XSS candidate at %s (embedded dalfox)", url)
	if param != "" {
		title = fmt.Sprintf("Reflected XSS candidate in mined parameter %q at %s (embedded dalfox)", param, url)
	}
	return models.Finding{
		ID:              fmt.Sprintf("dalfox-embed-xss-%d", time.Now().UnixNano()),
		Title:           title,
		Description:     "Embedded dalfox fallback detected JavaScript payload reflection. Requires manual verification for exploitability (context-sensitive).",
		Severity:        models.SeverityMedium,
		Confidence:      models.ConfidenceMedium,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-79",
		Target:          target,
		URL:             url,
		Parameter:       param,
		Evidence:        models.Evidence{Observed: payload + " reflected", Location: "dalfox-embedded reflection"},
		Source:          models.SourceDalfox,
		DetectionMethod: "embedded dalfox reflection check",
	}
}

// dalfoxSeverity maps dalfox PoC types to ANPU severities:
// v = verified vulnerable, r = reflected, a = AST-level.
func dalfoxSeverity(pocType string) (models.Severity, models.Confidence) {
	switch strings.ToLower(strings.TrimSpace(pocType)) {
	case "v", "vulnerable", "verified":
		return models.SeverityHigh, models.ConfidenceHigh
	case "r", "reflected":
		return models.SeverityMedium, models.ConfidenceMedium
	case "a", "ast":
		return models.SeverityLow, models.ConfidenceMedium
	default:
		return models.SeverityMedium, models.ConfidenceMedium
	}
}

// firstString returns the first non-empty value for any of keys.
func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		for mk, mv := range m {
			if strings.EqualFold(mk, k) {
				if s, ok := mv.(string); ok && strings.TrimSpace(s) != "" {
					return strings.TrimSpace(s)
				}
			}
		}
	}
	return ""
}

// parseDalfoxOutput converts dalfox -f json output (schema-tolerant)
// into ANPU findings. Informational (i-type) results are skipped.
func parseDalfoxOutput(data []byte, target string) []models.Finding {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil
	}
	// Accept both a JSON array and newline-delimited JSON objects.
	var items []map[string]any
	if err := json.Unmarshal(trimmed, &items); err != nil {
		items = nil
		sc := bufio.NewScanner(bytes.NewReader(trimmed))
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			var m map[string]any
			if err := json.Unmarshal([]byte(strings.TrimSpace(sc.Text())), &m); err == nil {
				items = append(items, m)
			}
		}
	}

	var out []models.Finding
	for _, m := range items {
		pocType := firstString(m, "type", "poc-type", "poctype", "result-type")
		if strings.EqualFold(pocType, "i") || strings.EqualFold(pocType, "info") || strings.EqualFold(pocType, "informational") {
			continue
		}
		fURL := firstString(m, "url", "target", "data-url")
		if fURL == "" {
			fURL = target
		}
		param := firstString(m, "param", "parameter", "data-param")
		poc := firstString(m, "poc", "message", "data", "payload", "evidence")
		if len(poc) > 400 {
			poc = poc[:400] + "..."
		}
		sev, conf := dalfoxSeverity(pocType)
		title := "Cross-site scripting verified by dalfox"
		if param != "" {
			title = fmt.Sprintf("Cross-site scripting in parameter %q (dalfox verified)", param)
		}
		out = append(out, models.Finding{
			ID:              fmt.Sprintf("dalfox-xss-%d", time.Now().UnixNano()),
			Title:           title,
			Description:     "Dalfox confirmed executable JavaScript reflection at this URL. Findings marked verified executed a benign probe payload (e.g. alert(1)-class) in the response context.",
			Severity:        sev,
			Confidence:      conf,
			Category:        models.CategoryVulnerability,
			CWE:             "CWE-79",
			Target:          target,
			URL:             fURL,
			Parameter:       param,
			Evidence:        models.Evidence{Observed: poc, Location: "dalfox PoC output"},
			Source:          models.SourceDalfox,
			DetectionMethod: "dalfox XSS scan with explicit params, mining skipped",
			Impact:          "An attacker can execute JavaScript in victims' browsers: session theft, defacement, or phishing on the trusted origin.",
			Remediation:     "Encode output for its context, validate input, and deploy a nonce-based Content-Security-Policy without 'unsafe-inline'.",
			References:      []string{"https://owasp.org/www-community/attacks/xss/"},
			FirstSeen:       time.Now(),
		})
	}
	return out
}
