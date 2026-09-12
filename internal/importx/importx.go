// Package importx parses third-party security artifacts (Wave 4 item
// 147): Burp Suite XML exports, OWASP ZAP JSON reports, and HTTP
// Archive (HAR) captures. Each parser normalizes to ANPU Findings
// (severity mapped, evidence preserved, source tagged) so external
// results flow into query/export/diff workflows. Pure functions over
// bytes — unit-tested with inline fixtures, no binaries needed.
package importx

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// ---------- Burp Suite XML ----------

type burpIssues struct {
	Issues []burpIssue `xml:"issue"`
}

type burpIssue struct {
	Name     string `xml:"name"`
	Severity string `xml:"severity"`
	Host     string `xml:"host"`
	Path     string `xml:"path"`
	Detail   string `xml:"issueDetail"`
	Remed    string `xml:"remediationBackground"`
}

// ParseBurp normalizes a Burp base64-free XML export.
func ParseBurp(data []byte, target string) ([]models.Finding, error) {
	var doc burpIssues
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing burp xml: %w", err)
	}
	var out []models.Finding
	for i, is := range doc.Issues {
		u := "https://" + is.Host + is.Path
		out = append(out, models.Finding{
			ID: fmt.Sprintf("burp-%d", i+1), Title: "Burp: " + strings.TrimSpace(is.Name),
			Description: trimLen(stripHTML(is.Detail), 800) + "\nRemediation: " + trimLen(stripHTML(is.Remed), 400),
			Severity:    mapBurpSeverity(is.Severity), Confidence: models.ConfidenceMedium,
			Category: models.CategoryVulnerability, Target: target, URL: u,
			Evidence: models.Evidence{Observed: "Burp severity " + is.Severity, Location: "burp xml import"},
			Source:   models.SourceCustom, DetectionMethod: "import: burp xml",
		})
	}
	return out, nil
}

func mapBurpSeverity(s string) models.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high":
		return models.SeverityHigh
	case "medium":
		return models.SeverityMedium
	case "low":
		return models.SeverityLow
	case "info", "information":
		return models.SeverityInfo
	}
	return models.SeverityInfo
}

// ---------- OWASP ZAP JSON ----------

type zapReport struct {
	Sites []struct {
		Alerts []struct {
			Alert      string `json:"alert"`
			RiskDesc   string `json:"riskdesc"`
			RiskCode   string `json:"riskcode"`
			Desc       string `json:"desc"`
			Solution   string `json:"solution"`
			URI        string `json:"uri"`
			CWEID      string `json:"cweid"`
			Confidence string `json:"confidence"`
		} `json:"alerts"`
	} `json:"site"`
}

// ParseZAP normalizes a ZAP JSON report (zap-baseline -J output).
func ParseZAP(data []byte, target string) ([]models.Finding, error) {
	var doc zapReport
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing zap json: %w", err)
	}
	var out []models.Finding
	n := 0
	for _, site := range doc.Sites {
		for _, a := range site.Alerts {
			n++
			cwe := strings.TrimSpace(a.CWEID)
			if cwe != "" && cwe != "0" && !strings.HasPrefix(cwe, "CWE-") {
				cwe = "CWE-" + cwe
			}
			out = append(out, models.Finding{
				ID: fmt.Sprintf("zap-import-%d", n), Title: "ZAP: " + strings.TrimSpace(a.Alert),
				Description: trimLen(stripHTML(a.Desc), 800) + "\nSolution: " + trimLen(stripHTML(a.Solution), 400),
				Severity:    mapZAPRisk(a.RiskCode, a.RiskDesc), Confidence: mapZAPConfidence(a.Confidence),
				Category: models.CategoryVulnerability, CWE: cwe, Target: target, URL: a.URI,
				Evidence: models.Evidence{Observed: "ZAP risk " + a.RiskDesc, Location: "zap json import"},
				Source:   models.SourceZAP, DetectionMethod: "import: zap json",
			})
		}
	}
	return out, nil
}

func mapZAPRisk(code, desc string) models.Severity {
	switch strings.TrimSpace(code) {
	case "3":
		return models.SeverityHigh
	case "2":
		return models.SeverityMedium
	case "1":
		return models.SeverityLow
	case "0":
		return models.SeverityInfo
	}
	return mapBurpSeverity(desc)
}

func mapZAPConfidence(c string) models.Confidence {
	switch strings.ToLower(strings.TrimSpace(c)) {
	case "high":
		return models.ConfidenceHigh
	case "medium":
		return models.ConfidenceMedium
	case "low":
		return models.ConfidenceLow
	}
	return models.ConfidenceMedium
}

// ---------- HAR ----------

type harFile struct {
	Log struct {
		Entries []struct {
			Request struct {
				URL    string `json:"url"`
				Method string `json:"method"`
			} `json:"request"`
			Response struct {
				Status int `json:"status"`
			} `json:"response"`
		} `json:"entries"`
	} `json:"log"`
}

// ParseHAR harvests endpoints from a HAR capture plus one Info finding
// per server-error (5xx) response observed in the capture.
func ParseHAR(data []byte, target string) ([]models.Finding, []models.Endpoint, error) {
	var doc harFile
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, fmt.Errorf("parsing har: %w", err)
	}
	seen := map[string]bool{}
	var endpoints []models.Endpoint
	var findings []models.Finding
	for _, e := range doc.Log.Entries {
		u := strings.TrimSpace(e.Request.URL)
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		if !strings.HasPrefix(u, "http") {
			continue
		}
		endpoints = append(endpoints, models.Endpoint{URL: u, Method: e.Request.Method, Category: categorize(u), Sources: []string{"har"}})
		if e.Response.Status >= 500 && e.Response.Status < 600 {
			findings = append(findings, models.Finding{
				ID:          fmt.Sprintf("har-5xx-%d", len(findings)+1),
				Title:       fmt.Sprintf("HAR capture shows HTTP %d on %s", e.Response.Status, displayPath(u)),
				Description: "A captured session recorded a server error: error pages leak stack traces and signal unhandled input. Reproduce the request from the HAR and review the response. Import-only signal — ANPU sent no traffic.",
				Severity:    models.SeverityLow, Confidence: models.ConfidenceMedium, Category: models.CategoryExposure,
				Target: target, URL: u,
				Evidence: models.Evidence{Observed: fmt.Sprintf("%s %s → %d", e.Request.Method, u, e.Response.Status), Location: "har import"},
				Source:   models.SourceCustom, DetectionMethod: "import: har 5xx",
			})
		}
	}
	sort.Slice(endpoints, func(i, j int) bool { return endpoints[i].URL < endpoints[j].URL })
	findings = append(findings, models.Finding{
		ID: "har-summary", Title: fmt.Sprintf("HAR import: %d endpoint(s) harvested", len(endpoints)),
		Description: "Endpoints harvested from an imported HAR capture for offline review and follow-up scanning. No traffic was sent.",
		Severity:    models.SeverityInfo, Confidence: models.ConfidenceHigh, Category: models.CategoryExposure,
		Target:   target,
		Evidence: models.Evidence{Observed: fmt.Sprintf("%d endpoints", len(endpoints)), Location: "har import"},
		Source:   models.SourceCustom, DetectionMethod: "import: har endpoints",
	})
	return findings, endpoints, nil
}

func categorize(raw string) models.EndpointCategory {
	u, err := url.Parse(raw)
	if err != nil {
		return models.EndpointUnknown
	}
	p := strings.ToLower(u.Path)
	switch {
	case strings.Contains(p, "api") || strings.HasSuffix(p, ".json"):
		return models.EndpointAPI
	case strings.Contains(p, "login") || strings.Contains(p, "auth"):
		return models.EndpointAuth
	default:
		return models.EndpointPage
	}
}

func displayPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if u.Path == "" {
		return "/"
	}
	return u.Path
}

func stripHTML(s string) string {
	var b strings.Builder
	inTag := false
	for _, r := range s {
		switch {
		case r == '<':
			inTag = true
		case r == '>':
			inTag = false
		case !inTag:
			b.WriteRune(r)
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

func trimLen(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
