// Package apiversion fuzzes API versioning surface (Wave 1 item 28):
// for a discovered API-ish base URL (or the target root), it probes
// sibling versions (/v2, /v3, /v4, /api/v2, version params, Accept
// versioning) — 11 requests max. A 200 JSON response clearly different
// from the baseline is an Info finding plus a harvested Endpoint for
// AuthZ/Active. GET-only, read-only, no state change.
package apiversion

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// maxRequests bounds all HTTP traffic: 1 baseline + 10 variants.
const maxRequests = 11

var versionPaths = []string{
	"/v2", "/v3", "/v4", "/api/v2", "/api/v3",
	"/v1", // downgrade check against a v2-style base is handled by swap logic
	"/api/v1", "/api/latest", "/latest", "/v2.0",
}

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "apiversion" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	base := pickBase(sc)
	made := 0
	get := func(u string, headers map[string]string) *anpuhttp.Response {
		if made >= maxRequests {
			return nil
		}
		// Charge the global per-tool ledger (Wave 4 item 151); a nil
		// ledger (unit tests) means uncapped.
		if sc.Ledger != nil {
			if err := sc.Ledger.Record("apiversion"); err != nil {
				return nil
			}
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		made++
		var resp *anpuhttp.Response
		var err error
		if len(headers) == 0 {
			resp, err = s.client.Get(cctx, u)
		} else {
			resp, err = s.client.DoWithHeaders(cctx, "GET", u, headers)
		}
		if err != nil || resp == nil {
			return nil
		}
		return resp
	}

	baseResp := get(base, nil)
	if baseResp == nil {
		return scanner.StageResult{}, nil
	}
	baseSig := of(baseResp)

	var findings []models.Finding
	var endpoints []models.Endpoint
	try := func(u, label string, headers map[string]string) {
		if made >= maxRequests || len(findings) >= 3 {
			return
		}
		resp := get(u, headers)
		if resp == nil || resp.StatusCode != 200 || len(resp.Body) < 16 {
			return
		}
		if !looksJSON(resp) {
			return
		}
		if of(resp) == baseSig {
			return // same API, different URL
		}
		findings = append(findings, models.Finding{
			ID:              "apiversion-sibling",
			Title:           fmt.Sprintf("Sibling API version reachable: %s", label),
			Description:     fmt.Sprintf("The version variant %s returns 200 JSON clearly different from the baseline: old versions often miss auth fixes applied to current ones. Inventory every version and decommission or equally harden legacy ones. Reproduce: curl -s %q.", label, u),
			Severity:        models.SeverityInfo,
			Confidence:      models.ConfidenceMedium,
			Category:        models.CategoryExposure,
			Target:          sc.Target.Raw,
			URL:             u,
			Evidence:        models.Evidence{Observed: fmt.Sprintf("200 JSON (%d bytes, differs from baseline)", len(resp.Body)), Location: "version variant"},
			Source:          models.SourceRecon,
			DetectionMethod: "API version sibling fuzz (apiversion, ≤11 requests)",
			Remediation:     "Version inventory; sunset or harden legacy versions.",
		})
		endpoints = append(endpoints, models.Endpoint{URL: u, Category: models.EndpointAPI, Sources: []string{"apiversion"}})
	}

	parsed, err := url.Parse(base)
	if err != nil {
		return scanner.StageResult{}, nil
	}
	root := parsed.Scheme + "://" + parsed.Host
	for _, p := range versionPaths {
		try(root+p, p, nil)
	}
	// Version params and Accept-versioning against the base itself.
	try(withParam(base, "version", "2"), "?version=2", nil)
	try(withParam(base, "api-version", "2"), "?api-version=2", nil)
	try(base, "Accept: application/vnd.api.v2+json", map[string]string{"Accept": "application/vnd.api.v2+json"})
	return scanner.StageResult{Findings: findings, Endpoints: endpoints}, nil
}

// pickBase prefers a discovered API endpoint, else the target root.
func pickBase(sc *scanner.ScanContext) string {
	for _, ep := range sc.Endpoints {
		if ep.Category != models.EndpointAPI {
			continue
		}
		u, err := url.Parse(ep.URL)
		if err != nil || !strings.EqualFold(u.Hostname(), sc.Target.Host) {
			continue
		}
		return ep.URL
	}
	return sc.Target.Raw
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

type sig struct {
	status int
	length int
}

func of(resp *anpuhttp.Response) sig {
	return sig{status: resp.StatusCode, length: len(resp.Body) / 32}
}

func looksJSON(resp *anpuhttp.Response) bool {
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(ct, "json") {
		return true
	}
	b := strings.TrimSpace(string(resp.Body))
	return strings.HasPrefix(b, "{") || strings.HasPrefix(b, "[")
}
