// Package vhost discovers virtual hosts (Wave 1 item 30, bounded):
// baseline GET with the real Host, then the same request with Host
// overridden (GetWithHost) for 12 common sibling names. A candidate
// whose status/body clearly differs from the baseline is an Info
// candidate-vhost finding (routing/hardening review). Skipped for IP
// targets. 13 requests max, GET-only, read-only.
package vhost

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// candidates bounds extra requests: 1 baseline + 12.
var candidates = []string{
	"www", "api", "dev", "staging", "admin", "test",
	"m", "blog", "shop", "mail", "internal", "beta",
}

// maxRequests bounds all HTTP traffic.
const maxRequests = 13

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "vhost" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

// buildCandidates prefixes the registrable base (pure, tested).
func buildCandidates(host string) []string {
	if host == "" || net.ParseIP(host) != nil {
		return nil
	}
	base := registrable(host)
	var out []string
	for _, c := range candidates {
		out = append(out, c+"."+base)
	}
	sort.Strings(out)
	return out
}

func registrable(host string) string {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	parts := strings.Split(h, ".")
	if len(parts) < 2 {
		return h
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// sig is a coarse response signature for comparison (pure, tested).
func sigOf(status int, body []byte) [2]int {
	return [2]int{status, len(body) / 256}
}

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	cands := buildCandidates(sc.Target.Host)
	if len(cands) == 0 {
		return scanner.StageResult{}, nil
	}
	made := 0
	get := func(hostOverride string) *anpuhttp.Response {
		if made >= maxRequests {
			return nil
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		made++
		var resp *anpuhttp.Response
		var err error
		if hostOverride == "" {
			resp, err = s.client.Get(cctx, sc.Target.Raw)
		} else {
			resp, err = s.client.GetWithHost(cctx, sc.Target.Raw, hostOverride, nil)
		}
		if err != nil || resp == nil {
			return nil
		}
		return resp
	}

	base := get("")
	if base == nil {
		return scanner.StageResult{}, nil
	}
	baseSig := sigOf(base.StatusCode, base.Body)

	var found []string
	for _, cand := range cands {
		if made >= maxRequests {
			break
		}
		resp := get(cand)
		if resp == nil {
			continue
		}
		if sigOf(resp.StatusCode, resp.Body) == baseSig {
			continue // same site, different name
		}
		found = append(found, cand)
	}
	if len(found) == 0 {
		return scanner.StageResult{}, nil
	}
	if len(found) > 6 {
		found = found[:6]
	}
	return scanner.StageResult{Findings: []models.Finding{{
		ID:              "vhost-candidates",
		Title:           fmt.Sprintf("%d candidate virtual host(s) route differently", len(found)),
		Description:     fmt.Sprintf("Overriding Host to %s changes the response versus the real hostname: distinct applications share this address. Review each for hardening gaps (staging/debug on prod IPs). Reproduce: curl -s -H 'Host: %s' TARGET.", strings.Join(found, ", "), found[0]),
		Severity:        models.SeverityInfo,
		Confidence:      models.ConfidenceMedium,
		Category:        models.CategoryExposure,
		Target:          sc.Target.Raw,
		Evidence:        models.Evidence{Observed: "distinct Hosts: " + strings.Join(found, ", "), Location: "Host-header override vs baseline"},
		Source:          models.SourceRecon,
		DetectionMethod: "bounded vhost discovery, 12 names (vhost, ≤13 requests)",
	}}}, nil
}
