// Package actuator probes Spring Boot Actuator exposure (Wave 1 item 13).
// Well-known endpoints (/actuator, /actuator/health, /actuator/env,
// /actuator/configprops, /actuator/mappings, /actuator/beans,
// /actuator/threaddump, plus Boot 1.x /health /env /dump /trace)
// are GET-fetched and matched for JSON markers; /actuator/heapdump is
// HEADERS-ONLY (a HEAD request — the dump itself is never downloaded,
// per policy). At most 12 requests. Baseline-subtract via control.
//
// Severity: env/dump/trace/configprops with content → High; health/info
// alone → Info; heapdump headers indicating a real dump → Medium.
package actuator

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// maxRequests bounds all HTTP traffic: 1 control + 10 GET + 1 HEAD.
const maxRequests = 12

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "actuator" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

type endpoint struct {
	path   string
	marker string // required body substring (lowercase)
	title  string
	sev    models.Severity
}

var endpoints = []endpoint{
	{"/actuator/env", "propertySources", "Spring Actuator /env exposed (config values)", models.SeverityHigh},
	{"/actuator/configprops", "prefix", "Spring Actuator /configprops exposed", models.SeverityHigh},
	{"/actuator/dump", "threads", "Spring Actuator /dump exposed (thread dump)", models.SeverityHigh},
	{"/actuator/trace", "timestamp", "Spring Actuator /trace exposed (request traces)", models.SeverityHigh},
	{"/env", "propertySources", "Spring Boot 1.x /env exposed (config values)", models.SeverityHigh},
	{"/dump", "threads", "Spring Boot 1.x /dump exposed", models.SeverityHigh},
	{"/trace", "timestamp", "Spring Boot 1.x /trace exposed", models.SeverityHigh},
	{"/actuator/mappings", "handler", "Spring Actuator /mappings exposed (route map)", models.SeverityMedium},
	{"/actuator/beans", "dependencies", "Spring Actuator /beans exposed", models.SeverityMedium},
	{"/actuator/health", "\"status\"", "Spring Actuator /health reachable", models.SeverityInfo},
}

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

	controlWords := map[string]struct{}{}
	if control := get("/anpu-actuator-control-404"); control != nil {
		controlWords = wordSet(control.Body)
	}

	var findings []models.Finding
	for _, e := range endpoints {
		if made >= maxRequests-1 { // reserve one slot for the heapdump HEAD
			break
		}
		resp := get(e.path)
		if resp == nil || resp.StatusCode != 200 || len(resp.Body) == 0 {
			continue
		}
		if !strings.Contains(strings.ToLower(string(resp.Body)), strings.ToLower(e.marker)) {
			continue
		}
		if overlap(wordSet(resp.Body), controlWords) > 0.85 {
			continue // baseline-subtract
		}
		findings = append(findings, models.Finding{
			ID:              "actuator-" + slug(e.path),
			Title:           e.title,
			Description:     fmt.Sprintf("The Actuator endpoint %s is publicly reachable and returns actuator content. /env /dump /trace leak configuration and runtime internals. Restrict actuator to localhost/management port with authentication. Reproduce: curl -s TARGET%s.", e.path, e.path),
			Severity:        e.sev,
			Confidence:      models.ConfidenceHigh,
			Category:        models.CategoryExposure,
			CWE:             "CWE-200",
			Target:          sc.Target.Raw,
			URL:             strings.TrimSuffix(sc.Target.Raw, "/") + e.path,
			Evidence:        models.Evidence{Observed: fmt.Sprintf("200 + marker %q (%d bytes)", e.marker, len(resp.Body)), Location: e.path},
			Source:          models.SourceRecon,
			DetectionMethod: "Actuator marker probe with 404 baseline (actuator, ≤12 requests)",
			Remediation:     "Expose only health/info publicly; bind management endpoints to localhost with auth.",
		})
		if len(findings) >= 4 {
			break
		}
	}
	// Heapdump: HEADERS ONLY — never download the dump.
	if made < maxRequests {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		made++
		if resp, err := s.client.DoWithHeaders(cctx, "HEAD", strings.TrimSuffix(sc.Target.Raw, "/")+"/actuator/heapdump", nil); err == nil && resp != nil {
			ct := strings.ToLower(resp.Header.Get("Content-Type"))
			if resp.StatusCode == 200 && (strings.Contains(ct, "octet-stream") || resp.Header.Get("Content-Length") != "") {
				findings = append(findings, models.Finding{
					ID:              "actuator-heapdump-headers",
					Title:           "Spring Actuator /heapdump endpoint present (headers only checked)",
					Description:     "HEAD /actuator/heapdump answers 200 with dump-like headers, so a full JVM heap (all in-memory secrets) is likely downloadable. ANPU never downloads dumps per policy — verify manually from an authorized host, then restrict the endpoint. Reproduce: curl -sI TARGET/actuator/heapdump.",
					Severity:        models.SeverityMedium,
					Confidence:      models.ConfidenceMedium,
					Category:        models.CategoryExposure,
					CWE:             "CWE-200",
					Target:          sc.Target.Raw,
					URL:             strings.TrimSuffix(sc.Target.Raw, "/") + "/actuator/heapdump",
					Evidence:        models.Evidence{Observed: fmt.Sprintf("HEAD → 200 %s", ct), Location: "/actuator/heapdump (HEAD only)"},
					Source:          models.SourceRecon,
					DetectionMethod: "heapdump HEAD check (actuator)",
					Remediation:     "Disable heapdump or restrict to authenticated management access.",
				})
			}
		}
	}
	return scanner.StageResult{Findings: findings}, nil
}

func slug(path string) string {
	s := strings.ToLower(strings.Trim(path, "/"))
	s = strings.ReplaceAll(s, "/", "-")
	return s
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
