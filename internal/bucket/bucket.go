// Package bucket checks for plausible cloud storage buckets derived from the
// target domain that are publicly reachable or disclose existence via 403.
// It is a passive-ish network check: it does not attack the target itself,
// but probes provider-owned endpoints (s3.amazonaws.com, blob.core.windows.net,
// storage.googleapis.com) with unauthenticated HEAD/GET. One probe per
// candidate bucket, max ~15 probes, safe for all profiles. Best-effort.
package bucket

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// Scanner implements scanner.Scanner for cloud bucket hints.
type Scanner struct {
	client *anpuhttp.Client
}

func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

func (s *Scanner) Name() string                     { return "bucket" }
func (s *Scanner) Available(_ context.Context) bool { return true }

func candidatesFor(host string) []string {
	// host is like sub.example.com or example.com
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return nil
	}
	// Strip TLD (last part) for base candidates
	base := strings.Join(parts[:len(parts)-1], "-")
	sld := parts[len(parts)-2] // second-level domain
	first := parts[0]

	set := map[string]bool{}
	var out []string
	add := func(c string) {
		c = strings.ToLower(strings.TrimSpace(c))
		if c == "" || set[c] || len(c) < 3 || len(c) > 63 {
			return
		}
		if strings.Contains(c, "..") || strings.HasPrefix(c, "-") || strings.HasSuffix(c, "-") {
			return
		}
		set[c] = true
		out = append(out, c)
	}
	add(first)
	add(sld)
	add(base)
	add(strings.ReplaceAll(host, ".", "-"))
	add(strings.ReplaceAll(host, ".", ""))
	if len(parts) >= 3 {
		add(parts[0] + "-" + sld)
	}
	// Trim to 5 max to keep probes bounded
	if len(out) > 5 {
		out = out[:5]
	}
	return out
}

func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	host := sc.Target.Host
	if host == "" {
		return scanner.StageResult{}, nil
	}
	// Skip IP hosts
	for _, c := range host {
		if (c >= '0' && c <= '9') || c == '.' {
			continue
		}
		goto notIP
	}
	// All digits/dots -> likely IP
	return scanner.StageResult{}, nil
notIP:
	cands := candidatesFor(host)
	if len(cands) == 0 {
		return scanner.StageResult{}, nil
	}

	// Provider templates: S3 virtual-hosted-style, Azure blob, GCS bucket
	type probe struct {
		provider string
		url      string
		cand     string
	}
	var probes []probe
	for _, c := range cands {
		probes = append(probes, probe{"S3", fmt.Sprintf("https://%s.s3.amazonaws.com/", c), c})
		probes = append(probes, probe{"Azure", fmt.Sprintf("https://%s.blob.core.windows.net/", c), c})
		probes = append(probes, probe{"GCS", fmt.Sprintf("https://storage.googleapis.com/%s", c), c})
	}
	if len(probes) > 15 {
		probes = probes[:15]
	}

	var findings []models.Finding
	for _, p := range probes {
		cctx, cancel := context.WithTimeout(ctx, 7*time.Second)
		resp, err := s.client.Get(cctx, p.url)
		cancel()
		if err != nil || resp == nil {
			continue
		}
		// Interpret S3/Azure/GCS bucket existence
		// S3: 200 = listable, 403 = exists but private (AccessDenied), 404 = not found
		// Azure: 200/400? Actually Azure returns 400 BadRequest for invalid, 404 for not found, 409? Simplified: 200/403 = exists
		// GCS: 200 = exists, 403 = exists private, 404 = not found
		exists := false
		public := false
		switch resp.StatusCode {
		case 200:
			exists = true
			public = true
		case 403:
			exists = true
			public = false
		case 400:
			// Azure returns 400 for existing but needs query, treat as exists hint if body mentions Error
			if strings.Contains(strings.ToLower(string(resp.Body)), "error") {
				exists = true
			}
		default:
			// 404, 301 etc -> not found or redirect, treat as not exists for our heuristic
			continue
		}
		if !exists {
			continue
		}
		sev := models.SeverityInfo
		title := fmt.Sprintf("Cloud bucket candidate exists: %s (%s) — %s", p.cand, p.provider, map[bool]string{true: "public listable", false: "exists (private/403)"}[public])
		if public {
			sev = models.SeverityMedium
			title = fmt.Sprintf("Public cloud bucket: %s (%s) is listable", p.cand, p.provider)
		}
		findings = append(findings, models.Finding{
			ID:              fmt.Sprintf("bucket-%s-%s", strings.ToLower(p.provider), p.cand),
			Title:           title,
			Description:     fmt.Sprintf("A cloud storage bucket named %q on %s responded with HTTP %d at %s. If the bucket belongs to the target org and is unintentionally public, it may expose backups, logs, or PII.", p.cand, p.provider, resp.StatusCode, p.url),
			Severity:        sev,
			Confidence:      models.ConfidenceMedium,
			Category:        models.CategoryExposure,
			CWE:             "CWE-200",
			Target:          sc.Target.Raw,
			URL:             p.url,
			Evidence:        models.Evidence{Observed: fmt.Sprintf("HTTP %d Content-Type %q (%d bytes)", resp.StatusCode, resp.Header.Get("Content-Type"), len(resp.Body)), Location: p.provider + " bucket probe"},
			Source:          models.SourceCustom,
			DetectionMethod: "HEAD/GET to provider bucket endpoint derived from domain labels",
			Remediation:     "Verify the bucket belongs to your org; if so, enforce private ACL, block public access, and rotate any exposed objects. If unowned, consider claiming the name to prevent bucket squatting.",
		})
		// Cap findings to avoid flooding
		if len(findings) >= 5 {
			break
		}
	}
	return scanner.StageResult{Findings: findings}, nil
}
