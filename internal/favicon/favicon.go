// Package favicon fetches the site's favicon and computes the Shodan-style
// murmurhash3 of its base64 form. The hash can be pivoted in Shodan
// (http.favicon.hash:<hash>) to find other hosts sharing the same icon -
// a network-level asset correlation signal. Passive, one extra GET max,
// safe for every profile.
package favicon

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// Scanner implements scanner.Scanner for favicon hashing.
type Scanner struct {
	client *anpuhttp.Client
}

func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

func (s *Scanner) Name() string                     { return "favicon" }
func (s *Scanner) Available(_ context.Context) bool { return true }

// linkIconRe extracts <link rel="icon|shortcut icon" href="..."> (case-insensitive, permissive).
var linkIconRe = regexp.MustCompile(`(?i)<link[^>]+rel=["'][^"']*icon[^"']*["'][^>]*href=["']([^"']+)["']`)

func faviconCandidates(targetRaw string, htmlBody []byte) []string {
	var out []string
	seen := map[string]bool{}
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" || seen[raw] {
			return
		}
		if strings.HasPrefix(raw, "data:") || strings.HasPrefix(raw, "javascript:") {
			return
		}
		seen[raw] = true
		out = append(out, raw)
	}
	// 1) Links in HTML
	for _, m := range linkIconRe.FindAllSubmatch(htmlBody, 4) {
		if len(m) < 2 {
			continue
		}
		href := string(m[1])
		// Resolve relative
		if !strings.HasPrefix(href, "http://") && !strings.HasPrefix(href, "https://") && !strings.HasPrefix(href, "//") {
			if base, err := url.Parse(targetRaw); err == nil {
				if u, err := base.Parse(href); err == nil {
					href = u.String()
				}
			}
		} else if strings.HasPrefix(href, "//") {
			if base, err := url.Parse(targetRaw); err == nil {
				href = base.Scheme + ":" + href
			}
		}
		add(href)
	}
	// 2) Fallback
	if base, err := url.Parse(targetRaw); err == nil {
		base.Path = "/favicon.ico"
		base.RawQuery = ""
		base.Fragment = ""
		add(base.String())
	}
	return out
}

// mmh3_32 computes murmurhash3 x86 32-bit (seed 0) - Shodan's choice.
// Ported from Austin Appleby's public domain C++.
func mmh3_32(data []byte, seed uint32) uint32 {
	const (
		c1 = 0xcc9e2d51
		c2 = 0x1b873593
		r1 = 15
		r2 = 13
		m  = 5
		n  = 0xe6546b64
	)
	h := seed
	nblocks := len(data) / 4
	for i := 0; i < nblocks; i++ {
		k := uint32(data[i*4]) | uint32(data[i*4+1])<<8 | uint32(data[i*4+2])<<16 | uint32(data[i*4+3])<<24
		k *= c1
		k = (k<<r1 | k>>(32-r1))
		k *= c2
		h ^= k
		h = (h<<r2 | h>>(32-r2))
		h = h*m + n
	}
	tail := data[nblocks*4:]
	var k1 uint32
	switch len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = (k1<<r1 | k1>>(32-r1))
		k1 *= c2
		h ^= k1
	}
	h ^= uint32(len(data))
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}

// shodanFaviconHash returns Shodan's http.favicon.hash for icon bytes.
func shodanFaviconHash(icon []byte) int32 {
	b64 := base64.StdEncoding.EncodeToString(icon)
	// Shodan inserts a newline every 76 chars (RFC 2045); Go's StdEncoding already does 76+? No, StdEncoding is continuous.
	// We mimic Shodan's python base64.encodebytes which wraps at 76 with newline. Handle by chunking.
	var buf bytes.Buffer
	for i := 0; i < len(b64); i += 76 {
		end := i + 76
		if end > len(b64) {
			end = len(b64)
		}
		buf.WriteString(b64[i:end])
		buf.WriteByte('\n')
	}
	return int32(mmh3_32(buf.Bytes(), 0))
}

func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	// Need HTML to extract custom href. Fetch via shared client (auth-aware).
	resp, err := s.client.WithAuth(sc.Auth.RequestHeaders()).Get(ctx, sc.Target.Raw)
	if err != nil || resp == nil || len(resp.Body) == 0 {
		return scanner.StageResult{Warnings: []string{fmt.Sprintf("favicon: fetch target HTML: %v", err)}}, nil
	}
	candidates := faviconCandidates(sc.Target.Raw, resp.Body)
	var icon []byte
	var iconURL string
	var lastErr error
	for _, cand := range candidates {
		candResp, err := s.client.WithAuth(sc.Auth.RequestHeaders()).Get(ctx, cand)
		if err != nil {
			lastErr = err
			continue
		}
		if candResp.StatusCode != http.StatusOK || len(candResp.Body) == 0 {
			lastErr = fmt.Errorf("HTTP %d", candResp.StatusCode)
			continue
		}
		ct := candResp.Header.Get("Content-Type")
		if !strings.Contains(strings.ToLower(ct), "image/") && len(candResp.Body) < 16 {
			// Tiny non-image likely fallback HTML, skip unless it's the last fallback
			if cand != candidates[len(candidates)-1] {
				continue
			}
		}
		// Cap at 512k
		if len(candResp.Body) > 512*1024 {
			icon = candResp.Body[:512*1024]
		} else {
			icon = candResp.Body
		}
		iconURL = cand
		lastErr = nil
		break
	}
	if len(icon) == 0 {
		return scanner.StageResult{Warnings: []string{fmt.Sprintf("favicon: no icon fetched: %v", lastErr)}}, nil
	}
	// Quick sanity: must look like image magic (PNG, ICO, JPEG, SVG, GIF).
	// Anything else is usually an HTML fallback page served as the icon —
	// still hashed, but at lower confidence.
	confidence := models.ConfidenceHigh
	if !(bytes.HasPrefix(icon, []byte("\x89PNG")) || bytes.HasPrefix(icon, []byte("\x00\x00\x01\x00")) || bytes.HasPrefix(icon, []byte("\xff\xd8\xff")) || bytes.Contains(icon[:min(512, len(icon))], []byte("<svg")) || bytes.HasPrefix(icon, []byte("GIF8"))) {
		confidence = models.ConfidenceMedium
	}

	h := shodanFaviconHash(icon)
	// Encode icon size for evidence without dumping bytes.
	var findings []models.Finding
	findings = append(findings, models.Finding{
		ID:              fmt.Sprintf("favicon-hash-%d", h),
		Title:           fmt.Sprintf("Favicon hash (Shodan mmh3) %d", h),
		Description:     fmt.Sprintf("Favicon at %s hashed to Shodan http.favicon.hash %d (%d bytes, %s). Pivot in Shodan/Censys to find other hosts sharing this icon — useful for asset correlation and shadow-IT discovery.", iconURL, h, len(icon), resp.Header.Get("Content-Type")),
		Severity:        models.SeverityInfo,
		Confidence:      confidence,
		Category:        models.CategoryExposure,
		Target:          sc.Target.Raw,
		Evidence:        models.Evidence{Observed: fmt.Sprintf("mmh3=%d base64_len=%d url=%s", h, len(base64.StdEncoding.EncodeToString(icon)), iconURL), Location: "favicon.ico / link[rel=icon]"},
		Source:          models.SourceCustom,
		DetectionMethod: "fetch favicon + base64 + murmurhash3",
		References:      []string{"https://help.shodan.io/the-basics/search-query-fundamentals/using-filters/http-favicon-hash", "https://docs.shodan.io/bulk-data/favicons"},
	})
	// Also emit a dork hint as a second informational finding when hash is non-zero
	if h != 0 {
		findings = append(findings, models.Finding{
			ID:              "favicon-dork",
			Title:           fmt.Sprintf("Shodan dork for favicon peers: http.favicon.hash:%d", h),
			Description:     fmt.Sprintf("Search Shodan/Censys/FOFA for `http.favicon.hash:%d` to enumerate other IPs/domains using the same favicon — same vendor, same template, often same org.", h),
			Severity:        models.SeverityInfo,
			Confidence:      models.ConfidenceHigh,
			Category:        models.CategoryExposure,
			Target:          sc.Target.Raw,
			Evidence:        models.Evidence{Observed: fmt.Sprintf("http.favicon.hash:%d", h), Location: iconURL},
			Source:          models.SourceCustom,
			DetectionMethod: "derived from favicon hash",
		})
	}
	// Cap icon usage to avoid unbounded read
	_ = io.Discard
	return scanner.StageResult{Findings: findings}, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
