// Package integrations — httpx probe integration.
//
// httpx (ProjectDiscovery) probes a target for liveness, status, title,
// web server, and technologies. ANPU normalizes its tech-detect output
// into Technology records that corroborate (via dedup) the built-in
// fingerprinting, plus a web-server record when reported.
//
// Absence degrades to a warning.
package integrations

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// HttpxScanner implements scanner.Scanner by shelling out to httpx.
type HttpxScanner struct {
	// BinaryPath overrides the resolved path to httpx (testing).
	BinaryPath string
	// Timeout bounds the whole httpx invocation.
	Timeout time.Duration
}

func NewHttpxScanner() *HttpxScanner {
	return &HttpxScanner{Timeout: 2 * time.Minute}
}

func (h *HttpxScanner) Name() string { return "httpx" }

func (h *HttpxScanner) resolvedPath() string {
	if h.BinaryPath != "" {
		return h.BinaryPath
	}
	if path, err := findExecutable("httpx"); err == nil {
		return path
	}
	return "httpx"
}

func (h *HttpxScanner) Available(ctx context.Context) bool {
	// Embedded fallback always available — external binary is optional accelerator
	return true
}

func (h *HttpxScanner) availableExternal(ctx context.Context) bool {
	return versionCheck(ctx, h.resolvedPath())
}

// httpxJSONLine mirrors the probe fields ANPU consumes.
type httpxJSONLine struct {
	URL       string   `json:"url"`
	Status    int      `json:"status_code"`
	Title     string   `json:"title"`
	WebServer string   `json:"webserver"`
	Tech      []string `json:"tech"`
}

// guessTechCategory buckets an httpx tech name coarsely. Unknown names
// map to "other" rather than being dropped.
func guessTechCategory(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "cloudflare") || strings.Contains(lower, "cloudfront") ||
		strings.Contains(lower, "akamai") || strings.Contains(lower, "fastly") ||
		strings.Contains(lower, "cdn") || strings.Contains(lower, "cloudfront"):
		return "cdn"
	case strings.Contains(lower, "nginx") || strings.Contains(lower, "apache") ||
		strings.Contains(lower, "iis") || strings.Contains(lower, "caddy") ||
		strings.Contains(lower, "lighttpd") || strings.Contains(lower, "openresty"):
		return "web-server"
	case strings.Contains(lower, "wordpress") || strings.Contains(lower, "drupal") ||
		strings.Contains(lower, "joomla"):
		return "cms"
	default:
		return "other"
	}
}

// Run probes the target and converts tech-detect output into ANPU
// technologies. If external binary is present it is used for best
// accuracy; otherwise an embedded fallback does a direct probe.
func (h *HttpxScanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	if h.availableExternal(ctx) {
		args := []string{
			"-u", sc.Target.Raw,
			"-silent", "-json", "-nc",
			"-tech-detect", "-status-code", "-title", "-web-server",
		}
		stdout, _, err := runCapture(ctx, h.Timeout, h.resolvedPath(), args...)
		if err == nil || len(bytes.TrimSpace(stdout)) > 0 {
			if techs := parseHttpxOutput(stdout, sc.Target.Raw); len(techs) > 0 {
				return scanner.StageResult{Technologies: techs}, nil
			}
		}
	}
	// Embedded fallback — direct probe
	return h.runEmbedded(ctx, sc)
}

func (h *HttpxScanner) runEmbedded(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	client := anpuhttp.NewClientWithLocalNetworkAllowed(scanner.AllowLocalNetwork)
	cctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	resp, err := client.Get(cctx, sc.Target.Raw)
	if err != nil || resp == nil {
		return scanner.StageResult{}, nil
	}
	var out []models.Technology
	loc := sc.Target.Raw
	// Server header as web-server tech
	if srv := strings.TrimSpace(resp.Header.Get("Server")); srv != "" {
		// strip version suffix for category, keep full as name
		out = append(out, models.Technology{
			Name:       srv,
			Category:   "web-server",
			Confidence: 0.55,
			Evidence:   models.Evidence{Observed: "Server: " + srv, Location: loc},
		})
	}
	// Title as tech hint (not a real tech, but useful for debugging)
	if m := titleRe.FindSubmatch(resp.Body); len(m) > 1 {
		title := strings.TrimSpace(string(m[1]))
		if len(title) > 0 && len(title) < 120 {
			out = append(out, models.Technology{
				Name:       "HTML title: " + title,
				Category:   "other",
				Confidence: 0.4,
				Evidence:   models.Evidence{Observed: title, Location: loc},
			})
		}
	}
	// Simple tech hints from headers/body
	bodyLower := strings.ToLower(string(resp.Body))
	for _, hint := range []struct{ needle, name, cat string }{
		{"cloudflare", "Cloudflare", "cdn"},
		{"fastly", "Fastly", "cdn"},
		{"akamai", "Akamai", "cdn"},
		{"wordpress", "WordPress", "cms"},
		{"drupal", "Drupal", "cms"},
		{"joomla", "Joomla", "cms"},
	} {
		if strings.Contains(strings.ToLower(resp.Header.Get("Server")), hint.needle) || strings.Contains(bodyLower, hint.needle) {
			out = append(out, models.Technology{
				Name:       hint.name,
				Category:   hint.cat,
				Confidence: 0.5,
				Evidence:   models.Evidence{Observed: "httpx-embed hint: " + hint.needle, Location: loc},
			})
		}
	}
	if len(out) > maxHttpxTechs {
		out = out[:maxHttpxTechs]
	}
	return scanner.StageResult{Technologies: out}, nil
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

const maxHttpxTechs = 50

// parseHttpxOutput converts httpx JSON lines into Technology records.
func parseHttpxOutput(data []byte, target string) []models.Technology {
	var out []models.Technology
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if len(out) >= maxHttpxTechs {
			break
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var hl httpxJSONLine
		if err := json.Unmarshal([]byte(line), &hl); err != nil {
			continue
		}
		loc := hl.URL
		if loc == "" {
			loc = target
		}
		for _, tech := range hl.Tech {
			tech = strings.TrimSpace(tech)
			if tech == "" {
				continue
			}
			out = append(out, models.Technology{
				Name:       tech,
				Category:   guessTechCategory(tech),
				Confidence: 0.6,
				Evidence:   models.Evidence{Observed: "httpx tech-detect", Location: loc},
			})
		}
		if ws := strings.TrimSpace(hl.WebServer); ws != "" {
			out = append(out, models.Technology{
				Name:       ws,
				Category:   "web-server",
				Confidence: 0.6,
				Evidence:   models.Evidence{Observed: "httpx webserver", Location: loc},
			})
		}
	}
	return out
}
