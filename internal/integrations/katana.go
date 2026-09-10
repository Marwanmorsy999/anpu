// Package integrations — katana crawl integration.
//
// Katana (ProjectDiscovery) is a fast crawler that discovers endpoints
// ANPU's built-in regex crawler misses: JS-rendered routes, form
// endpoints, API references. ANPU invokes the real binary when
// installed, parses its JSONL crawl output, and feeds the endpoints
// into the shared pipeline so Active/AuthZ/Params probe them.
//
// Absence degrades to a warning; the built-in crawler covers the stage.
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

	"github.com/anpu-project/anpu/internal/crawler"
	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// KatanaScanner implements scanner.Scanner by shelling out to katana.
type KatanaScanner struct {
	// BinaryPath overrides the resolved path to katana (testing).
	BinaryPath string
	// Timeout bounds the whole katana invocation.
	Timeout time.Duration
}

func NewKatanaScanner() *KatanaScanner {
	return &KatanaScanner{Timeout: 5 * time.Minute}
}

func (k *KatanaScanner) Name() string { return "katana" }

func (k *KatanaScanner) resolvedPath() string {
	if k.BinaryPath != "" {
		return k.BinaryPath
	}
	if path, err := findExecutable("katana"); err == nil {
		return path
	}
	return "katana"
}

func (k *KatanaScanner) Available(ctx context.Context) bool { return true }
func (k *KatanaScanner) availableExternal(ctx context.Context) bool {
	return versionCheck(ctx, k.resolvedPath())
}

// katanaJSONLine mirrors the crawl fields ANPU consumes. Katana emits
// far more; unknown fields are ignored.
type katanaJSONLine struct {
	Request struct {
		Method   string `json:"method"`
		Endpoint string `json:"endpoint"`
	} `json:"request"`
}

// katanaDepthForProfile bounds crawl cost per profile.
func katanaDepthForProfile(p models.Profile) string {
	switch p {
	case models.ProfileDeep:
		return "5"
	default:
		return "3"
	}
}

// Run crawls the target and converts discovered endpoints into ANPU
// endpoints. If external binary is present it is used for best JS
// coverage; otherwise an embedded fallback uses the built-in crawler.
func (k *KatanaScanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	if k.availableExternal(ctx) {
		args := []string{
			"-u", sc.Target.Raw,
			"-silent", "-jsonl", "-nc",
			"-d", katanaDepthForProfile(sc.Config.Profile),
			"-jc",
		}
		stdout, stderr, err := runCapture(ctx, k.Timeout, k.resolvedPath(), args...)
		var warnings []string
		if err != nil {
			if len(stdout) == 0 {
				msg := ""
				if stderr != "" {
					msg = " — " + stderr
				}
				warnings = append(warnings, fmt.Sprintf("katana run failed with no output: %v%s", err, msg))
			} else {
				warnings = append(warnings, fmt.Sprintf("katana exited with an error (endpoints captured so far are still included): %v", err))
			}
		}
		if eps := parseKatanaOutput(stdout); len(eps) > 0 {
			return scanner.StageResult{Endpoints: eps, Warnings: warnings}, nil
		}
		if len(stdout) > 0 {
			return scanner.StageResult{Endpoints: parseKatanaOutput(stdout), Warnings: warnings}, nil
		}
		// fall through to embedded on empty
	}
	return k.runEmbedded(ctx, sc)
}

func (k *KatanaScanner) runEmbedded(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	client := anpuhttp.NewClientWithLocalNetworkAllowed(scanner.AllowLocalNetwork)
	lim := crawler.LimitsForProfile(sc.Config.Profile)
	// Katana embedded does a slightly deeper JS crawl than the base Endpoints stage
	if lim.MaxPages < 10 {
		lim.MaxPages = 10
	}
	c := crawler.New(client, lim)
	eps, warns, err := c.Discover(ctx, sc.Target.Raw)
	if err != nil {
		return scanner.StageResult{Warnings: warns}, nil
	}
	// Tag as katana-embedded for provenance
	for i := range eps {
		if len(eps[i].Sources) == 0 {
			eps[i].Sources = []string{"katana-embedded"}
		} else {
			// keep original but add marker
			found := false
			for _, s := range eps[i].Sources {
				if s == "katana-embedded" {
					found = true
					break
				}
			}
			if !found {
				eps[i].Sources = append(eps[i].Sources, "katana-embedded")
			}
		}
	}
	return scanner.StageResult{Endpoints: eps, Warnings: warns}, nil
}

const maxKatanaEndpoints = 2000

// parseKatanaOutput converts katana JSONL (or plain URL lines) into
// ANPU endpoints. Only parseable http(s) URLs are kept.
func parseKatanaOutput(data []byte) []models.Endpoint {
	var out []models.Endpoint
	seen := map[string]bool{}
	add := func(raw, method string) {
		raw = strings.TrimSpace(raw)
		if raw == "" || seen[raw] {
			return
		}
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return
		}
		seen[raw] = true
		out = append(out, models.Endpoint{
			URL:      raw,
			Method:   strings.ToUpper(method),
			Category: models.EndpointUnknown,
			Sources:  []string{"katana"},
		})
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		if len(out) >= maxKatanaEndpoints {
			break
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var kl katanaJSONLine
		if err := json.Unmarshal([]byte(line), &kl); err == nil && kl.Request.Endpoint != "" {
			add(kl.Request.Endpoint, kl.Request.Method)
			continue
		}
		// Fall back to bare-URL lines.
		add(line, "")
	}
	return out
}
