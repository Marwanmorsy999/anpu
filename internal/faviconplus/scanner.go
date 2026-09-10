// Package faviconplus sweeps icon paths (Wave 1 item 46): 8 common
// icon locations are fetched; distinct non-empty icons are grouped by
// content hash (FNV-64) and reported as endpoints with their hashes
// for Shodan-style pivoting. A site root icon differing from the
// framework-default set is Info. 9 requests max, GET-only.
package faviconplus

import (
	"context"
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

var iconPaths = []string{
	"/favicon.ico", "/apple-touch-icon.png", "/apple-touch-icon-precomposed.png",
	"/android-chrome-192x192.png", "/mstile-150x150.png", "/safari-pinned-tab.svg",
	"/favicon-32x32.png", "/favicon-16x16.png",
}

// maxRequests bounds all HTTP traffic: 1 homepage + 8 icons.
const maxRequests = 9

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "faviconplus" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

// hash64 returns the FNV-64 hex of a body (pure, tested).
func hash64(b []byte) string {
	h := fnv.New64a()
	_, _ = h.Write(b)
	return fmt.Sprintf("%016x", h.Sum64())
}

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	made := 0
	get := func(path string) []byte {
		if made >= maxRequests {
			return nil
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		made++
		resp, err := s.client.Get(cctx, strings.TrimSuffix(sc.Target.Raw, "/")+path)
		if err != nil || resp == nil || resp.StatusCode != 200 || len(resp.Body) == 0 {
			return nil
		}
		return resp.Body
	}
	_ = get("") // homepage warms the connection pool; icons carry the signal
	type icon struct {
		path, hash string
		size       int
	}
	groups := map[string][]string{}
	var icons []icon
	for _, p := range iconPaths {
		if made >= maxRequests {
			break
		}
		body := get(p)
		if body == nil {
			continue
		}
		h := hash64(body)
		groups[h] = append(groups[h], p)
		icons = append(icons, icon{p, h, len(body)})
	}
	if len(icons) == 0 {
		return scanner.StageResult{}, nil
	}
	sort.Slice(icons, func(i, j int) bool { return icons[i].path < icons[j].path })
	var endpoints []models.Endpoint
	for _, ic := range icons {
		endpoints = append(endpoints, models.Endpoint{
			URL: strings.TrimSuffix(sc.Target.Raw, "/") + ic.path, Category: models.EndpointAsset, Sources: []string{"faviconplus"},
		})
	}
	var descs []string
	for h, paths := range groups {
		descs = append(descs, fmt.Sprintf("%s (%s)", h[:12], strings.Join(paths, ",")))
	}
	sort.Strings(descs)
	return scanner.StageResult{Endpoints: endpoints, Findings: []models.Finding{{
		ID: "faviconplus-set", Title: fmt.Sprintf("%d icon file(s) in %d distinct hash group(s)", len(icons), len(groups)),
		Description: "Icon files are stable fingerprints: identical hashes pivot across hosts (Shodan http.favicon.hash technique) and unexpected icons reveal frameworks/admin panels. Reproduce: curl each icon path and hash the bytes. GET-only asset sweep.",
		Severity:    models.SeverityInfo, Confidence: models.ConfidenceHigh, Category: models.CategoryExposure,
		Target:   sc.Target.Raw,
		Evidence: models.Evidence{Observed: strings.Join(descs, "; "), Location: "icon path sweep"},
		Source:   models.SourceRecon, DetectionMethod: "favicon-path sweep, 8 paths (faviconplus, ≤9 requests)",
	}}}, nil
}
