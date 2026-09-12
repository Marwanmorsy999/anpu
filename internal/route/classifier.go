package route

import (
	"regexp"
	"sort"
	"strings"

	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// classifier.go — route sampling for adversarial active scanning.
//
// When the target exposes many endpoints with the same route shape
// (e.g., /api/users/1, /api/users/2, ... /api/users/1000), probing
// every one is wasteful and noisy. The classifier groups endpoints by
// normalized shape and samples 3–5 per group when the total count
// exceeds 10, preserving coverage while bounding request volume.
//
// This mirrors the active gate in scanner.go:50-115 which also checks
// status/CT/soft404 before probing.

var (
	uuidRe  = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	numRe   = regexp.MustCompile(`\d+`)
	hexIDRe = regexp.MustCompile(`[0-9a-f]{6,}`)
)

// Classify returns a normalized route shape for sampling.
// e.g., /api/users/123 -> /api/users/{num}, /api/items/ab12cd -> /api/items/{id}
func Classify(rawURL string) string {
	// Extract path only.
	path := rawURL
	if idx := strings.Index(rawURL, "?"); idx >= 0 {
		path = rawURL[:idx]
	}
	// Strip scheme+host if present.
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		// Find third slash after scheme.
		if i := strings.Index(path[8:], "/"); i >= 0 {
			path = path[8+i:]
		} else {
			path = "/"
		}
	}
	path = strings.ToLower(path)
	// Normalize UUIDs, numbers, hex IDs.
	path = uuidRe.ReplaceAllString(path, "{uuid}")
	path = numRe.ReplaceAllString(path, "{num}")
	// Replace remaining long hex tokens (e.g., object IDs).
	path = hexIDRe.ReplaceAllString(path, "{id}")
	// Collapse duplicate placeholders.
	path = strings.ReplaceAll(path, "{num}{num}", "{num}")
	return path
}

// Sample returns a sampled subset when count>10, otherwise the original.
// Per-group sampling: 3–5 per shape (4 default) when a group exceeds 5.
func Sample(endpoints []models.Endpoint) []models.Endpoint {
	if len(endpoints) <= 10 {
		return endpoints
	}
	groups := make(map[string][]models.Endpoint)
	for _, ep := range endpoints {
		key := Classify(ep.URL)
		groups[key] = append(groups[key], ep)
	}
	// Deterministic order for stability.
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out []models.Endpoint
	for _, k := range keys {
		grp := groups[k]
		if len(grp) > 5 {
			// Sample 3–5: use 4 as the sweet spot, but keep at least 3
			// and at most 5. Small groups stay intact.
			n := 4
			if len(grp) <= 7 {
				n = 3
			} else if len(grp) > 20 {
				n = 5
			}
			if n > len(grp) {
				n = len(grp)
			}
			// Deterministic: sort by URL and take first n.
			sort.Slice(grp, func(i, j int) bool { return grp[i].URL < grp[j].URL })
			out = append(out, grp[:n]...)
		} else {
			out = append(out, grp...)
		}
	}
	return out
}

// SampleSize returns the number of samples to keep for a group size.
// Exported for testing and for active/scanner.go gate diagnostics.
func SampleSize(groupSize int) int {
	if groupSize <= 5 {
		return groupSize
	}
	if groupSize <= 7 {
		return 3
	}
	if groupSize > 20 {
		return 5
	}
	return 4
}
