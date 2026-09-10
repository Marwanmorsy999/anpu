// Package findings implements finding normalization and deduplication:
// merging results that different scanners (built-in analyzers, Nuclei,
// ZAP) reported for what is effectively the same underlying issue, while
// preserving every original source reference for traceability.
package findings

import (
	"crypto/sha1"
	"encoding/hex"
	"net/url"
	"sort"
	"strings"

	"github.com/anpu-project/anpu/pkg/models"
)

// canonicalizeDedupURL sorts query params so `?b=2&a=1` and `?a=1&b=2`
// are the same for dedup. Param and CWE are part of the key (models.DedupKey
// already does this, but we mirror it here so the dedup layer is explicit
// about query canonicalization even if a caller bypasses models.DedupKey).
func canonicalizeDedupURL(raw string) string {
	if raw == "" {
		return raw
	}
	p, err := url.Parse(raw)
	if err != nil || p.RawQuery == "" {
		return raw
	}
	q := p.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	first := true
	for _, k := range keys {
		vals := q[k]
		sort.Strings(vals)
		for _, v := range vals {
			if !first {
				sb.WriteString("&")
			}
			sb.WriteString(url.QueryEscape(k))
			sb.WriteString("=")
			sb.WriteString(url.QueryEscape(v))
			first = false
		}
	}
	p.RawQuery = sb.String()
	return p.String()
}

// Deduplicate groups findings by their DedupKey (category + normalized
// URL + normalized title + Param|CWE) and merges each group into a single Finding.
// Query strings are canonicalized so `?b=2&a=1` == `?a=1&b=2`. The merged
// finding keeps the highest severity/confidence observed across the group
// (never silently downgrading a real issue because one scanner was less sure),
// and records every contributing source in MergedFrom so no original evidence is lost.
func Deduplicate(in []models.Finding) []models.Finding {
	groups := map[string][]models.Finding{}
	order := []string{}
	for _, f := range in {
		// Ensure URL is canonicalized for the key (Param|CWE are in models.DedupKey).
		f.URL = canonicalizeDedupURL(f.URL)
		f.Target = canonicalizeDedupURL(f.Target)
		key := f.DedupKey()
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], f)
	}

	out := make([]models.Finding, 0, len(order))
	for _, key := range order {
		out = append(out, mergeGroup(groups[key]))
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity.Rank() != out[j].Severity.Rank() {
			return out[i].Severity.Rank() > out[j].Severity.Rank()
		}
		return out[i].Title < out[j].Title
	})

	return out
}

func mergeGroup(group []models.Finding) models.Finding {
	if len(group) == 1 {
		f := group[0]
		f.MergedFrom = []models.SourceRef{{
			Source:       f.Source,
			OriginalID:   f.ID,
			OriginalName: f.Title,
			Evidence:     f.Evidence,
		}}
		f.ID = stableID(f)
		return f
	}

	// Start from the highest-severity, highest-confidence member so the
	// merged finding's narrative text is the "best" one available.
	best := group[0]
	for _, f := range group[1:] {
		if f.Severity.Rank() > best.Severity.Rank() ||
			(f.Severity.Rank() == best.Severity.Rank() && f.Confidence.Rank() > best.Confidence.Rank()) {
			best = f
		}
	}

	merged := best
	merged.MergedFrom = nil

	maxSevRank, maxConfRank := -1, -1
	for _, f := range group {
		if f.Severity.Rank() > maxSevRank {
			maxSevRank = f.Severity.Rank()
			merged.Severity = f.Severity
		}
		if f.Confidence.Rank() > maxConfRank {
			maxConfRank = f.Confidence.Rank()
			merged.Confidence = f.Confidence
		}
		merged.MergedFrom = append(merged.MergedFrom, models.SourceRef{
			Source:       f.Source,
			OriginalID:   f.ID,
			OriginalName: f.Title,
			Evidence:     f.Evidence,
		})
	}
	merged.Source = models.SourceAggregation
	merged.ID = stableID(merged)
	return merged
}

// stableID produces a deterministic, content-derived ID for a finding so
// that re-running a scan against unchanged output yields the same IDs
// (useful for diffing scans over time / SARIF stability).
func stableID(f models.Finding) string {
	h := sha1.New()
	h.Write([]byte(f.DedupKey()))
	sum := h.Sum(nil)
	return "anpu-" + hex.EncodeToString(sum)[:12]
}
