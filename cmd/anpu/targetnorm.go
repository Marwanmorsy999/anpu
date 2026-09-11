package main

import "strings"

// targetnorm.go — one shared target normalization for history-backed
// comparisons (Phase 5). `anpu diff` used to refuse scans whose targets
// differed by a trailing slash or scheme case; `drift --from-history`
// only matched exact strings. Both now compare normalized forms so
// http/https inconsistencies, default ports, and trailing slashes
// don't trap users. Paths keep their case (some servers are
// case-sensitive); scheme and host do not.

// normalizeCompareTarget normalizes a target URL for comparison.
func normalizeCompareTarget(raw string) string {
	s := strings.TrimSpace(raw)
	if i := strings.Index(s, "://"); i >= 0 {
		scheme := strings.ToLower(s[:i])
		rest := s[i+3:]
		host := rest
		path := ""
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			host = rest[:j]
			path = rest[j:]
		}
		host = strings.ToLower(host)
		if (scheme == "http" && strings.HasSuffix(host, ":80")) ||
			(scheme == "https" && strings.HasSuffix(host, ":443")) {
			host = host[:strings.LastIndex(host, ":")]
		}
		return strings.TrimRight(scheme+"://"+host+path, "/")
	}
	return strings.TrimRight(strings.ToLower(s), "/")
}
