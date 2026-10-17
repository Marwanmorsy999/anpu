// Package version defines the ANPU release version used by the CLI and reports.
//
// All three variables are injected at release time by GoReleaser via
// -ldflags -X (see .goreleaser.yaml). Source builds fall back to the
// defaults below.
package version

import "strings"

// Version is the release version. GoReleaser overrides it at build time.
var Version = "0.3.1"

// Commit is the source commit used to build the binary. GoReleaser
// overrides it at build time.
var Commit = "unknown"

// Date is the build timestamp. GoReleaser overrides it at build time.
var Date = "unknown"

// unknown is the sentinel GoReleaser-less builds carry; it is hidden from
// the rendered version string rather than shown as literal "unknown".
const unknown = "unknown"

// Full returns the canonical single-line version string. Both `anpu
// --version` and `anpu version` print exactly this (prefixed with
// "anpu version ") so the two forms can never drift apart.
//
// Source builds render as just the version; release builds append the
// commit and build date, e.g. "0.3.1 (commit 1a2b3c4, built
// 2026-10-18T09:00:00Z)".
func Full() string {
	var meta []string
	if c := strings.TrimSpace(Commit); c != "" && c != unknown {
		meta = append(meta, "commit "+c)
	}
	if d := strings.TrimSpace(Date); d != "" && d != unknown {
		meta = append(meta, "built "+d)
	}
	if len(meta) == 0 {
		return Version
	}
	return Version + " (" + strings.Join(meta, ", ") + ")"
}
