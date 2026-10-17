// Package version defines the ANPU release version used by the CLI and reports.
//
// All three variables are injected at release time by GoReleaser via
// -ldflags -X (see .goreleaser.yaml). Source builds fall back to the
// defaults below.
package version

import "strings"

// Version is the release version. GoReleaser overrides it at build time
// with the release tag, so a v0.4.0 tag produces a binary reporting
// 0.4.0. This default is what a source build (`go build ./cmd/anpu`)
// reports, and is kept in step with the latest release so a source build
// never claims to be an older version than what is published.
var Version = "0.4.0"

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
// commit and build date, e.g. "0.4.0 (commit 1a2b3c4, built
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
