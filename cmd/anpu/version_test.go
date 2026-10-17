package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Marwanmorsy999/anpu/pkg/version"
)

// runVersionForm executes the root command with args and returns the
// trimmed stdout/stderr the CLI produced.
func runVersionForm(t *testing.T, args ...string) string {
	t.Helper()
	root := newRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		t.Fatalf("executing %v: %v", args, err)
	}
	return strings.TrimSpace(buf.String())
}

// `anpu --version` and `anpu version` must print the same line, or scripts
// that grep one form break against the other.
func TestVersionFlagMatchesVersionCommand(t *testing.T) {
	origCommit, origDate := version.Commit, version.Date
	t.Cleanup(func() { version.Commit, version.Date = origCommit, origDate })

	// Release-build shape: version + commit + date all injected.
	version.Commit = "1a2b3c4"
	version.Date = "2026-10-18T09:00:00Z"

	flagOut := runVersionForm(t, "--version")
	cmdOut := runVersionForm(t, "version")

	if flagOut != cmdOut {
		t.Fatalf("--version %q != version command %q; the two forms must match", flagOut, cmdOut)
	}
	for _, want := range []string{version.Version, "1a2b3c4", "2026-10-18T09:00:00Z"} {
		if !strings.Contains(cmdOut, want) {
			t.Fatalf("output %q must contain %q", cmdOut, want)
		}
	}
	if !strings.HasPrefix(cmdOut, "anpu version ") {
		t.Fatalf("output must be prefixed with %q, got %q", "anpu version ", cmdOut)
	}
}

// A source build (no injected commit/date) must render the bare version and
// must never print the literal "unknown".
func TestVersionSourceBuildOmitsUnknownMetadata(t *testing.T) {
	origCommit, origDate := version.Commit, version.Date
	t.Cleanup(func() { version.Commit, version.Date = origCommit, origDate })

	version.Commit = "unknown"
	version.Date = "unknown"

	got := runVersionForm(t, "version")
	want := "anpu version " + version.Version
	if got != want {
		t.Fatalf("source build must render %q, got %q", want, got)
	}
	if strings.Contains(got, "unknown") {
		t.Fatalf("source build must not print the literal %q: %q", "unknown", got)
	}
}
