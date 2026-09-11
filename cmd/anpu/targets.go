package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/anpu-project/anpu/internal/config"
)

// targets.go — target selection helpers (Phase 6).
// Relocated verbatim from scan.go.

// collectTargets resolves the effective target list from (in priority
// order): --stdin, --list, the positional arg, then target.url in config.
// Lines starting with # and blank lines are ignored. Targets require an
// explicit http(s):// scheme, except config-file targets which default
// to https://.
func collectTargets(cmd *cobra.Command, targetArg string, stdinFlag bool, listFile string, cfgFile *config.File) ([]string, error) {
	switch {
	case stdinFlag && listFile != "":
		return nil, fmt.Errorf("use only one of --stdin or --list")
	case stdinFlag:
		if targetArg != "" {
			return nil, fmt.Errorf("pass targets via stdin or as an argument, not both")
		}
		lines, err := readTargetLines(cmd.InOrStdin())
		if err != nil {
			return nil, err
		}
		if len(lines) == 0 {
			return nil, fmt.Errorf("no targets received on stdin: pipe one URL per line")
		}
		return lines, nil
	case listFile != "":
		if targetArg != "" {
			return nil, fmt.Errorf("pass targets via --list or as an argument, not both")
		}
		f, err := os.Open(listFile) // #nosec G304 -- CLI reads operator-specified paths (reports, wordlists, checkpoints, code dir).
		if err != nil {
			return nil, fmt.Errorf("reading target list %q: %w", listFile, err)
		}
		defer func() { _ = f.Close() }()
		lines, err := readTargetLines(f)
		if err != nil {
			return nil, err
		}
		if len(lines) == 0 {
			return nil, fmt.Errorf("no targets found in %q", listFile)
		}
		return lines, nil
	default:
		if targetArg == "" {
			if cfgFile.Target.URL == "" {
				return nil, fmt.Errorf("no target specified: pass a URL, use --stdin/--list, or set target.url in anpu.yaml")
			}
			targetArg = cfgFile.Target.URL
			if !strings.HasPrefix(targetArg, "http://") && !strings.HasPrefix(targetArg, "https://") {
				targetArg = "https://" + targetArg // default to https for config targets
			}
		}
		return []string{targetArg}, nil
	}
}

// buildPipeline wires up every scan stage in pipeline order. This is the
// single place that knows about concrete scanner implementations — the
// orchestrator (internal/scanner) and every analyzer package only know
// about the Scanner interface, so adding a new stage means adding one
// entry here.
// readTargetLines reads one target per line, ignoring blank lines and
// lines starting with #. It caps input at 100k lines / 10MB to avoid
// runaway memory use from an accidental binary pipe.
func readTargetLines(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
		if len(out) >= 100000 {
			return nil, fmt.Errorf("target list exceeds 100000 entries")
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading targets: %w", err)
	}
	return out, nil
}
func sanitizeForFilename(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return b.String()
}
