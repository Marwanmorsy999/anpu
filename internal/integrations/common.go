package integrations

// common.go — shared helpers for optional external-tool integrations.
//
// Every integration follows the same contract (see nuclei.go for the
// reference implementation):
//
//  1. The tool is invoked only when installed (Available check).
//  2. Absence degrades to a StageResult warning — never a fatal error.
//  3. Structured output (usually JSONL) is normalized into ANPU's
//     Finding/Endpoint/Technology/Subdomain model.

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// findExecutable resolves a tool using PATH first, then common Go/bin
// locations. This keeps Windows installations working even when the Go
// bin directory is not on PATH.
func findExecutable(binary string) (string, error) {
	if path, err := exec.LookPath(binary); err == nil {
		return path, nil
	}

	names := []string{binary}
	if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(binary), ".exe") {
		names = append(names, binary+".exe")
	}

	var candidates []string
	if gobin := strings.TrimSpace(os.Getenv("GOBIN")); gobin != "" {
		for _, name := range names {
			candidates = append(candidates, filepath.Join(gobin, name))
		}
	}
	if gopath := strings.TrimSpace(os.Getenv("GOPATH")); gopath != "" {
		for _, gp := range filepath.SplitList(gopath) {
			for _, name := range names {
				candidates = append(candidates, filepath.Join(gp, "bin", name))
			}
		}
	}
	// `go env` fallback (cached, one subprocess per process): covers the
	// common case where GOPATH/GOBIN are unset but `go install` drops
	// binaries into ~/go/bin. This is what makes post-install detection
	// work right after `anpu tools install`.
	for _, dir := range goToolDirs() {
		for _, name := range names {
			candidates = append(candidates, filepath.Join(dir, name))
		}
	}

	// pipx user bin (covers `pipx install` without PATH updates taking
	// effect in the current session).
	if home, herr := os.UserHomeDir(); herr == nil {
		for _, name := range names {
			candidates = append(candidates, filepath.Join(home, ".local", "bin", name))
		}
	}

	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() { // #nosec G703 -- flagged path derives from the operator's own CLI input; escaping the intended tree is operator-inflicted.
			return candidate, nil
		}
	}

	return "", fmt.Errorf("%s not found on PATH or Go bin directories", binary)
}

// LookupBinary reports whether a tool binary resolves (PATH + Go bins).
func LookupBinary(binary string) (string, bool) {
	path, err := findExecutable(binary)
	return path, err == nil
}

var (
	goToolDirsOnce  sync.Once
	goToolDirsCache []string
)

// goToolDirs returns `go env GOBIN` + `go env GOPATH`/bin (cached).
// Empty when no Go toolchain is present (falls back to ~/go/bin).
func goToolDirs() []string {
	goToolDirsOnce.Do(func() {
		var dirs []string
		if out, err := exec.Command("go", "env", "GOBIN", "GOPATH").Output(); err == nil {
			lines := strings.Split(strings.TrimSpace(string(out)), "\n")
			if len(lines) > 0 && strings.TrimSpace(lines[0]) != "" {
				dirs = append(dirs, strings.TrimSpace(lines[0]))
			}
			if len(lines) > 1 {
				for _, gp := range filepath.SplitList(strings.TrimSpace(lines[1])) {
					if gp != "" {
						dirs = append(dirs, filepath.Join(gp, "bin"))
					}
				}
			}
		}
		if len(dirs) == 0 {
			if home, herr := os.UserHomeDir(); herr == nil {
				dirs = append(dirs, filepath.Join(home, "go", "bin"))
			}
		}
		goToolDirsCache = dirs
	})
	return goToolDirsCache
}

// versionCheck reports whether path executes and answers a version flag.
// It tries --version first (Rust/clap tools like dalfox) then -version
// (ProjectDiscovery Go tools, nuclei).
func versionCheck(ctx context.Context, path string) bool {
	for _, flag := range []string{"--version", "-version"} {
		checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := exec.CommandContext(checkCtx, path, flag).Run() // #nosec G204 -- ANPU orchestrates operator-installed security tools by resolved path with bounded read-only flags.
		cancel()
		if err == nil {
			return true
		}
	}
	return false
}

// runCapture executes the tool and returns its stdout. Stderr is captured
// for diagnostics; over-long output is trimmed to 500 runes.
func runCapture(ctx context.Context, timeout time.Duration, path string, args ...string) (stdout []byte, stderr string, err error) {
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, path, args...) // #nosec G204 -- ANPU orchestrates operator-installed security tools by resolved path with bounded read-only flags.
	var out, serr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &serr
	err = cmd.Run()
	stderr = strings.TrimSpace(serr.String())
	if stderr != "" {
		stderr = strings.Join(strings.Fields(stderr), " ")
		if len(stderr) > 500 {
			stderr = stderr[:500] + "..."
		}
	}
	return out.Bytes(), stderr, err
}
