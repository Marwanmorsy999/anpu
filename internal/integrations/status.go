// Package integrations — status.go: honest per-tool status for
// `anpu tools` (Phase 4). The old doctor showed 8 binaries with a
// permanent ✓; this reports every registry tool with its real state,
// prerequisites, worst-case cost, and install hint — plus the operator
// environment (ANPU_WORDLIST/CODE_DIR/APK/RESOLVERS/...) those tools
// depend on.
package integrations

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Tool states reported by ToolStatus.
const (
	// ToolExternal means the binary resolves and answers a version flag.
	ToolExternal = "external"
	// ToolEmbedded means no binary, but native modules cover the ground.
	ToolEmbedded = "embedded"
	// ToolMissingInstallable means no binary and no embedded cover, but
	// an automated recipe exists.
	ToolMissingInstallable = "missing-installable"
	// ToolMissingManual means no binary, no cover, manual setup only.
	ToolMissingManual = "missing-manual"
)

// BinaryResponds reports whether binary resolves and answers --version
// or -version within the timeout. It mirrors the runtime check in
// common.go (which tries --version first for clap tools like dalfox,
// then -version for ProjectDiscovery Go tools).
func BinaryResponds(ctx context.Context, binary string) (string, bool) {
	path, ok := LookupBinary(binary)
	if !ok {
		return "", false
	}
	if !versionCheck(ctx, path) {
		return path, false
	}
	return path, true
}

// SpecPrereqs lists operator prerequisites for a spec in stable order:
// env-gated inputs first, then run gates.
func SpecPrereqs(spec *ToolSpec) []string {
	var out []string
	if spec == nil {
		return out
	}
	if spec.RequiresWordlist {
		out = append(out, "ANPU_WORDLIST (or bundled "+spec.DefaultWordlist+")")
	}
	if spec.RequiresCodeDir {
		out = append(out, "ANPU_CODE_DIR")
	}
	if spec.RequiresAPK {
		out = append(out, "ANPU_APK")
	}
	if spec.RequiresResolvers {
		out = append(out, "ANPU_RESOLVERS (or public default)")
	}
	if spec.Adversarial {
		out = append(out, "--adversarial --confirm-authorized")
	}
	if spec.ParamURL || spec.RequiresParams {
		out = append(out, "parameterized URLs")
	}
	return out
}

// SpecTimeout returns the worst-case wall time for one spec invocation.
func SpecTimeout(spec *ToolSpec) int {
	if spec == nil {
		return 0
	}
	if spec.TimeoutSec > 0 {
		return spec.TimeoutSec
	}
	return defaultTimeout
}

// hasAutomatedRecipe reports whether any one-liner install exists.
func hasAutomatedRecipe(r Recipe) bool {
	return r.GoInstall != "" || r.Pipx != "" || r.Apt != "" || r.Choco != "" || r.Docker != ""
}

// InstallHintShort is the first automated install step, or the manual
// pointer when only docs exist.
func InstallHintShort(r Recipe, goos string) string {
	if r.GoInstall != "" {
		return "go install -v " + r.GoInstall
	}
	if r.Pipx != "" {
		return "pipx install " + r.Pipx
	}
	if r.Apt != "" && (goos == "linux" || goos == "") {
		return "sudo apt install -y " + r.Apt
	}
	if r.Choco != "" && (goos == "windows" || goos == "") {
		return "choco install -y " + r.Choco
	}
	if r.Docker != "" {
		return "docker pull " + r.Docker
	}
	if r.Manual != "" {
		return "manual: " + r.Manual
	}
	return "no automated recipe"
}

// ToolStatus resolves one registry tool to (state, detail). State is
// one of the Tool* constants; detail names the binary path, the native
// fallback modules, or the install hint. Pure except for PATH/exec
// probing of actually-installed binaries.
func ToolStatus(ctx context.Context, name string) (state, detail string) {
	recipe, ok := Get(name)
	if !ok {
		return ToolMissingManual, "unknown tool (try: anpu tools install --list)"
	}
	spec, _ := SpecByName(name)
	binary := recipe.Binary
	if spec != nil && spec.Binary != "" {
		binary = spec.Binary
	}
	if path, ok := BinaryResponds(ctx, binary); ok {
		return ToolExternal, "found: " + path
	}
	if path, ok := LookupBinary(binary); ok {
		// Resolves but answers no version flag — likely present but
		// broken; say so instead of claiming embedded readiness.
		return ToolExternal, "found (no version response): " + path
	}
	fallbacks := EmbeddedFallbacks(name)
	if len(fallbacks) > 0 {
		d := "embedded (" + strings.Join(fallbacks, ", ") + ")"
		if prereqs := SpecPrereqs(spec); len(prereqs) > 0 {
			d += "; needs " + strings.Join(prereqs, ", ")
		}
		return ToolEmbedded, d
	}
	if hasAutomatedRecipe(recipe) {
		return ToolMissingInstallable, "install: " + InstallHintShort(recipe, runtime.GOOS)
	}
	return ToolMissingManual, InstallHintShort(recipe, runtime.GOOS)
}

// LevelWorstCase sums per-tool timeouts of staged specs by profile:
// profiles are cumulative (ultra runs advanced + ultra + safe tools),
// so ultra's figure includes the lower levels. Sequential worst case
// if every binary were installed and burned its full timeout. Parallel
// stages overlap in practice, so real runs cost less;
// ANPU_TOOL_BUDGET_SEC caps the cumulative total when set.
func LevelWorstCase() map[string]int {
	byLevel := map[string]int{}
	for _, s := range StagedSpecs() {
		byLevel[s.Level] += SpecTimeout(s)
	}
	out := map[string]int{
		"safe":     byLevel[LevelSafe],
		"advanced": byLevel[LevelSafe] + byLevel[LevelAdvanced],
		"ultra":    byLevel[LevelSafe] + byLevel[LevelAdvanced] + byLevel[LevelUltra],
	}
	return out
}

// EnvInfo is one operator-environment prerequisite and its state.
type EnvInfo struct {
	Name  string
	Value string
	OK    bool
	Used  string
}

func fileExists(path string) bool {
	info, err := os.Stat(strings.TrimSpace(path))
	return err == nil && !info.IsDir()
}

func dirExists(path string) bool {
	info, err := os.Stat(strings.TrimSpace(path))
	return err == nil && info.IsDir()
}

// EnvStatus reports the operator environment wrapper tools depend on.
// Pure except for env reads and existence stats.
func EnvStatus() []EnvInfo {
	wl := strings.TrimSpace(os.Getenv("ANPU_WORDLIST"))
	cd := strings.TrimSpace(os.Getenv("ANPU_CODE_DIR"))
	apk := strings.TrimSpace(os.Getenv("ANPU_APK"))
	rs := strings.TrimSpace(os.Getenv("ANPU_RESOLVERS"))
	mobsfURL := strings.TrimSpace(os.Getenv("ANPU_MOBSF_URL"))
	mobsfKey := strings.TrimSpace(os.Getenv("ANPU_MOBSF_KEY"))
	budget := strings.TrimSpace(os.Getenv("ANPU_TOOL_BUDGET_SEC"))
	return []EnvInfo{
		{"ANPU_WORDLIST", wl, wl != "" && fileExists(wl), "fuzzers (ffuf/gobuster/…); unset falls back to bundled wordlists"},
		{"ANPU_CODE_DIR", cd, cd != "" && dirExists(cd), "code tools (semgrep/trivy/osv/grype/gitleaks/…); unset skips them"},
		{"ANPU_APK", apk, apk != "" && fileExists(apk), "mobile scope (mobsf); unset skips it"},
		{"ANPU_RESOLVERS", rs, rs != "" && fileExists(rs), "DNS brute tools; unset uses public resolvers"},
		{"ANPU_MOBSF_URL", mobsfURL, mobsfURL != "", "MobSF server endpoint (operator-run infra)"},
		{"ANPU_MOBSF_KEY", maskKey(mobsfKey), mobsfKey != "", "MobSF API key (never printed)"},
		{"ANPU_TOOL_BUDGET_SEC", budget, budget != "" && budget != "0", "cumulative external-tool seconds cap; unset/0 = uncapped"},
	}
}

func maskKey(k string) string {
	if k == "" {
		return ""
	}
	return "***set***"
}

// FormatDuration renders worst-case seconds as "45s", "2m", or "1m30s".
func FormatDuration(totalSec int) string {
	if totalSec < 60 {
		return fmt.Sprintf("%ds", totalSec)
	}
	if totalSec%60 == 0 {
		return fmt.Sprintf("%dm", totalSec/60)
	}
	return fmt.Sprintf("%dm%ds", totalSec/60, totalSec%60)
}

// SortedToolNames returns registry names in stable order for CLI output.
func SortedToolNames() []string {
	names := Names()
	sort.Strings(names)
	return names
}

// statusProbeTimeout bounds each binary version probe in the doctor.
const statusProbeTimeout = 8 * time.Second

// ProbeTimeout exposes the per-tool probe budget for tests/docs.
func ProbeTimeout() time.Duration { return statusProbeTimeout }
