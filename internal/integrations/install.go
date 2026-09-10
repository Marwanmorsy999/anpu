// Package integrations — install.go: managed installation for the
// Wave 2 free-binary registry (`anpu tools install`). Method priority
// is cross-platform and rootless-first: `go install` → `pipx` →
// system package manager (apt with sudo -n on Linux, choco on
// Windows) → `docker pull` → manual error with the recipe.
//
// Installation only places the vendor's own free binary on disk; every
// safety rule still applies at RUN time (absent tools skip, noisy
// tools need ultra, state-touching tools need --adversarial
// --confirm-authorized, fuzzers need ANPU_WORDLIST).
package integrations

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// DefaultInstallTimeout bounds one tool installation (compiles like
// nuclei/trivy can take minutes on first build).
const DefaultInstallTimeout = 10 * time.Minute

// resolveInstall picks the install command for a recipe on an OS.
// Pure (unit-tested); execution lives in Install.
func resolveInstall(r Recipe, goos string) (method string, argv []string, err error) {
	if goos == "" {
		goos = runtime.GOOS
	}
	switch {
	case r.GoInstall != "":
		return "go", []string{"install", "-v", r.GoInstall}, nil
	case r.Pipx != "":
		return "pipx", []string{"install", r.Pipx}, nil
	case r.Apt != "" && goos == "linux":
		if os.Geteuid() == 0 {
			return "apt", []string{"install", "-y", r.Apt}, nil
		}
		// -n: fail fast instead of hanging on a password prompt.
		return "sudo", []string{"-n", "apt", "install", "-y", r.Apt}, nil
	case r.Choco != "" && goos == "windows":
		return "choco", []string{"install", "-y", r.Choco}, nil
	case r.Docker != "":
		return "docker", []string{"pull", r.Docker}, nil
	default:
		where := "this OS"
		if r.Manual != "" {
			return "", nil, fmt.Errorf("no automated install for %s on %s — manual: %s", r.Name, where, r.Manual)
		}
		return "", nil, fmt.Errorf("no automated install for %s on %s", r.Name, where)
	}
}

// Install installs one recipe and verifies the binary resolves after.
// It returns the method used ("go", "pipx", "apt", "choco", "docker").
func Install(ctx context.Context, r Recipe, timeout time.Duration) (string, error) {
	method, argv, err := resolveInstall(r, runtime.GOOS)
	if err != nil {
		return "", err
	}
	if timeout <= 0 {
		timeout = DefaultInstallTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, method, argv...)
	out, runErr := cmd.CombinedOutput()
	if runErr != nil {
		tail := strings.TrimSpace(string(out))
		if len(tail) > 800 {
			tail = tail[len(tail)-800:]
		}
		hint := ""
		if method == "sudo" {
			hint = " (no passwordless sudo? run the printed command yourself)"
		}
		return "", fmt.Errorf("installing %s via %s failed: %v%s — output tail: %s", r.Name, method, runErr, hint, tail)
	}
	if method == "docker" {
		inspectCtx, inspectCancel := context.WithTimeout(ctx, time.Minute)
		defer inspectCancel()
		if err := exec.CommandContext(inspectCtx, "docker", "image", "inspect", r.Docker).Run(); err != nil {
			return method, fmt.Errorf("%s pulled via docker but image %s not found locally: %v", r.Name, r.Docker, err)
		}
		return method, nil
	}
	if _, ok := LookupBinary(r.Binary); ok {
		return method, nil
	}
	return method, fmt.Errorf("%s installed via %s but %s is still not on PATH/Go-bin (open a new shell or check GOBIN)", r.Name, method, r.Binary)
}

// InstallableSpecs returns specs with an automated install path on
// this OS (used by `tools install --all`).
func InstallableSpecs(goos string) []*ToolSpec {
	var out []*ToolSpec
	for _, s := range ToolSpecs() {
		r, ok := Get(s.Name)
		if !ok {
			continue
		}
		if _, _, err := resolveInstall(r, goos); err == nil {
			out = append(out, s)
		}
	}
	return out
}
