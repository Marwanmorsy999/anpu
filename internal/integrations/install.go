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
// Pure (unit-tested); execution lives in Install. Automated refs render
// through installRef (v0.5.7 P0-4): go modules and pipx packages are
// installed at the pinned upstream version (module content further
// verified against the Go checksum database), docker pulls are digest-
// addressed. apt/choco stay distro-managed — the distro's own signature
// verification is the integrity channel there.
func resolveInstall(r Recipe, goos string) (method string, argv []string, err error) {
	if goos == "" {
		goos = runtime.GOOS
	}
	switch {
	case r.GoInstall != "":
		return "go", []string{"install", "-v", installRef(r)}, nil
	case r.Pipx != "":
		return "pipx", []string{"install", installRef(r)}, nil
	case r.Apt != "" && goos == "linux":
		if os.Geteuid() == 0 {
			return "apt", []string{"install", "-y", r.Apt}, nil
		}
		// -n: fail fast instead of hanging on a password prompt.
		return "sudo", []string{"-n", "apt", "install", "-y", r.Apt}, nil
	case r.Choco != "" && goos == "windows":
		return "choco", []string{"install", "-y", r.Choco}, nil
	case r.Docker != "":
		return "docker", []string{"pull", installRef(r)}, nil
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
// After a local install succeeds, the binary's sha256 is recorded in the
// per-user digest state (~/.anpu/tool-digests.json) so every later run
// can verify the binary has not changed since install (fail closed on
// drift — see digests.go).
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
	cmd := exec.CommandContext(runCtx, method, argv...) // #nosec G204 -- ANPU orchestrates operator-installed security tools by resolved path with bounded read-only flags.
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
		// Inspect exactly what was pulled (the pinned ref), not the
		// recipe's raw tag.
		pulledRef := argv[len(argv)-1]
		inspectCtx, inspectCancel := context.WithTimeout(ctx, time.Minute)
		defer inspectCancel()
		if err := exec.CommandContext(inspectCtx, "docker", "image", "inspect", pulledRef).Run(); err != nil { // #nosec G204 -- ANPU orchestrates operator-installed security tools by resolved path with bounded read-only flags.
			return method, fmt.Errorf("%s pulled via docker but image %s not found locally: %v", r.Name, pulledRef, err)
		}
		return method, nil
	}
	if _, ok := LookupBinary(r.Binary); !ok {
		return method, fmt.Errorf("%s installed via %s but %s is still not on PATH/Go-bin (open a new shell or check GOBIN)", r.Name, method, r.Binary)
	}
	// Record the installed binary's digest for run-time drift checks.
	// A record failure is a warning, not an install failure: the pin
	// itself already came from the registry; the record is the local
	// tamper-evidence baseline.
	if rerr := RecordInstalledDigest(r.Binary, r.Version, method); rerr != nil {
		return method, fmt.Errorf("%s installed via %s but its digest could not be recorded (run `anpu tools verify` after install): %w", r.Name, method, rerr)
	}
	return method, nil
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
