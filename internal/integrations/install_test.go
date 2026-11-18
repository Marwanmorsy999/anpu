package integrations

import (
	"runtime"
	"strings"
	"testing"
)

// P0-4 (v0.5.7): every automated recipe must install a pinned upstream
// version — unpinned `@latest` installs were the supply-chain gap the
// audit flagged. apt/choco stay distro-managed (the distro signature
// verification is the integrity channel there); pipx git refs whose
// upstream tag could not be resolved at pin time are the documented
// exception (ghauri, Oralyzer).

func TestResolveInstallPinsGoModuleVersion(t *testing.T) {
	r := Recipe{Name: "gau", GoInstall: "github.com/lc/gau/v2/cmd/gau@latest", Version: "v2.2.4"}
	method, argv, err := resolveInstall(r, "linux")
	if err != nil {
		t.Fatalf("resolveInstall: %v", err)
	}
	if method != "go" {
		t.Fatalf("method = %q", method)
	}
	if got, want := argv[len(argv)-1], "github.com/lc/gau/v2/cmd/gau@v2.2.4"; got != want {
		t.Fatalf("pinned ref = %q, want %q", got, want)
	}
	if strings.Contains(argv[len(argv)-1], "@latest") {
		t.Fatalf("pinned install must not use @latest: %q", argv[len(argv)-1])
	}
}

func TestResolveInstallGoWithoutPinFallsBackToLatest(t *testing.T) {
	r := Recipe{Name: "x", GoInstall: "example.com/x/cmd/x@latest"}
	_, argv, err := resolveInstall(r, "linux")
	if err != nil {
		t.Fatalf("resolveInstall: %v", err)
	}
	if got := argv[len(argv)-1]; got != "example.com/x/cmd/x@latest" {
		t.Fatalf("unpinned ref = %q", got)
	}
}

// osv-scanner's recipe carried a @v1 suffix; the pin table must replace
// any existing ref suffix, not append after it.
func TestResolveInstallGoReplacesExistingRefSuffix(t *testing.T) {
	r := Recipe{Name: "osv-scanner", GoInstall: "github.com/google/osv-scanner/cmd/osv-scanner@v1", Version: "v1.9.2"}
	_, argv, err := resolveInstall(r, "linux")
	if err != nil {
		t.Fatalf("resolveInstall: %v", err)
	}
	if got, want := argv[len(argv)-1], "github.com/google/osv-scanner/cmd/osv-scanner@v1.9.2"; got != want {
		t.Fatalf("ref = %q, want %q", got, want)
	}
}

func TestResolveInstallPinsPipxVersion(t *testing.T) {
	r := Recipe{Name: "arjun", Pipx: "arjun", Version: "2.2.7"}
	_, argv, err := resolveInstall(r, "linux")
	if err != nil {
		t.Fatalf("resolveInstall: %v", err)
	}
	if got, want := argv[len(argv)-1], "arjun==2.2.7"; got != want {
		t.Fatalf("pinned pipx spec = %q, want %q", got, want)
	}
}

func TestResolveInstallPipxGitRefPinsTag(t *testing.T) {
	r := Recipe{Name: "ghauri", Pipx: "git+https://github.com/r0oth3x49/ghauri.git", Version: "v1.3.5"}
	_, argv, _ := resolveInstall(r, "linux")
	if got, want := argv[len(argv)-1], "git+https://github.com/r0oth3x49/ghauri.git@v1.3.5"; got != want {
		t.Fatalf("pinned git ref = %q, want %q", got, want)
	}
}

func TestResolveInstallPipxGitRefWithoutPinUnchanged(t *testing.T) {
	r := Recipe{Name: "oralyzer", Pipx: "git+https://github.com/r0075h3ll/Oralyzer.git"}
	_, argv, _ := resolveInstall(r, "linux")
	if got := argv[len(argv)-1]; got != r.Pipx {
		t.Fatalf("unpinned git ref changed: %q", got)
	}
}

func TestResolveInstallDockerUsesDigestRef(t *testing.T) {
	r := Recipe{Name: "mobsf", Docker: "opensecurity/mobile-security-framework-mobsf:latest",
		Digest: "sha256:f185153825a97862a75b38d2527fa41a4484a1f62f9e5b15c756d3a2aefa6cad"}
	method, argv, _ := resolveInstall(r, "linux")
	if method != "docker" {
		t.Fatalf("method = %q", method)
	}
	want := "opensecurity/mobile-security-framework-mobsf@sha256:f185153825a97862a75b38d2527fa41a4484a1f62f9e5b15c756d3a2aefa6cad"
	if got := argv[len(argv)-1]; got != want {
		t.Fatalf("digest pull ref = %q, want %q", got, want)
	}
}

// The pin table must cover every automated install path except the
// documented exceptions; a new recipe without a pin fails this test and
// must either carry a resolved version or land in the exception list with
// a reason.
func TestRegistryPinsComplete(t *testing.T) {
	// pipx git refs whose upstream tag could not be resolved at pin time
	// (2026-11-18): PyPI stub or no releases API result.
	unpinnedGit := map[string]string{
		"ghauri":   "upstream has no resolvable release tag (pipx installs from git)",
		"oralyzer": "upstream has no resolvable release tag (pipx installs from git)",
	}
	for _, r := range All() {
		switch {
		case r.GoInstall != "":
			if r.Version == "" {
				t.Errorf("go recipe %s is unpinned — resolve a version from proxy.golang.org and add it to versionPins", r.Name)
			}
		case r.Pipx != "":
			if strings.Contains(r.Pipx, "git+") {
				if r.Version == "" {
					if _, ok := unpinnedGit[r.Name]; !ok {
						t.Errorf("git recipe %s is unpinned without a documented reason", r.Name)
					}
				}
				continue
			}
			if r.Version == "" {
				t.Errorf("pipx recipe %s is unpinned — resolve a version from PyPI and add it to versionPins", r.Name)
			}
		case r.Docker != "":
			if r.Digest == "" && r.Version == "" {
				t.Errorf("docker recipe %s has neither a digest nor a version pin", r.Name)
			}
		}
	}
}

// Pin values must be well-formed refs, not prose or empty strings from a
// copy-paste slip.
func TestPinValuesWellFormed(t *testing.T) {
	for name, v := range versionPins {
		if v == "" {
			t.Errorf("pin for %s is empty", name)
			continue
		}
		if strings.ContainsAny(v, " ;'\"$\t\n") {
			t.Errorf("pin for %s contains illegal characters: %q", name, v)
		}
	}
	for name, d := range digestPins {
		if !strings.HasPrefix(d, "sha256:") || len(d) != len("sha256:")+64 {
			t.Errorf("digest pin for %s must be sha256:<64 hex>, got %q", name, d)
		}
	}
}

// The manifest must fingerprint the PINNED refs, so the scan-start hash
// covers the actual supply chain a scan ran with.
func TestManifestRefShowsPinnedVersion(t *testing.T) {
	r, ok := Get("gau")
	if !ok {
		t.Fatal("gau recipe missing")
	}
	_, ref := manifestMethodRef(r)
	if !strings.Contains(ref, "@v2.2.4") {
		t.Fatalf("manifest ref must show the pinned version, got %q", ref)
	}
}

// InstallHint renders the same pinned ref resolveInstall would execute —
// what the operator copy-pastes and what runs must never diverge.
func TestInstallHintMatchesResolveInstall(t *testing.T) {
	r, ok := Get("ffuf")
	if !ok {
		t.Fatal("ffuf recipe missing")
	}
	hint := InstallHint(r, runtime.GOOS)
	_, argv, _ := resolveInstall(r, runtime.GOOS)
	if !strings.Contains(hint, argv[len(argv)-1]) {
		t.Fatalf("hint %q does not contain the pinned ref %q", hint, argv[len(argv)-1])
	}
}
